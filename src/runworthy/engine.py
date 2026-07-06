"""The core engine (spec §5): a pure function ``ScanTarget → ReadinessReport``.

No UI, no LLM. Network egress is limited to git clone (intake) and the pinned
detectors' own remotes (OSV.dev). Phase 0 always emits ``verdict = PROVISIONAL``.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .adapters import ADAPTERS
from .adapters.base import AdapterContext
from .fingerprint import fingerprint
from .intake import open_target
from .models import (
    TOTAL_CONTROLS,
    AgentMap,
    Finding,
    ReadinessReport,
    ScanTarget,
    Verdict,
)
from .normalize import finalize
from .tools import detector_versions


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _run_adapters(ctx: AdapterContext) -> list[Finding]:
    """Detectors are independent subprocesses — run them concurrently."""
    raw: list[Finding] = []
    with ThreadPoolExecutor(max_workers=len(ADAPTERS)) as pool:
        for result in pool.map(lambda a: a.run(ctx), ADAPTERS):
            raw.extend(result)
    return raw


def _base_report(
    target: ScanTarget,
    agent_map: AgentMap,
    findings: list[Finding],
    versions: dict[str, str],
    notes: list[str],
    generated_at: str | None,
) -> ReadinessReport:
    from . import __version__

    return ReadinessReport(
        band=None,  # no band without the interpretation layer
        verdict=Verdict.PROVISIONAL,  # Phase 0 is always provisional
        score=0,
        assessed_controls=0,
        total_controls=TOTAL_CONTROLS,
        posture_items=[],
        findings=findings,
        operational_answers=[],
        target_ref=target.ref,
        commit_sha=target.commit_sha,
        generated_at=generated_at or _now(),
        engine_version=__version__,
        detector_versions=versions,
        agent_map=agent_map,
        notes=notes,
    )


def scan(ref: str, *, generated_at: str | None = None) -> ReadinessReport:
    """Scan a target (local path or public repo URL) → provisional ReadinessReport.

    ``generated_at`` may be pinned for reproducible fixtures.
    """
    versions = detector_versions()
    with open_target(ref) as source:
        target = source.target
        agent_map = fingerprint(source.root, target)

        if agent_map.is_empty():
            # Honest early exit — Runworthy assesses agent operations; on a repo
            # with no agent surface it says so rather than fabricating findings.
            return _base_report(
                target,
                agent_map,
                findings=[],
                versions=versions,
                notes=["no agent surface detected - nothing to assess"],
                generated_at=generated_at,
            )

        ctx = AdapterContext(root=source.root, target=target, agent_map=agent_map, versions=versions)
        raw = _run_adapters(ctx)
        findings, dropped = finalize(raw)

    notes = [
        f"PROVISIONAL: 0 of {TOTAL_CONTROLS} controls assessed - Phase 0 emits deterministic "
        "findings only; the AFR grade requires the Phase 1 interpretation layer.",
    ]
    if dropped:
        notes.append(f"{dropped} finding(s) dropped for missing file:line location.")
    return _base_report(target, agent_map, findings, versions, notes, generated_at)
