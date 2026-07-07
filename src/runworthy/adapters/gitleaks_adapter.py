"""gitleaks adapter — whole-repo hardcoded/long-lived secrets (spec §3 → AFR-05, AFR-06).

Runs with ``--redact`` so secret values never leave gitleaks; the adapter never
reads the flagged source line itself (that would re-introduce the secret).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..classify import is_template_path
from ..models import Confidence, Finding, Severity
from ..normalize import secret_dedup_key
from .base import AdapterContext, ToolUnavailable, rel_posix, resolve_exe, run_tool

DETECTOR = "gitleaks"
AFR_CONTROLS = ["AFR-05", "AFR-06"]

# Rules whose leak is severe enough to rate critical rather than high.
_CRITICAL_RULES = {"private-key", "aws-access-token", "gcp-service-account", "gcp-api-key"}

# gitleaks entropy below this isn't a real high-entropy secret. gitleaks reports
# Entropy even under --redact (it's a number, not the value), so we can gate on it
# without ever handling the raw secret.
_ENTROPY_MIN = 3.0


def _is_low_signal(item: dict, file: str) -> bool:
    """True when a gitleaks hit is almost certainly a placeholder, not a committed
    credential: a match in a template/example/docs file (the VF-1 case —
    ``.env.example`` of empty ``VARNAME=`` assignments, where the generic rule
    over-matched across a CRLF), or a sub-threshold-entropy match. We deliberately
    do NOT inspect the redacted Match for a variable-name shape: with --redact a
    real ``OPENAI_API_KEY=sk-...`` reduces to the same ``OPENAI_API_KEY=REDACTED``,
    so that test would hide real env-var secrets."""
    if is_template_path(file):
        return True
    ent = item.get("Entropy")
    return isinstance(ent, (int, float)) and 0 < ent < _ENTROPY_MIN


def classify_secret(item: dict, file: str, rule: str) -> tuple[Confidence, Severity]:
    """Confidence/severity for a gitleaks hit. A low-signal match (template file or
    low entropy) drops to low/info so it can never render as a Confirmed Boldface
    gap; a real secret in real source stays high."""
    if _is_low_signal(item, file):
        return Confidence.LOW, Severity.INFO
    base_sev = Severity.CRITICAL if rule in _CRITICAL_RULES else Severity.HIGH
    return Confidence.HIGH, base_sev


def run(ctx: AdapterContext) -> list[Finding]:
    try:
        exe = resolve_exe("gitleaks")
    except ToolUnavailable:
        return []
    version = ctx.versions.get(DETECTOR, "unknown")

    with tempfile.TemporaryDirectory(prefix="rw-gitleaks-") as td:
        report = Path(td) / "gitleaks.json"
        run_tool(
            [
                exe,
                "dir",
                str(ctx.root),
                "--report-format",
                "json",
                "--report-path",
                str(report),
                "--redact",
                "--no-banner",
                "--exit-code",
                "0",
            ],
            timeout=300,
        )
        if not report.exists():
            return []
        try:
            raw = json.loads(report.read_text(encoding="utf-8") or "[]")
        except json.JSONDecodeError:
            return []
    if not isinstance(raw, list):
        return []

    findings: list[Finding] = []
    for item in raw or []:
        rule = item.get("RuleID", "secret")
        file = rel_posix(item.get("File", ""), ctx.root)
        line = int(item.get("StartLine", 0) or 0)
        if not file or line < 1:
            continue
        fingerprint = item.get("Fingerprint") or f"{file}:{rule}:{line}"
        confidence, severity = classify_secret(item, file, rule)
        findings.append(
            Finding(
                finding_id="",  # assigned in normalize.finalize
                detector=DETECTOR,
                detector_version=version,
                afr_controls=list(AFR_CONTROLS),
                severity=severity,
                confidence=confidence,  # capped low for placeholders/templates
                file=file,
                line=line,
                snippet_redacted=str(item.get("Match", "REDACTED")),  # already redacted by gitleaks
                raw_message=f"{rule}: {item.get('Description', 'hardcoded secret')}",
                dedup_key=secret_dedup_key(fingerprint),
            )
        )
    return findings
