"""gitleaks adapter — whole-repo hardcoded/long-lived secrets (spec §3 → AFR-05, AFR-06).

Runs with ``--redact`` so secret values never leave gitleaks; the adapter never
reads the flagged source line itself (that would re-introduce the secret).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..models import Confidence, Finding, Severity
from ..normalize import secret_dedup_key
from .base import AdapterContext, ToolUnavailable, rel_posix, resolve_exe, run_tool

DETECTOR = "gitleaks"
AFR_CONTROLS = ["AFR-05", "AFR-06"]

# Rules whose leak is severe enough to rate critical rather than high.
_CRITICAL_RULES = {"private-key", "aws-access-token", "gcp-service-account", "gcp-api-key"}


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
        severity = Severity.CRITICAL if rule in _CRITICAL_RULES else Severity.HIGH
        findings.append(
            Finding(
                finding_id="",  # assigned in normalize.finalize
                detector=DETECTOR,
                detector_version=version,
                afr_controls=list(AFR_CONTROLS),
                severity=severity,
                confidence=Confidence.HIGH,  # deterministic regex + entropy match
                file=file,
                line=line,
                snippet_redacted=str(item.get("Match", "REDACTED")),  # already redacted by gitleaks
                raw_message=f"{rule}: {item.get('Description', 'hardcoded secret')}",
                dedup_key=secret_dedup_key(fingerprint),
            )
        )
    return findings
