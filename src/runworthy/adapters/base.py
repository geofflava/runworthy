"""Shared adapter plumbing: subprocess runner + severity/confidence mappers."""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..models import AgentMap, Confidence, ScanTarget, Severity

logger = logging.getLogger("runworthy.adapters")


@dataclass
class AdapterContext:
    root: Path
    target: ScanTarget
    agent_map: AgentMap
    versions: dict[str, str] = field(default_factory=dict)


class ToolUnavailable(RuntimeError):
    """The external tool is not on PATH — the adapter is skipped, not fatal."""


def resolve_exe(exe: str) -> str:
    path = shutil.which(exe)
    if not path:
        raise ToolUnavailable(exe)
    return path


def run_tool(cmd: list[str], timeout: int = 300, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run an external detector. Return code is intentionally *not* checked:
    gitleaks/osv-scanner exit nonzero when they find something — that's success
    for us. Callers parse the emitted report/stdout.

    Output is decoded as UTF-8 (``errors="replace"``) — never the Windows locale
    codepage: detector JSON routinely carries bytes cp1252 can't decode, and a
    decode error would silently null out ``stdout``.

    A detector that times out or fails to launch is **non-fatal** — it degrades to
    an empty result (the adapter emits nothing) rather than aborting the scan.
    """
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        logger.warning("detector %r failed or timed out: %s", cmd[0] if cmd else "?", exc)
        return subprocess.CompletedProcess(cmd, returncode=124, stdout="", stderr=str(exc))


def rel_posix(path_str: str, root: Path) -> str:
    """Normalize a detector-reported path to a repo-relative POSIX string.

    Strips a leading ``./`` prefix only — never with ``lstrip("./")``, which
    would eat the leading dot of a dotfile (``.env.example`` -> ``env.example``)
    and break file:line spot-verifiability.
    """
    # Detectors may report either separator; normalize to POSIX before any
    # path logic so results are identical on Windows and Linux (CI / Cloud Run).
    p = Path(path_str.replace("\\", "/"))
    try:
        if p.is_absolute():
            p = p.resolve().relative_to(root.resolve())
    except ValueError:
        pass
    s = p.as_posix()
    return s[2:] if s.startswith("./") else s


def sev_from_str(s: str | None, default: Severity = Severity.MEDIUM) -> Severity:
    if not s:
        return default
    try:
        return Severity(s.strip().lower())
    except ValueError:
        return default


def sev_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.MEDIUM


def conf_from_float(c: float | None) -> Confidence:
    if c is None:
        return Confidence.MEDIUM
    if c >= 0.8:
        return Confidence.HIGH
    if c >= 0.6:
        return Confidence.MEDIUM
    return Confidence.LOW
