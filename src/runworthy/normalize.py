"""Normalization: dedup keys, cross-detector merge, redaction, location guard.

Realizes the contract's invariants (spec §4):
 1. every emitted Finding has file + line + dedup_key (else it is dropped);
 2. no secret value survives into the emitted JSON (redaction pass);
 4. overlapping detectors (SkillSpector-SC4 + OSV on the same dependency) merge
    into one finding that lists both detectors.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .models import Finding, Severity
from .redact import mask_secrets

logger = logging.getLogger("runworthy.normalize")

_SEVERITY_ORDER: dict[str, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Which detector "wins" the primary slot when a finding is corroborated.
_DETECTOR_AUTHORITY: dict[str, int] = {
    "osv-scanner": 3,  # canonical CVE source for dependency findings
    "gitleaks": 3,  # canonical secret source
    "skillspector": 1,
}

_ECOSYSTEM_BY_MANIFEST: dict[str, str] = {
    "requirements.txt": "PyPI",
    "pyproject.toml": "PyPI",
    "setup.py": "PyPI",
    "setup.cfg": "PyPI",
    "pipfile": "PyPI",
    "pipfile.lock": "PyPI",
    "poetry.lock": "PyPI",
    "environment.yml": "PyPI",
    "package.json": "npm",
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "go.mod": "Go",
    "go.sum": "Go",
    "cargo.toml": "crates.io",
    "cargo.lock": "crates.io",
    "gemfile": "RubyGems",
    "gemfile.lock": "RubyGems",
    "pom.xml": "Maven",
}


def norm_pkg(name: str) -> str:
    """Canonical package name for dedup (PyPI is case-insensitive, ``_``≡``-``)."""
    return name.strip().lower().replace("_", "-")


def ecosystem_for(file: str) -> str:
    return _ECOSYSTEM_BY_MANIFEST.get(Path(file).name.lower(), "PyPI")


def dep_dedup_key(ecosystem: str, package: str, file: str) -> str:
    """Dependency findings are keyed per {package, ecosystem, manifest} so an
    OSV finding and a SkillSpector-SC4 finding for the same vulnerable dep merge
    (spec §3 dedup rule, realized at package granularity to avoid CVE-flooding)."""
    return f"dep::{ecosystem.lower()}::{norm_pkg(package)}::{file}"


def code_dedup_key(rule_class: str, file: str, line: int) -> str:
    return f"code::{rule_class}::{file}::{line}"


def secret_dedup_key(fingerprint: str) -> str:
    return f"secret::{fingerprint}"


def _matches_pkg(line: str, target: str) -> bool:
    """True if ``target`` appears in ``line`` as a delimited token (name==,
    "name":, name =, - name) — not as a substring of a longer identifier."""
    esc = re.escape(target)
    return re.search(rf"(?<![\w.-]){esc}(?![\w.-])", line) is not None


def resolve_manifest_line(root: Path, file: str, package: str) -> int | None:
    """Find the 1-based line where ``package`` is declared in a manifest, so an
    OSV finding (which is package-level, no line) still carries a real
    file:line. Exact declaration keys are tried before the delimited-token
    fallback: ``@`` and ``/`` count as token delimiters, so ``hono`` would
    otherwise "match" inside ``"node_modules/@hono/node-server"`` hundreds of
    lines before the real ``"node_modules/hono"`` entry (runworthy#2), and the
    rendered evidence link would open on the wrong package. Returns None if not
    textually locatable."""
    target = norm_pkg(package)
    try:
        text = (root / file).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return None
    lines = [raw.lower().replace("_", "-") for raw in text.splitlines()]
    esc = re.escape(target)
    exact = (
        re.compile(rf'"[^"]*node-modules/{esc}"\s*:'),  # npm lockfile entry key
        re.compile(rf'"{esc}"\s*:'),  # JSON dependency key (package.json etc.)
    )
    for pat in exact:
        for i, line in enumerate(lines, start=1):
            if pat.search(line):
                return i
    for i, line in enumerate(lines, start=1):
        if _matches_pkg(line, target):
            return i
    return None


def _severity_max(a: Severity, b: Severity) -> Severity:
    return a if _SEVERITY_ORDER[a] >= _SEVERITY_ORDER[b] else b


def finalize(findings: list[Finding]) -> tuple[list[Finding], int]:
    """Drop unlocated findings, redact, assign ids, merge duplicates.

    Returns (findings, dropped_count). Output order is deterministic.
    """
    kept: list[Finding] = []
    dropped = 0
    for f in findings:
        if not f.file or not f.line or f.line < 1:
            logger.warning("dropping finding without location: %s %s", f.detector, f.raw_message[:60])
            dropped += 1
            continue
        f.snippet_redacted = mask_secrets(f.snippet_redacted)
        f.raw_message = mask_secrets(f.raw_message) or f.raw_message
        f.finding_id = Finding.make_id(f.dedup_key)
        kept.append(f)

    merged: dict[str, Finding] = {}
    for f in kept:
        existing = merged.get(f.dedup_key)
        if existing is None:
            merged[f.dedup_key] = f
            continue
        primary, other = _order_primary(existing, f)
        primary.severity = _severity_max(primary.severity, other.severity)
        primary.afr_controls = sorted(set(primary.afr_controls) | set(other.afr_controls))
        corroborators = set(primary.also_reported_by) | {other.detector} | set(other.also_reported_by)
        corroborators.discard(primary.detector)
        primary.also_reported_by = sorted(corroborators)
        merged[f.dedup_key] = primary

    out = sorted(merged.values(), key=lambda x: (x.file, x.line, x.dedup_key))
    return out, dropped


def _order_primary(a: Finding, b: Finding) -> tuple[Finding, Finding]:
    """Return (primary, other) by detector authority."""
    if _DETECTOR_AUTHORITY.get(b.detector, 0) > _DETECTOR_AUTHORITY.get(a.detector, 0):
        return b, a
    return a, b
