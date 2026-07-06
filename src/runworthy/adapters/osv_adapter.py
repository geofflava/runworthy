"""OSV-Scanner adapter — vulnerable dependencies in manifests/lockfiles
(spec §3 → AFR-10).

OSV reports at *package* granularity with no line number. To keep the invariant
that every finding carries a real ``file:line``, the adapter resolves each
package's declaration line in its manifest. Findings are aggregated per package
(not per CVE) to avoid flooding and to align with SkillSpector-SC4 for dedup.
"""

from __future__ import annotations

import json

from ..models import Confidence, Finding
from ..normalize import dep_dedup_key, resolve_manifest_line
from .base import AdapterContext, ToolUnavailable, rel_posix, resolve_exe, run_tool, sev_from_cvss

DETECTOR = "osv-scanner"
AFR_CONTROLS = ["AFR-10"]


def _max_cvss(groups: list[dict]) -> float | None:
    scores: list[float] = []
    for g in groups:
        raw = g.get("max_severity")
        if raw:
            try:
                scores.append(float(raw))
            except (TypeError, ValueError):
                pass
    return max(scores) if scores else None


def _advisory_ids(package_vulns: list[dict]) -> list[str]:
    """Prefer CVE ids for the human message; fall back to primary ids."""
    cves: set[str] = set()
    primary: set[str] = set()
    for v in package_vulns:
        primary.add(v.get("id", ""))
        for alias in v.get("aliases", []) or []:
            if str(alias).upper().startswith("CVE-"):
                cves.add(alias)
    ids = sorted(cves) if cves else sorted(i for i in primary if i)
    return ids


def run(ctx: AdapterContext) -> list[Finding]:
    try:
        exe = resolve_exe("osv-scanner")
    except ToolUnavailable:
        return []
    version = ctx.versions.get(DETECTOR, "unknown")

    # --no-resolve: scan declared/locked packages only, no transitive resolution.
    # This keeps network egress to OSV.dev alone (transitive resolution would
    # reach package registries, outside the allowlist) and keeps scans fast;
    # a real lockfile still yields full pinned-transitive coverage.
    proc = run_tool(
        [exe, "scan", "source", "--recursive", "--no-resolve", "--format", "json", str(ctx.root)],
        timeout=300,
    )
    out = (proc.stdout or "").strip()
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    for result in data.get("results", []) or []:
        manifest = rel_posix(result.get("source", {}).get("path", ""), ctx.root)
        if not manifest:
            continue
        ecosystem_default = None
        for pkg in result.get("packages", []) or []:
            info = pkg.get("package", {})
            name = info.get("name", "")
            vulns = pkg.get("vulnerabilities", []) or []
            if not name or not vulns:
                continue
            ecosystem = info.get("ecosystem") or ecosystem_default or "PyPI"
            groups = pkg.get("groups", []) or []
            advisory_count = len(groups) if groups else len(vulns)
            line = resolve_manifest_line(ctx.root, manifest, name) or 1
            ids = _advisory_ids(vulns)
            id_str = (", ".join(ids[:5]) + ("…" if len(ids) > 5 else "")) if ids else "see OSV.dev"
            findings.append(
                Finding(
                    finding_id="",
                    detector=DETECTOR,
                    detector_version=version,
                    afr_controls=list(AFR_CONTROLS),
                    severity=sev_from_cvss(_max_cvss(groups)),
                    confidence=Confidence.HIGH,  # deterministic OSV database match
                    file=manifest,
                    line=line,
                    snippet_redacted=f"{name}=={info.get('version', '?')}",
                    raw_message=(
                        f"Vulnerable dependency {name} {info.get('version', '?')} "
                        f"({ecosystem}): {advisory_count} advisory(ies) [{id_str}]"
                    ),
                    dedup_key=dep_dedup_key(ecosystem, name, manifest),
                )
            )
    return findings
