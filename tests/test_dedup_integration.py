"""Dedup integration (criterion 6): a real scan where OSV and SkillSpector-SC4
both see the same vulnerable dependency yields one finding listing both."""

from __future__ import annotations

import shutil

import pytest

from runworthy.tools import TOOLS

requires_tools = pytest.mark.skipif(
    not all(shutil.which(t.exe) for t in TOOLS.values()), reason="detector tools not on PATH"
)


@requires_tools
@pytest.mark.tools
def test_vuln_dep_repo_merges_osv_and_skillspector(scanned):
    report = scanned("vuln_dep_repo")
    dep_findings = [f for f in report.findings if f.dedup_key.startswith("dep::")]
    assert dep_findings, "expected at least one dependency finding"

    # every dep dedup_key appears exactly once (no double-reporting)
    keys = [f.dedup_key for f in dep_findings]
    assert len(keys) == len(set(keys))

    # the 'requests' finding is corroborated by both detectors
    requests_findings = [f for f in dep_findings if "requests" in f.dedup_key]
    assert len(requests_findings) == 1
    merged = requests_findings[0]
    detectors = {merged.detector, *merged.also_reported_by}
    assert "osv-scanner" in detectors
    assert "skillspector" in detectors
    assert merged.afr_controls == ["AFR-10"]
