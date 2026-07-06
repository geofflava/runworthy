"""Golden-file regression test (criterion 7).

Captures a *stable projection* of the report — the fingerprint plus the
structural shape of each finding (dedup_key, detector, corroboration, mapping,
location). Volatile fields are excluded: ``generated_at``, tool versions, and
the CVSS-derived severity of dependency findings (which tracks the live OSV
database). Regenerate with ``RW_UPDATE_GOLDEN=1 pytest tests/test_golden.py``.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from runworthy.models import ReadinessReport
from runworthy.tools import TOOLS

GOLDEN = Path(__file__).parent / "golden"
requires_tools = pytest.mark.skipif(
    not all(shutil.which(t.exe) for t in TOOLS.values()), reason="detector tools not on PATH"
)


def project(report: ReadinessReport) -> dict:
    def pf(f) -> dict:
        d = {
            "dedup_key": f.dedup_key,
            "detector": f.detector,
            "also_reported_by": sorted(f.also_reported_by),
            "afr_controls": sorted(f.afr_controls),
            "file": f.file,
            "line": f.line,
            "confidence": str(f.confidence),
        }
        if not f.dedup_key.startswith("dep::"):
            d["severity"] = str(f.severity)  # deterministic for code/secret findings
        return d

    am = report.agent_map
    return {
        "agent_map": {
            k: sorted(getattr(am, k))
            for k in ("frameworks", "entrypoints", "tools", "prompts", "mcp_servers", "skills", "memory_stores")
        },
        "verdict": str(report.verdict),
        "findings": sorted((pf(f) for f in report.findings), key=lambda x: (x["file"], x["dedup_key"])),
    }


@requires_tools
@pytest.mark.tools
@pytest.mark.parametrize("name", ["langgraph_app", "vuln_dep_repo"])
def test_golden_projection(scanned, name):
    proj = project(scanned(name))
    gf = GOLDEN / f"{name}.json"
    if os.environ.get("RW_UPDATE_GOLDEN"):
        gf.parent.mkdir(parents=True, exist_ok=True)
        gf.write_text(json.dumps(proj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    assert gf.exists(), "golden missing — regenerate with RW_UPDATE_GOLDEN=1"
    expected = json.loads(gf.read_text(encoding="utf-8"))
    assert proj == expected
