"""End-to-end scan invariants on real fixtures (require the detector tools)."""

from __future__ import annotations

import shutil

import pytest

from runworthy.models import AFR_CONTROLS, TOTAL_CONTROLS, Confidence, Verdict
from runworthy.tools import TOOLS

requires_tools = pytest.mark.skipif(
    not all(shutil.which(t.exe) for t in TOOLS.values()), reason="detector tools not on PATH"
)

# The only AFR controls a Phase-0 adapter may mechanically assign (spec §3).
_ALLOWED_AFR = {"AFR-05", "AFR-06", "AFR-08", "AFR-09", "AFR-10"}

pytestmark = [requires_tools, pytest.mark.tools]


def test_verdict_always_provisional(scanned):
    r = scanned("langgraph_app")
    assert r.verdict is Verdict.PROVISIONAL
    assert r.posture_items == []
    assert r.operational_answers == []
    assert r.band is None
    assert r.total_controls == TOTAL_CONTROLS == 29
    assert r.assessed_controls == 0


def test_env_template_yields_no_high_confidence_secret(scanned):
    """VF-1 regression: an all-empty CRLF ``.env.example`` (the exact shape that
    NO-GO'd open_deep_research) must produce zero high-confidence secret findings,
    so it can never anchor a Confirmed Boldface gap. Whether gitleaks flags the
    template at all, nothing on it may be high-confidence."""
    r = scanned("env_template_repo")
    secrets = [f for f in r.findings if f.detector == "gitleaks"]
    assert all(f.confidence is not Confidence.HIGH for f in secrets)
    for f in secrets:
        if f.file.endswith(".env.example"):
            assert f.confidence is Confidence.LOW
    # And the scan still grades honestly (no invented failure).
    assert r.verdict is Verdict.PROVISIONAL


def test_every_finding_has_location_and_key(scanned):
    for name in ("langgraph_app", "secret_repo", "vuln_dep_repo"):
        for f in scanned(name).findings:
            assert f.file
            assert f.line >= 1
            assert f.dedup_key
            assert f.finding_id


def test_afr_controls_are_mechanical_only(scanned):
    for name in ("langgraph_app", "vuln_dep_repo", "secret_repo"):
        for f in scanned(name).findings:
            assert f.afr_controls, "every finding carries at least one mechanical mapping"
            assert set(f.afr_controls) <= _ALLOWED_AFR
            assert all(c in AFR_CONTROLS for c in f.afr_controls)


def test_skillspector_containment_is_bounded(scanned):
    """App-code mode keeps only a handful of dangerous-code/exfil/secrets
    findings — never the raw flood."""
    r = scanned("langgraph_app")
    ss_code = [f for f in r.findings if f.detector == "skillspector" and f.dedup_key.startswith("code::")]
    assert len(ss_code) <= 15


def test_provenance_present(scanned):
    r = scanned("langgraph_app")
    assert r.engine_version
    assert r.detector_versions.get("skillspector")
    assert r.generated_at
