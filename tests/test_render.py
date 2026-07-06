"""Markdown renderer: everything in build item 3 is present and reads plainly."""

from __future__ import annotations

from runworthy.models import (
    AgentMap,
    Confidence,
    Finding,
    PostureItem,
    PostureStatus,
    ReadinessReport,
    Severity,
    Verdict,
)
from runworthy.render import render_markdown


def _finding(fid, detector, sev, file, line, msg):
    return Finding(
        finding_id=fid, detector=detector, detector_version="x", afr_controls=[],
        severity=sev, confidence=Confidence.HIGH, file=file, line=line, raw_message=msg,
        dedup_key=f"{fid}-k",
    )


def _report(target_ref="langchain-ai/open_deep_research", sha="408da44"):
    findings = [
        _finding("rw-secret1", "gitleaks", Severity.HIGH, ".env.example", 1, "Generic API Key"),
        _finding("rw-code1", "skillspector", Severity.MEDIUM, "src/utils.py", 328, "External Transmission"),
    ]
    posture = [
        PostureItem(afr_control="AFR-05", status=PostureStatus.GAP, confidence=Confidence.HIGH,
                    boldface=True, evidence=["rw-secret1"],
                    plain_explanation="A hardcoded key sits in .env.example:1.", fix="Use a secret manager."),
        PostureItem(afr_control="AFR-12", status=PostureStatus.UNKNOWN, confidence=Confidence.MEDIUM,
                    boldface=True, evidence=["rw-code1"],
                    plain_explanation="The agent can send data out (src/utils.py:328) with no approval step.",
                    fix="Add a human approval gate for outbound actions."),
        PostureItem(afr_control="AFR-20", status=PostureStatus.UNKNOWN, confidence=Confidence.LOW,
                    boldface=True, evidence=[],
                    plain_explanation="Couldn't tell whether a kill-switch exists.", fix="Confirm you can stop it."),
    ]
    return ReadinessReport(
        verdict=Verdict.NO_GO, band="Exposed", score=0, assessed_controls=1,
        posture_items=posture, findings=findings, target_ref=target_ref, commit_sha=sha,
        generated_at="2026-07-06T01:28:12Z", engine_version="0.1.0",
        detector_versions={"gitleaks": "8.30.1", "osv-scanner": "2.4.0"},
        agent_map=AgentMap(frameworks=["LangGraph", "LangChain"]),
        notes=["a note"],
    )


def test_renders_all_required_sections():
    md = render_markdown(_report())
    assert "# Runworthy report — langchain-ai/open_deep_research" in md
    assert "## Verdict: NO-GO" in md and "Exposed" in md
    # provenance line
    assert "commit `408da44`" in md
    assert "gitleaks 8.30.1" in md and "osv-scanner 2.4.0" in md
    # all ten Boldface gates always shown
    for gate in ("AFR-01", "AFR-04", "AFR-05", "AFR-09", "AFR-11", "AFR-12", "AFR-16", "AFR-17", "AFR-20", "AFR-25"):
        assert f"| {gate} |" in md
    # tiered sections
    assert "## Confirmed gaps" in md
    assert "## Likely gaps — verify" in md
    assert "## Couldn't determine" in md


def test_github_deep_link_when_repo():
    md = render_markdown(_report())
    assert "https://github.com/langchain-ai/open_deep_research/blob/408da44/.env.example#L1" in md


def test_plain_file_line_when_local_path():
    md = render_markdown(_report(target_ref=r"C:\Users\Geoff\scratch\odr", sha=None))
    assert "github.com" not in md.split("AFR " + "v0.2.0")[0]  # no blob links in body
    assert "`.env.example:1`" in md


def test_footer_is_findings_and_gaps_not_certification():
    md = render_markdown(_report())
    assert "CC BY 4.0" in md
    assert "AFR v0.2.0" in md
    assert "not a certification" in md
    assert "certified secure" not in md


def test_couldnt_determine_lists_unassessed_boldface_with_questions():
    md = render_markdown(_report())
    # AFR-20 is low-confidence unknown -> appears with its plain question
    assert "AFR-20" in md.split("## Couldn't determine")[1]
    # AFR-01 has no assessment at all -> also owed a question
    assert "AFR-01" in md.split("## Couldn't determine")[1]
    # AFR-12 is a likely gap (shown as a card) -> NOT repeated here
    assert "AFR-12" not in md.split("## Couldn't determine")[1].split("---")[0]
