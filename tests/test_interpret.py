"""Graph plumbing + anti-hallucination enforcement, with a fake model (no key).

The eval suite (test_evals.py) exercises the graph on real recorded cassettes;
this file pins the graph's contract-critical behaviour deterministically: evidence
that doesn't resolve is rejected, retried, then dropped — never asserted.
"""

from __future__ import annotations

from runworthy.interpret import interpret
from runworthy.models import (
    AgentMap,
    Confidence,
    Finding,
    PostureStatus,
    ReadinessReport,
    Severity,
    Verdict,
)


class FakeModel:
    """Duck-types StructuredModel.complete, returning canned output per node."""

    def __init__(self, by_node: dict[str, dict]):
        self.by_node = by_node
        self.calls: list[str] = []

    def complete(self, *, node: str, system: str, user: str, schema: dict) -> dict:
        self.calls.append(node)
        return self.by_node[node]


def _finding(fid, detector, controls, sev, conf, file, line, msg):
    return Finding(
        finding_id=fid, detector=detector, detector_version="x", afr_controls=controls,
        severity=sev, confidence=conf, file=file, line=line, raw_message=msg,
        dedup_key=f"{fid}-key",
    )


def _report():
    findings = [
        _finding("rw-secret1", "gitleaks", ["AFR-05", "AFR-06"], Severity.HIGH, Confidence.HIGH,
                 ".env", 1, "Generic API Key"),
        _finding("rw-dep1", "osv-scanner", ["AFR-10"], Severity.MEDIUM, Confidence.HIGH,
                 "requirements.txt", 2, "Vulnerable dependency requests"),
        _finding("rw-code1", "skillspector", ["AFR-08", "AFR-09"], Severity.MEDIUM, Confidence.MEDIUM,
                 "agent.py", 9, "subprocess call"),
    ]
    return ReadinessReport(
        findings=findings,
        target_ref="owner/repo",
        commit_sha="abc123",
        generated_at="2026-07-06T00:00:00Z",
        engine_version="0.1.0",
        detector_versions={"gitleaks": "8.30.1"},
        agent_map=AgentMap(frameworks=["LangGraph"], tools=["shell-exec"], entrypoints=["agent.py"]),
        notes=["phase0 note"],
    )


def test_graph_produces_graded_evidence_bound_report():
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "gap", "confidence": "high",
             "evidence": ["rw-secret1"], "rationale": "hardcoded secret in .env"},
            {"afr_control": "AFR-10", "status": "gap", "confidence": "high",
             "evidence": ["rw-dep1"], "rationale": "vulnerable dependency"},
            {"afr_control": "AFR-12", "status": "unknown", "confidence": "medium",
             "evidence": ["rw-code1"], "rationale": "shell-exec but no approval gate seen"},
            {"afr_control": "AFR-20", "status": "unknown", "confidence": "low",
             "evidence": [], "rationale": "kill-switch not visible"},
        ]},
        "translate": {"items": [
            {"index": 0, "plain_explanation": "A hardcoded API key sits in .env:1.", "fix": "Move it to a secret manager."},
            {"index": 1, "plain_explanation": "requirements.txt:2 uses a vulnerable requests.", "fix": "Upgrade it."},
            {"index": 2, "plain_explanation": "The agent runs shell commands (agent.py:9) with no approval.", "fix": "Add an approval step."},
            {"index": 3, "plain_explanation": "Couldn't tell if you have a kill-switch.", "fix": "Confirm you can stop the agent."},
        ]},
    })
    report = interpret(_report(), model=model)

    by_control = {p.afr_control: p for p in report.posture_items}
    assert set(by_control) == {"AFR-05", "AFR-10", "AFR-12", "AFR-20"}
    assert by_control["AFR-05"].status is PostureStatus.GAP
    assert by_control["AFR-05"].confidence is Confidence.HIGH
    assert by_control["AFR-05"].boldface is True
    assert by_control["AFR-05"].evidence == ["rw-secret1"]
    assert by_control["AFR-12"].status is PostureStatus.UNKNOWN
    assert by_control["AFR-12"].confidence is Confidence.MEDIUM  # likely gap — verify
    assert by_control["AFR-20"].confidence is Confidence.LOW  # couldn't determine
    assert "kill-switch" in by_control["AFR-20"].plain_explanation

    # AFR-05 is a confirmed Boldface gap -> NO_GO / Exposed.
    assert report.verdict is Verdict.NO_GO
    assert report.band == "Exposed"
    # self-contained: still embeds the findings it cites.
    assert len(report.findings) == 3
    assert model.calls == ["map", "translate"]  # synthesize is deterministic, no model call


def test_unciteable_evidence_is_dropped_not_asserted():
    """A gap citing a finding_id that doesn't exist must never reach the report."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "gap", "confidence": "high",
             "evidence": ["rw-DOES-NOT-EXIST"], "rationale": "hallucinated"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report(), model=model)

    assert report.posture_items == []
    assert report.verdict is Verdict.PROVISIONAL  # nothing confirmed -> not NO_GO
    assert any("dropped" in n for n in report.notes)
    # retried before dropping: 1 initial + MAX_MAP_RETRIES map calls
    assert model.calls.count("map") == 3


def test_gap_cited_to_unrelated_finding_is_dropped():
    """A Boldface gap must cite evidence *about that control*. Citing a real
    finding that belongs to a different control (here an AFR-10 dep finding used
    to 'confirm' AFR-01) must be dropped, not turned into a NO_GO."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-01", "status": "gap", "confidence": "high",
             "evidence": ["rw-dep1"], "rationale": "misattributed"},  # rw-dep1 is AFR-10, not AFR-01
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report(), model=model)
    assert report.posture_items == []
    assert report.verdict is Verdict.PROVISIONAL
    assert report.band is None


def test_hallucinated_file_line_in_prose_falls_back():
    """If the translated sentence names a file:line we have no evidence for, the
    prose is replaced with a safe control-derived line — the founder never reads a
    fabricated path as fact."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "gap", "confidence": "high",
             "evidence": ["rw-secret1"], "rationale": "hardcoded secret in .env"},
        ]},
        "translate": {"items": [
            {"index": 0, "plain_explanation": "A hardcoded AWS key sits in src/config/prod.py:12.",
             "fix": "Rotate it."},  # prod.py:12 is not in the evidence (the secret is in .env)
        ]},
    })
    report = interpret(_report(), model=model)
    item = report.posture_items[0]
    assert "src/config/prod.py" not in item.plain_explanation
    assert "src/config/prod.py" not in item.fix


def test_pass_gap_without_high_confidence_is_rejected():
    """status pass/gap requires high confidence + evidence; a 'medium gap' is not
    a confirmed failure and must be dropped, keeping the verdict honest."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-16", "status": "gap", "confidence": "medium",
             "evidence": ["rw-code1"], "rationale": "weak claim"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report(), model=model)
    assert report.posture_items == []
    assert report.verdict is Verdict.PROVISIONAL
