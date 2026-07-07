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
    # Control set re-derived under the VF-3 guards: AFR-05 cites a real-source .env
    # secret (direct-class) so its gap stands; AFR-10 cites an OSV dep (direct) and
    # the non-rewrite floor leaves the model's gap/high untouched; AFR-12 (unknown)
    # and AFR-20 (couldn't-determine) are unaffected. No item added or dropped.
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
    """A gap citing a finding_id that doesn't exist is dropped (never asserted).

    The garbage model output leaves no valid model item — but the shared fixture's
    real OSV MEDIUM dependency (rw-dep1) is floored to a confirmed AFR-10 gap
    regardless (VF-3 §5), so the report carries exactly that one mechanically-derived
    item. AFR-10 is not Boldface, so the verdict stays PROVISIONAL."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "gap", "confidence": "high",
             "evidence": ["rw-DOES-NOT-EXIST"], "rationale": "hallucinated"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report(), model=model)

    assert [p.afr_control for p in report.posture_items] == ["AFR-10"]
    only = report.posture_items[0]
    assert only.status is PostureStatus.GAP and only.confidence is Confidence.HIGH
    assert only.evidence == ["rw-dep1"]  # mechanically floored to the dep finding
    assert report.verdict is Verdict.PROVISIONAL  # AFR-10 gap is not Boldface
    assert any("dropped" in n for n in report.notes)
    # retried before dropping: 1 initial + MAX_MAP_RETRIES map calls
    assert model.calls.count("map") == 3


def test_gap_cited_to_unrelated_finding_is_dropped():
    """A gap must cite evidence *about that control*. Citing a real finding that
    belongs to a different control (here an AFR-10 dep finding used to 'confirm'
    AFR-01) is dropped, not turned into a NO_GO. The dep finding still floors its
    own control (AFR-10) mechanically — but never the misattributed AFR-01."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-01", "status": "gap", "confidence": "high",
             "evidence": ["rw-dep1"], "rationale": "misattributed"},  # rw-dep1 is AFR-10, not AFR-01
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report(), model=model)
    controls = {p.afr_control for p in report.posture_items}
    assert controls == {"AFR-10"}  # only the mechanical floor, not the misattributed AFR-01
    assert report.posture_items[0].status is PostureStatus.GAP
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


def test_boldface_gap_on_template_finding_becomes_couldnt_determine():
    """VF-1/VF-3 regression: a Boldface gap resting only on a placeholder in a
    template file (``.env.example``) must not force NO-GO. VF-3 template hygiene
    strips the placeholder citation *before* the gap guard, so the item is left with
    no evidence and renders as 'couldn't determine' (unknown/low) — even more
    conservative than VF-1's 'likely gap — verify'. A real (non-template) dep gap is
    untouched, so genuine findings still land."""
    findings = [
        _finding("rw-tmplsecret", "gitleaks", ["AFR-05", "AFR-06"], Severity.INFO, Confidence.LOW,
                 ".env.example", 1, "generic-api-key placeholder"),
        _finding("rw-dep1", "osv-scanner", ["AFR-10"], Severity.MEDIUM, Confidence.HIGH,
                 "requirements.txt", 2, "Vulnerable dependency langchain"),
    ]
    report_in = ReadinessReport(
        findings=findings, target_ref="owner/repo", commit_sha="abc123",
        generated_at="2026-07-06T00:00:00Z", engine_version="0.1.0",
        detector_versions={"gitleaks": "8.30.1"},
        agent_map=AgentMap(frameworks=["LangGraph"], tools=[], entrypoints=["agent.py"]),
    )
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "gap", "confidence": "high",
             "evidence": ["rw-tmplsecret"], "rationale": "key in .env.example"},
            {"afr_control": "AFR-10", "status": "gap", "confidence": "high",
             "evidence": ["rw-dep1"], "rationale": "vulnerable dependency"},
        ]},
        "translate": {"items": [
            {"index": 0, "plain_explanation": "Worth checking your credential setup.", "fix": "Verify per-agent keys."},
            {"index": 1, "plain_explanation": "A pinned dependency has an open advisory.", "fix": "Upgrade it."},
        ]},
    })
    report = interpret(report_in, model=model)
    by_control = {p.afr_control: p for p in report.posture_items}
    # AFR-05's only evidence was a template placeholder -> stripped -> couldn't determine.
    assert by_control["AFR-05"].status is PostureStatus.UNKNOWN
    assert by_control["AFR-05"].confidence is Confidence.LOW
    assert by_control["AFR-05"].evidence == []
    # AFR-10 (non-Boldface, real dep finding) stays a confirmed gap.
    assert by_control["AFR-10"].status is PostureStatus.GAP
    # No confirmed Boldface gap -> PROVISIONAL, never NO-GO.
    assert report.verdict is Verdict.PROVISIONAL
    assert report.band is None
    assert any("template" in n for n in report.notes)


def test_boldface_gap_on_real_source_still_no_go():
    """The guard must not over-suppress: a high-confidence secret in *real* source
    (``.env``, not a template) is a genuine Confirmed Boldface gap and must still
    force NO-GO / Exposed."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "gap", "confidence": "high",
             "evidence": ["rw-secret1"], "rationale": "hardcoded secret in .env"},
        ]},
        "translate": {"items": [
            {"index": 0, "plain_explanation": "A key sits in .env:1.", "fix": "Rotate and scope it."},
        ]},
    })
    report = interpret(_report(), model=model)
    by_control = {p.afr_control: p for p in report.posture_items}
    assert by_control["AFR-05"].status is PostureStatus.GAP
    assert report.verdict is Verdict.NO_GO
    assert report.band == "Exposed"


def test_pass_gap_without_high_confidence_is_rejected():
    """status pass/gap requires high confidence + evidence; a 'medium gap' is not a
    confirmed failure and is dropped, keeping the verdict honest. The shared
    fixture's real OSV dep still floors AFR-10 mechanically, so that one confirmed
    gap remains — the dropped weak claim does not."""
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-16", "status": "gap", "confidence": "medium",
             "evidence": ["rw-code1"], "rationale": "weak claim"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report(), model=model)
    assert [p.afr_control for p in report.posture_items] == ["AFR-10"]
    assert report.posture_items[0].status is PostureStatus.GAP
    assert "AFR-16" not in {p.afr_control for p in report.posture_items}
    assert report.verdict is Verdict.PROVISIONAL


# --- VF-3 evidence-class discipline ------------------------------------------


def _report_with(findings, *, agent_map=None):
    return ReadinessReport(
        findings=findings, target_ref="owner/repo", commit_sha="abc123",
        generated_at="2026-07-06T00:00:00Z", engine_version="0.1.0",
        detector_versions={"skillspector": "2.3.9"},
        agent_map=agent_map or AgentMap(frameworks=["crewAI"], tools=["shell-exec"], entrypoints=["main.py"]),
    )


def test_confidence_high_pattern_gap_never_no_go():
    """The crewai TT3 shape: a SkillSpector taint finding (env-read → outbound call)
    arrives severity critical / confidence high on *real source*, and the model
    confirms an AFR-09 (Boldface) gap citing it. It is pattern-class, not direct, so
    the generalized gap guard downgrades it to 'likely — verify' and a working agent
    repo stays PROVISIONAL, never NO_GO."""
    findings = [
        _finding("rw-taint", "skillspector", ["AFR-08", "AFR-09"], Severity.CRITICAL, Confidence.HIGH,
                 "src/agent.py", 42, "TT3 Tainted flow: os.getenv -> requests.post"),
    ]
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-09", "status": "gap", "confidence": "high",
             "evidence": ["rw-taint"], "rationale": "env credential flows to an outbound call"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report_with(findings), model=model)
    by_control = {p.afr_control: p for p in report.posture_items}
    assert by_control["AFR-09"].status is PostureStatus.UNKNOWN  # downgraded from gap
    assert by_control["AFR-09"].confidence is Confidence.MEDIUM  # likely gap — verify
    assert report.verdict is Verdict.PROVISIONAL
    assert report.verdict is not Verdict.NO_GO
    assert any("downgraded" in n for n in report.notes)


def test_pass_citing_a_finding_is_rewritten_to_couldnt_determine():
    """No detector emits presence-of-control evidence, so a 'pass' citing a finding
    (a problem) is baseless. The pass guard rewrites it to 'couldn't determine'
    (unknown/low) — absence/contradiction of findings must never read as 'in place'."""
    findings = [
        _finding("rw-secret1", "gitleaks", ["AFR-05", "AFR-06"], Severity.HIGH, Confidence.HIGH,
                 ".env", 1, "Generic API Key"),
    ]
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-05", "status": "pass", "confidence": "high",
             "evidence": ["rw-secret1"], "rationale": "credentials look managed"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report_with(findings), model=model)
    by_control = {p.afr_control: p for p in report.posture_items}
    assert by_control["AFR-05"].status is PostureStatus.UNKNOWN
    assert by_control["AFR-05"].confidence is Confidence.LOW
    assert report.verdict is not Verdict.GO


def test_osv_pass_is_floored_to_gap():
    """odr-shape: the model wrongly asserts AFR-10 *pass* over a real OSV dependency
    finding. The pass guard strips the baseless pass, then the mechanical floor
    reasserts AFR-10 as a confirmed gap from the OSV evidence — the dependency gap
    can't be wobbled away."""
    findings = [
        _finding("rw-dep1", "osv-scanner", ["AFR-10"], Severity.HIGH, Confidence.HIGH,
                 "requirements.txt", 3, "Vulnerable dependency langchain"),
    ]
    model = FakeModel({
        "map": {"items": [
            {"afr_control": "AFR-10", "status": "pass", "confidence": "high",
             "evidence": ["rw-dep1"], "rationale": "deps look scanned"},
        ]},
        "translate": {"items": []},
    })
    report = interpret(_report_with(findings), model=model)
    by_control = {p.afr_control: p for p in report.posture_items}
    assert by_control["AFR-10"].status is PostureStatus.GAP
    assert by_control["AFR-10"].confidence is Confidence.HIGH
    assert by_control["AFR-10"].evidence == ["rw-dep1"]
    assert any("mechanically derived" in n for n in report.notes)


def test_floor_ignores_secrets_and_patterns():
    """The floor is scoped to the OSV route. A repo whose only findings are a
    real-source secret (direct, but AFR-05/06) and a code pattern must not gain a
    mechanical AFR-10 gap — flooring a lone secret is the VF-1 failure shape the
    floor deliberately avoids."""
    findings = [
        _finding("rw-secret1", "gitleaks", ["AFR-05", "AFR-06"], Severity.HIGH, Confidence.HIGH,
                 ".env", 1, "Generic API Key"),
        _finding("rw-code1", "skillspector", ["AFR-08", "AFR-09"], Severity.MEDIUM, Confidence.MEDIUM,
                 "agent.py", 9, "subprocess call"),
    ]
    model = FakeModel({"map": {"items": []}, "translate": {"items": []}})
    report = interpret(_report_with(findings), model=model)
    assert "AFR-10" not in {p.afr_control for p in report.posture_items}
    assert report.posture_items == []  # nothing floored, nothing invented
