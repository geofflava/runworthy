"""Operational overlay: which Boldface it asks about, and how answers re-grade."""

from __future__ import annotations

from runworthy import overlay
from runworthy.models import (
    Confidence,
    OperationalAnswer,
    PostureItem,
    PostureStatus,
    ReadinessReport,
    Verdict,
)


def _item(control, status, conf=Confidence.HIGH, evidence=("rw-x",)):
    return PostureItem(
        afr_control=control, status=status, confidence=conf, boldface=True,
        evidence=list(evidence), plain_explanation="…", fix="…",
    )


def _report(posture):
    return ReadinessReport(
        posture_items=posture, findings=[], target_ref="owner/repo",
        generated_at="2026-07-06T00:00:00Z", engine_version="0.1.0",
    )


def test_pending_skips_already_confirmed_boldface():
    report = _report([
        _item("AFR-05", PostureStatus.GAP),           # confirmed -> not asked
        _item("AFR-04", PostureStatus.PASS),           # confirmed -> not asked
        _item("AFR-12", PostureStatus.UNKNOWN, Confidence.MEDIUM, evidence=["rw-c"]),  # likely -> still asked
    ])
    pending = overlay.pending_boldface(report)
    assert "AFR-05" not in pending and "AFR-04" not in pending
    assert "AFR-12" in pending  # a likely gap is not a confirmation; still ask
    assert "AFR-20" in pending and "AFR-01" in pending


def test_ask_reads_yes_no_and_skips_blank():
    report = _report([])  # all ten Boldface pending
    scripted = iter(["y", "n", "", "skip", "yes", "no", "n", "y", "", "y"])
    answers = overlay.ask(
        report, input_fn=lambda _prompt: next(scripted), output=lambda _m: None,
        now="2026-07-06T00:00:00Z",
    )
    # 10 pending; blanks/"skip" dropped -> 7 answers
    assert len(answers) == 7
    assert all(a.answer in ("yes", "no") for a in answers)


def test_merge_no_answer_becomes_confirmed_gap_and_nogo():
    report = _report([])
    answers = [OperationalAnswer(
        answer_id="op-afr20", afr_control="AFR-20", question="kill-switch?",
        answer="no", answered_at="2026-07-06T00:00:00Z",
    )]
    merged = overlay.merge(report, answers)
    item = next(p for p in merged.posture_items if p.afr_control == "AFR-20")
    assert item.status is PostureStatus.GAP
    assert item.evidence == ["op-afr20"]
    assert merged.verdict is Verdict.NO_GO  # confirmed Boldface gap


def test_merge_answer_overrides_inferred_absence():
    report = _report([
        _item("AFR-01", PostureStatus.UNKNOWN, Confidence.LOW, evidence=[]),
    ])
    answers = [OperationalAnswer(
        answer_id="op-afr01", afr_control="AFR-01", question="registry?",
        answer="yes", answered_at="2026-07-06T00:00:00Z",
    )]
    merged = overlay.merge(report, answers)
    items = [p for p in merged.posture_items if p.afr_control == "AFR-01"]
    assert len(items) == 1  # the inferred item is replaced, not duplicated
    assert items[0].status is PostureStatus.PASS
    assert items[0].evidence == ["op-afr01"]
