"""The AFR grade is the product's spine — these tests pin it to the framework.

Acceptance criterion 2 (WP-03): verdict semantics and band math match
``docs/agent-flight-rules.md`` §Scoring, including the "perfect Boldface =
Baseline" floor and the "unknown never counts as zero" rule that keeps partial
scans honest.
"""

from __future__ import annotations

import pytest

from runworthy.afr import (
    BAND_BASELINE,
    BAND_EXPOSED,
    BAND_MANAGED,
    BAND_RESILIENT,
    band_for_scorecard,
    control_status,
    summarize,
)
from runworthy.models import AFR_CONTROLS, BOLDFACE, PostureItem, PostureStatus, Verdict

NON_BOLDFACE = [c for c in AFR_CONTROLS if c not in BOLDFACE]


def scorecard(default: int = 0, **overrides: int) -> dict[str, int]:
    """A complete 29-control scorecard, `default` everywhere unless overridden."""
    card = {c: default for c in AFR_CONTROLS}
    card.update(overrides)
    return card


def with_boldface(bold: int, rest: int) -> dict[str, int]:
    card = {c: rest for c in AFR_CONTROLS}
    for c in BOLDFACE:
        card[c] = bold
    return card


# --- Band math (>= 6 constructed scorecards, AFR §Scoring) --------------------


def test_perfect_boldface_alone_is_baseline():
    """The floor, by design: all ten Boldface at 2, everything else 0 == 20 pts."""
    card = with_boldface(bold=2, rest=0)
    assert sum(card.values()) == 20
    assert band_for_scorecard(card) == BAND_BASELINE


@pytest.mark.parametrize(
    "card, expected",
    [
        # 1. everything tested -> Resilient (58)
        (scorecard(2), BAND_RESILIENT),
        # 2. everything present but untested -> Baseline (29)
        (scorecard(1), BAND_BASELINE),
        # 3. one Boldface missing, everything else tested -> Exposed
        (scorecard(2, **{"AFR-20": 0}), BAND_EXPOSED),
        # 4. all Boldface tested + nine non-Boldface tested (zeros remain) -> Managed (38)
        (with_boldface(bold=2, rest=0) | {c: 2 for c in NON_BOLDFACE[:9]}, BAND_MANAGED),
        # 5. all Boldface tested, only one control at zero, total 56 -> Managed (a zero blocks Resilient)
        (scorecard(2, **{NON_BOLDFACE[0]: 0}), BAND_MANAGED),
        # 6. below the floor: every Boldface present but total 19 -> Exposed
        (with_boldface(bold=1, rest=0) | {c: 1 for c in NON_BOLDFACE[:9]}, BAND_EXPOSED),
        # 7. Resilient boundary: all Boldface tested, no zeros, exactly 50
        (with_boldface(bold=2, rest=1) | {c: 2 for c in NON_BOLDFACE[:11]}, BAND_RESILIENT),
        # 8. one Boldface merely present (1) caps a near-perfect card at Baseline
        (scorecard(2, **{"AFR-01": 1}), BAND_BASELINE),
    ],
)
def test_band_math(card, expected):
    assert band_for_scorecard(card) == expected


def test_resilient_needs_no_zeros():
    """All Boldface tested and total >= 50, but a single non-Boldface zero drops
    it to Managed — Resilient tolerates no zeros anywhere."""
    card = scorecard(2, **{NON_BOLDFACE[0]: 0})  # total 56
    assert sum(card.values()) == 56
    assert band_for_scorecard(card) == BAND_MANAGED


def test_incomplete_scorecard_is_an_error():
    with pytest.raises(ValueError, match="incomplete scorecard"):
        band_for_scorecard({"AFR-01": 2})


def test_scores_must_be_0_1_2():
    with pytest.raises(ValueError, match="0, 1, or 2"):
        band_for_scorecard(scorecard(3))


# --- Verdict semantics under partial observability ---------------------------


def item(control: str, status: PostureStatus, *, evidence: list[str] | None = None) -> PostureItem:
    return PostureItem(
        afr_control=control,
        status=status,
        boldface=control in BOLDFACE,
        evidence=[] if evidence is None else evidence,
        plain_explanation="…",
        fix="…",
    )


def test_unknown_boldface_is_provisional_never_exposed():
    """A scan that can't see a Boldface control holds at PROVISIONAL — it must
    never treat 'couldn't determine' as a zero."""
    items = [item(c, PostureStatus.PASS, evidence=["rw-x"]) for c in list(BOLDFACE)[:-1]]
    # last Boldface simply unassessed (no item at all)
    grade = summarize(items)
    assert grade.verdict is Verdict.PROVISIONAL
    assert grade.band is None  # provisional band, not Exposed


def test_confirmed_boldface_zero_is_nogo_and_exposed():
    items = [item(c, PostureStatus.PASS, evidence=["rw-x"]) for c in BOLDFACE if c != "AFR-05"]
    items.append(item("AFR-05", PostureStatus.GAP, evidence=["rw-secret"]))
    grade = summarize(items)
    assert grade.verdict is Verdict.NO_GO
    assert grade.band == BAND_EXPOSED


def test_all_boldface_pass_with_evidence_is_go():
    items = [item(c, PostureStatus.PASS, evidence=["rw-x"]) for c in BOLDFACE]
    grade = summarize(items)
    assert grade.verdict is Verdict.GO
    # non-Boldface still unknown -> band stays provisional even though verdict is GO
    assert grade.band is None
    assert grade.assessed_controls == len(BOLDFACE)


def test_go_with_full_scorecard_names_a_band():
    """Every control assessed as a present-but-untested pass -> GO, Baseline."""
    items = [item(c, PostureStatus.PASS, evidence=["rw-x"]) for c in AFR_CONTROLS]
    grade = summarize(items)
    assert grade.verdict is Verdict.GO
    assert grade.band == BAND_BASELINE
    assert grade.assessed_controls == len(AFR_CONTROLS)
    assert grade.score == len(AFR_CONTROLS)  # all pass == 1 each


def test_confirmed_gap_beats_unknown_for_nogo():
    """One confirmed Boldface gap is NO_GO even while other Boldface are unknown."""
    items = [item("AFR-20", PostureStatus.GAP, evidence=["rw-x"])]
    grade = summarize(items)
    assert grade.verdict is Verdict.NO_GO


def test_evidenceless_gap_cannot_force_nogo():
    """Anti-hallucination: a gap item with no evidence can't assert a failure.
    It degrades to unknown, so the verdict stays PROVISIONAL, not NO_GO."""
    items = [item("AFR-20", PostureStatus.GAP, evidence=[])]
    grade = summarize(items)
    assert grade.status_by_control["AFR-20"] is PostureStatus.UNKNOWN
    assert grade.verdict is Verdict.PROVISIONAL


def test_control_status_precedence_gap_over_pass():
    items = [
        item("AFR-09", PostureStatus.PASS, evidence=["rw-a"]),
        item("AFR-09", PostureStatus.GAP, evidence=["rw-b"]),
    ]
    assert control_status(items)["AFR-09"] is PostureStatus.GAP


def test_score_counts_only_assessed():
    items = [
        item("AFR-01", PostureStatus.PASS, evidence=["rw-a"]),  # +1
        item("AFR-04", PostureStatus.GAP, evidence=["rw-b"]),   # +0
        item("AFR-05", PostureStatus.UNKNOWN),                  # unassessed
    ]
    grade = summarize(items)
    assert grade.score == 1
    assert grade.assessed_controls == 2  # pass + gap; unknown excluded
