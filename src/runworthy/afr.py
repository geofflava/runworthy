"""The AFR grade — deterministic scoring, bands, and the GO/NO-GO verdict.

This module is the framework's arithmetic, in code. It contains **no LLM and no
I/O**: it turns a set of assessed controls into a band and a verdict exactly as
``docs/agent-flight-rules.md`` §"Scoring & readiness bands" specifies. The
interpretation layer proposes evidence-backed ``PostureItem``s; this module — and
only this module — decides what grade they add up to. Keeping the math here (not
in a prompt) is what lets the eval suite pin it.

The three rules that make partial observability honest (spec §4):
- ``unknown != 0``. An unassessed control scores nothing and is *not* counted as
  a failure. It holds the verdict at PROVISIONAL until someone answers.
- ``GO`` needs every Boldface control assessed at >= 1 **with evidence**.
- ``NO_GO`` needs at least one Boldface control **confirmed** at 0 (an
  evidence-backed gap). A confirmed Boldface zero is Exposed, full stop.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import BOLDFACE, PostureItem, PostureStatus, Verdict

# --- Bands (AFR §Scoring) ----------------------------------------------------

BAND_EXPOSED = "Exposed"
BAND_BASELINE = "Baseline"
BAND_MANAGED = "Managed"
BAND_RESILIENT = "Resilient"

MAX_SCORE = 58  # 29 controls * 2

#: pass/gap map to a control score; unknown is unassessed (None), never 0.
#: A scan can show a control is *present* (score 1); it can rarely show it is
#: *tested* (score 2 — drills, denied requests, expiry policies), so a scan-only
#: pass is conservatively a 1. Score 2 arrives from the operational overlay.
_STATUS_SCORE: dict[PostureStatus, int | None] = {
    PostureStatus.PASS: 1,
    PostureStatus.GAP: 0,
    PostureStatus.UNKNOWN: None,
}


def band_for_scorecard(scores: dict[str, int]) -> str:
    """Return the AFR band for a **complete** scorecard: every AFR control mapped
    to an integer 0, 1, or 2.

    Bands are conditional — a raw total cannot buy a band the Boldface doesn't
    support (AFR §Scoring):

    - **Exposed**   — any Boldface at 0, or total < 20.
    - **Baseline**  — all Boldface >= 1 and total >= 20.
    - **Managed**   — all Boldface at 2 and total >= 38.
    - **Resilient** — all Boldface at 2, no control at 0, total >= 50.

    Note the two truths the band names encode: a perfect Boldface (all ten at 2)
    with nothing else lands exactly at Baseline — the floor — and you cannot
    reach Managed with an untested kill-switch.
    """
    missing = set(BOLDFACE) - scores.keys()
    if missing:
        raise ValueError(f"incomplete scorecard: missing Boldface controls {sorted(missing)}")
    if any(v not in (0, 1, 2) for v in scores.values()):
        bad = {k: v for k, v in scores.items() if v not in (0, 1, 2)}
        raise ValueError(f"scores must be 0, 1, or 2; got {bad}")

    total = sum(scores.values())
    boldface_scores = [scores[c] for c in BOLDFACE]
    all_boldface_2 = all(s == 2 for s in boldface_scores)
    no_control_zero = all(s > 0 for s in scores.values())

    if min(boldface_scores) == 0 or total < 20:
        return BAND_EXPOSED
    if all_boldface_2 and no_control_zero and total >= 50:
        return BAND_RESILIENT
    if all_boldface_2 and total >= 38:
        return BAND_MANAGED
    return BAND_BASELINE


# --- Verdict & posture aggregation -------------------------------------------


def control_status(items: list[PostureItem]) -> dict[str, PostureStatus]:
    """Collapse posture items to one status per control.

    A control may attract several items (e.g. many findings map to AFR-09). The
    aggregate follows the precedence **gap > pass > unknown**: a single
    evidence-backed gap makes the control a gap; otherwise an evidence-backed
    pass makes it a pass; otherwise it is unknown (unassessed).

    Only items carrying evidence can assert pass or gap — an item without
    evidence cannot claim a control is either in place or broken (the
    anti-hallucination contract, spec §4). Such items degrade to ``unknown``.
    """
    result: dict[str, PostureStatus] = {}
    for it in items:
        grounded = bool(it.evidence)
        if it.status is PostureStatus.GAP and grounded:
            status = PostureStatus.GAP
        elif it.status is PostureStatus.PASS and grounded:
            status = PostureStatus.PASS
        else:
            status = PostureStatus.UNKNOWN

        prev = result.get(it.afr_control)
        result[it.afr_control] = _dominant(prev, status)
    return result


def _dominant(a: PostureStatus | None, b: PostureStatus) -> PostureStatus:
    order = {PostureStatus.GAP: 2, PostureStatus.PASS: 1, PostureStatus.UNKNOWN: 0}
    if a is None:
        return b
    return a if order[a] >= order[b] else b


def verdict_from_status(status_by_control: dict[str, PostureStatus]) -> Verdict:
    """Apply the GO/NO-GO/PROVISIONAL rule to per-control statuses.

    Precedence is deliberate: a confirmed Boldface gap is ``NO_GO`` even if other
    Boldface controls are still unknown — a known company-ending gap is not
    rescued by unanswered questions.
    """
    boldface_status = {c: status_by_control.get(c, PostureStatus.UNKNOWN) for c in BOLDFACE}
    if any(s is PostureStatus.GAP for s in boldface_status.values()):
        return Verdict.NO_GO
    if all(s is PostureStatus.PASS for s in boldface_status.values()):
        return Verdict.GO
    return Verdict.PROVISIONAL


@dataclass(frozen=True)
class GradeSummary:
    verdict: Verdict
    band: str | None  # None => provisional band; renderer shows "N of 29 assessed"
    score: int
    assessed_controls: int
    status_by_control: dict[str, PostureStatus]

    @property
    def provisional(self) -> bool:
        return self.band is None


def summarize(items: list[PostureItem]) -> GradeSummary:
    """Turn evidence-backed posture items into the report's grade fields.

    ``band`` is only named when it can be named honestly:
    - ``NO_GO`` -> **Exposed** (a confirmed Boldface zero is Exposed by rule,
      regardless of what else is still unknown).
    - all 29 controls assessed -> the full ``band_for_scorecard`` result.
    - otherwise -> ``None``: a provisional band the renderer prints as
      "provisional — N of 29 controls assessed."
    """
    status_by_control = control_status(items)
    verdict = verdict_from_status(status_by_control)

    scores = {c: _STATUS_SCORE[s] for c, s in status_by_control.items()}
    assessed = {c: v for c, v in scores.items() if v is not None}
    score = sum(assessed.values())

    if verdict is Verdict.NO_GO:
        band: str | None = BAND_EXPOSED
    elif len(assessed) == len(_all_controls()):
        band = band_for_scorecard(assessed)
    else:
        band = None

    return GradeSummary(
        verdict=verdict,
        band=band,
        score=score,
        assessed_controls=len(assessed),
        status_by_control=status_by_control,
    )


def _all_controls() -> tuple[str, ...]:
    from .models import AFR_CONTROLS

    return AFR_CONTROLS
