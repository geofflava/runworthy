"""The operational overlay (spec §5): the few Boldface questions code can't see.

After the scan and interpretation, a handful of Boldface controls are still
``unknown`` — the ones that live outside code: a named owner (AFR-01), a tested
kill-switch (AFR-20), an incident runbook (AFR-25), and the like. The overlay asks
only about those, pre-filtered to what the scan couldn't ground, so the operator
answers a short list with the scan's context fresh in mind.

Answers merge into the grade **deterministically** — an operator's plain yes/no is
authoritative, so it becomes an evidence-backed PostureItem without a second model
call. ``--non-interactive`` skips the overlay entirely; the verdict stays
PROVISIONAL, which is the honest outcome of an unanswered Boldface.
"""

from __future__ import annotations

from collections.abc import Callable

from .afr import summarize
from .afr_catalog import CONTROLS
from .models import (
    BOLDFACE,
    AFR_CONTROLS,
    Confidence,
    OperationalAnswer,
    PostureItem,
    PostureStatus,
    ReadinessReport,
    Verdict,
)

_BOLDFACE_ORDER = [c for c in AFR_CONTROLS if c in BOLDFACE]


def pending_boldface(report: ReadinessReport) -> list[str]:
    """Boldface controls the scan left ``unknown`` — the overlay's question set.
    A control the scan already confirmed (pass or a confirmed gap) is not asked."""
    resolved: dict[str, PostureStatus] = {}
    for p in report.posture_items:
        # a confirmed pass/gap resolves the control; a low/medium unknown does not
        if p.status in (PostureStatus.PASS, PostureStatus.GAP) and p.evidence:
            resolved[p.afr_control] = p.status
    return [c for c in _BOLDFACE_ORDER if c not in resolved]


def ask(
    report: ReadinessReport,
    *,
    input_fn: Callable[[str], str] = input,
    output: Callable[[str], None] = print,
    now: str,
) -> list[OperationalAnswer]:
    """Prompt for each pending Boldface control. yes/no become answers; anything
    else (unsure, blank) is left unanswered so it stays honestly unknown."""
    pending = pending_boldface(report)
    if not pending:
        return []
    output("")
    output("A few Boldface controls can't be seen in code. Answer y / n, or press Enter to skip.")
    answers: list[OperationalAnswer] = []
    for cid in pending:
        c = CONTROLS[cid]
        raw = input_fn(f"  [{cid}] {c.question} (y/n/skip) ").strip().lower()
        if raw in ("y", "yes"):
            answer = "yes"
        elif raw in ("n", "no"):
            answer = "no"
        else:
            continue
        answers.append(
            OperationalAnswer(
                answer_id=f"op-{cid.lower().replace('-', '')}",
                afr_control=cid,
                question=c.question,
                answer=answer,
                answered_at=now,
            )
        )
    return answers


def _posture_from_answer(a: OperationalAnswer) -> PostureItem:
    c = CONTROLS[a.afr_control]
    if a.answer == "yes":
        status = PostureStatus.PASS
        explanation = f"You confirmed this is in place: {c.title} ({a.afr_control})."
        fix = "Keep it current — re-check it at your next quarterly review."
    else:  # "no"
        status = PostureStatus.GAP
        explanation = f"You told us this isn't in place: {c.title} ({a.afr_control})."
        fix = c.question
    return PostureItem(
        afr_control=a.afr_control,
        status=status,
        confidence=Confidence.HIGH,  # an operator's answer is authoritative
        boldface=a.afr_control in BOLDFACE,
        evidence=[a.answer_id],
        plain_explanation=explanation,
        fix=fix,
    )


def merge(report: ReadinessReport, answers: list[OperationalAnswer]) -> ReadinessReport:
    """Fold operator answers into the grade. Answer-derived items win for their
    control (an explicit yes/no overrides an inferred absence), then the whole set
    is re-graded."""
    if not answers:
        return report
    answered = {a.afr_control for a in answers}
    kept = [p for p in report.posture_items if p.afr_control not in answered]
    added = [_posture_from_answer(a) for a in answers]
    posture = kept + added
    grade = summarize(posture)

    notes = [n for n in report.notes if not n.startswith("PROVISIONAL:")]
    unresolved = sorted(
        c for c in BOLDFACE
        if grade.status_by_control.get(c, PostureStatus.UNKNOWN) is PostureStatus.UNKNOWN
    )
    if grade.verdict is Verdict.PROVISIONAL and unresolved:
        notes.append(
            f"PROVISIONAL: {len(unresolved)} Boldface control(s) still unassessed — "
            + ", ".join(unresolved)
            + "."
        )

    existing_ids = {a.answer_id for a in report.operational_answers}
    merged_answers = list(report.operational_answers) + [a for a in answers if a.answer_id not in existing_ids]
    return report.model_copy(
        update={
            "verdict": grade.verdict,
            "band": grade.band,
            "score": grade.score,
            "assessed_controls": grade.assessed_controls,
            "posture_items": posture,
            "operational_answers": merged_answers,
            "notes": notes,
        }
    )
