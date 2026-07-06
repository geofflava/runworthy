"""The interpretation nodes as plain, testable functions.

``graph.py`` wires these into a LangGraph ``StateGraph``; the tests call them
directly with a replay-mode model. Splitting the logic out this way keeps the
anti-hallucination enforcement (evidence validation, retry, drop) in code the eval
suite exercises without booting the graph runtime.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..afr import summarize
from ..afr_catalog import CONTROLS
from ..classify import is_template_path
from ..models import (
    AFR_CONTROLS,
    BOLDFACE,
    AgentMap,
    Confidence,
    OperationalAnswer,
    PostureItem,
    PostureStatus,
    ReadinessReport,
    Verdict,
)
from ..redact import mask_secrets
from ..model.client import StructuredModel
from .prompts import MAP_SYSTEM, TRANSLATE_SYSTEM, map_user_prompt, translate_user_prompt
from .schemas import MAP_SCHEMA, TRANSLATE_SCHEMA

EXAMPLES_PER_GROUP = 8
MAX_TOTAL_EXAMPLES = 60
MAX_MAP_RETRIES = 2
_MSG_CLIP = 140

_ORDER = {PostureStatus.GAP: 2, PostureStatus.PASS: 1, PostureStatus.UNKNOWN: 0}
_CONF_ORDER = {Confidence.HIGH: 2, Confidence.MEDIUM: 1, Confidence.LOW: 0}


@dataclass
class MapItem:
    afr_control: str
    status: PostureStatus
    confidence: Confidence
    evidence: list[str]
    rationale: str


@dataclass
class MapContext:
    surface: str
    findings_digest: str
    answers_digest: str
    controls_text: str
    citeable_ids: set[str]
    finding_by_id: dict[str, object]
    answer_by_id: dict[str, OperationalAnswer]
    dropped_examples: int


# --- context building --------------------------------------------------------


def _surface_text(am: AgentMap) -> str:
    if am.is_empty():
        return "(no agent surface detected)"
    parts = []
    for label, vals in (
        ("frameworks", am.frameworks),
        ("entrypoints", am.entrypoints),
        ("tools", am.tools),
        ("mcp_servers", am.mcp_servers),
        ("skills", am.skills),
        ("prompts", am.prompts),
        ("memory_stores", am.memory_stores),
    ):
        if vals:
            parts.append(f"- {label}: {', '.join(vals)}")
    return "\n".join(parts)


def _group_findings(findings: list) -> list[tuple[tuple[str, ...], list]]:
    groups: dict[tuple[str, ...], list] = {}
    for f in findings:
        tag = tuple(f.afr_controls) or ("(unmapped)",)
        groups.setdefault(tag, []).append(f)
    # order by the lowest AFR id in each tag-set for a stable, readable digest
    def sort_key(item):
        tag = item[0]
        return min((c for c in tag if c.startswith("AFR-")), default="AFR-99")

    return sorted(groups.items(), key=sort_key)


def _findings_digest(findings: list) -> tuple[str, int]:
    """Return (digest text, count-not-shown-to-the-model).

    The digest SAMPLES findings (per-group and total caps) only to bound tokens —
    it does not bound what's *citeable*. Every finding in the report is real and
    embedded, so any of their ids is valid evidence (see build_context); a model
    can't guess a sha1 id it never saw, so the cap costs nothing in grounding."""
    if not findings:
        return "(no findings)", 0
    lines: list[str] = []
    shown = 0
    for tag, group in _group_findings(findings):
        header = ", ".join(tag)
        lines.append(f"[{header}] {len(group)} finding(s):")
        take = max(min(EXAMPLES_PER_GROUP, MAX_TOTAL_EXAMPLES - shown), 0)
        for f in group[:take]:
            msg = mask_secrets((f.raw_message or "").replace("\n", " "))[:_MSG_CLIP]
            lines.append(f"  {f.finding_id} · {f.file}:{f.line} · {f.detector} · {f.severity} · {msg}")
            shown += 1
        remaining = len(group) - min(len(group), take)
        if remaining > 0:
            lines.append(f"  (+{remaining} more of the same kind, all in the report)")
        if shown >= MAX_TOTAL_EXAMPLES:
            break
    return "\n".join(lines), len(findings) - shown


def _answers_digest(answers: list[OperationalAnswer]) -> tuple[str, dict[str, OperationalAnswer]]:
    if not answers:
        return "(no operator answers)", {}
    lines = []
    by_id = {}
    for a in answers:
        lines.append(f"  {a.answer_id} · {a.afr_control} · Q: {a.question} · A: {a.answer}")
        by_id[a.answer_id] = a
    return "\n".join(lines), by_id


def _controls_text() -> str:
    rows = []
    for cid in AFR_CONTROLS:
        c = CONTROLS[cid]
        star = " ★" if c.boldface else ""
        rows.append(f"{cid} — {c.title}{star}")
    return "\n".join(rows)


def build_context(report: ReadinessReport, answers: list[OperationalAnswer]) -> MapContext:
    findings_digest, not_shown = _findings_digest(report.findings)
    answers_digest, ans_by_id = _answers_digest(answers)
    # Every finding in the report is real evidence — citeable and resolvable —
    # whether or not the token-bounded digest showed it to the model.
    finding_by_id = {f.finding_id: f for f in report.findings}
    return MapContext(
        surface=_surface_text(report.agent_map),
        findings_digest=findings_digest,
        answers_digest=answers_digest,
        controls_text=_controls_text(),
        citeable_ids=set(finding_by_id) | set(ans_by_id),
        finding_by_id=finding_by_id,
        answer_by_id=ans_by_id,
        dropped_examples=not_shown,
    )


# --- map node ----------------------------------------------------------------


def _coerce_item(raw: dict) -> MapItem | None:
    try:
        return MapItem(
            afr_control=raw["afr_control"],
            status=PostureStatus(raw["status"]),
            confidence=Confidence(raw["confidence"]),
            evidence=[e for e in raw.get("evidence", []) if isinstance(e, str)],
            rationale=str(raw.get("rationale", "")),
        )
    except (KeyError, ValueError):
        return None


def _evidence_supports_control(it: MapItem, ctx: MapContext) -> bool:
    """A confirmed pass/gap must cite at least one piece of evidence that is
    actually *about* this control — a finding the detectors mapped to it, or an
    operator answer for it. This is what stops a real finding for one control from
    'grounding' a confirmed gap on an unrelated Boldface control (which would
    otherwise force a NO_GO the evidence never supported). Inferred items
    (status=unknown) carry no such requirement — they are cautions, not
    confirmations, and may cite a related finding as context."""
    for e in it.evidence:
        f = ctx.finding_by_id.get(e)
        if f is not None and it.afr_control in f.afr_controls:
            return True
        a = ctx.answer_by_id.get(e)
        if a is not None and a.afr_control == it.afr_control:
            return True
    return False


def _validate(items: list[MapItem], ctx: MapContext) -> tuple[list[MapItem], list[MapItem], set[str]]:
    """Split items into (valid, invalid). Invalid = cites an id not in evidence,
    or asserts a pass/gap that isn't high-confidence and grounded in evidence
    *for that control*. Returns the offending ids too."""
    valid: list[MapItem] = []
    invalid: list[MapItem] = []
    bad_ids: set[str] = set()
    for it in items:
        if it.afr_control not in AFR_CONTROLS:
            invalid.append(it)
            continue
        unknown_ids = [e for e in it.evidence if e not in ctx.citeable_ids]
        if unknown_ids:
            bad_ids.update(unknown_ids)
            invalid.append(it)
            continue
        if it.status in (PostureStatus.PASS, PostureStatus.GAP):
            # a confirmed pass/gap must be grounded, high-confidence, AND cite
            # evidence that pertains to the control it asserts
            if not it.evidence or it.confidence is not Confidence.HIGH or not _evidence_supports_control(it, ctx):
                invalid.append(it)
                continue
        valid.append(it)
    return valid, invalid, bad_ids


def _dedupe(items: list[MapItem]) -> list[MapItem]:
    """At most one item per control — keep the most-defined (gap>pass>unknown,
    then highest confidence, then most evidence)."""
    best: dict[str, MapItem] = {}
    for it in items:
        cur = best.get(it.afr_control)
        if cur is None or _rank(it) > _rank(cur):
            best[it.afr_control] = it
    return [best[c] for c in AFR_CONTROLS if c in best]


def _rank(it: MapItem) -> tuple[int, int, int]:
    return (_ORDER[it.status], _CONF_ORDER[it.confidence], len(it.evidence))


def _boldface_confirmation_guard(items: list[MapItem], ctx: MapContext) -> tuple[list[MapItem], int]:
    """Defense in depth for the highest-stakes call. A *Confirmed* gap on a
    Boldface control forces NO-GO, so it must rest on a high-confidence finding in
    real source (not a template/example/docs file) — or an operator's answer.
    Anything weaker is downgraded to "Likely gap — verify" (unknown/medium): still
    surfaced, but it can no longer flip the verdict. This is what stops a
    placeholder in ``.env.example`` from grading a repo NO-GO."""
    out: list[MapItem] = []
    downgraded = 0
    for it in items:
        if it.status is PostureStatus.GAP and it.afr_control in BOLDFACE:
            strong = any(
                (f := ctx.finding_by_id.get(e)) is not None
                and f.confidence is Confidence.HIGH
                and not is_template_path(f.file)
                for e in it.evidence
            )
            answered = any(e in ctx.answer_by_id for e in it.evidence)
            if not (strong or answered):
                out.append(MapItem(it.afr_control, PostureStatus.UNKNOWN, Confidence.MEDIUM, it.evidence, it.rationale))
                downgraded += 1
                continue
        out.append(it)
    return out, downgraded


def run_map(model: StructuredModel, ctx: MapContext) -> tuple[list[MapItem], list[str]]:
    """Call the map node, validate evidence, retry on violations, then drop what
    still doesn't ground. Returns (valid items, notes)."""
    notes: list[str] = []
    user = mask_secrets(
        map_user_prompt(ctx.surface, ctx.findings_digest, ctx.answers_digest, ctx.controls_text)
    )
    valid: list[MapItem] = []
    for attempt in range(MAX_MAP_RETRIES + 1):
        out = model.complete(node="map", system=MAP_SYSTEM, user=user, schema=MAP_SCHEMA)
        items = [mi for mi in (_coerce_item(r) for r in (out.get("items") or [])) if mi is not None]
        v, invalid, bad_ids = _validate(items, ctx)
        valid = _dedupe(v)
        if not invalid:
            break
        if attempt < MAX_MAP_RETRIES:
            fix = (
                "\n\nSome items were rejected. Do not cite ids that are not in the "
                f"evidence above. Rejected/unknown evidence ids: {sorted(bad_ids) or 'none'}. "
                "For pass/gap you MUST give a real evidence id and confidence 'high'; "
                "otherwise use status 'unknown'. Re-emit ALL items, corrected."
            )
            user = mask_secrets(
                map_user_prompt(ctx.surface, ctx.findings_digest, ctx.answers_digest, ctx.controls_text) + fix
            )
        else:
            notes.append(f"{len(invalid)} proposed assessment(s) dropped for unciteable or ungrounded evidence.")
    valid, downgraded = _boldface_confirmation_guard(valid, ctx)
    if downgraded:
        notes.append(
            f"{downgraded} proposed Boldface gap(s) downgraded to 'likely — verify' "
            "for lacking a high-confidence finding in real source."
        )
    if ctx.dropped_examples:
        notes.append(
            f"{ctx.dropped_examples} finding(s) were summarised rather than shown individually to the model "
            "(all remain in the report)."
        )
    return valid, notes


# --- translate node ----------------------------------------------------------


def _evidence_block(items: list[MapItem], ctx: MapContext) -> str:
    ids: list[str] = []
    for it in items:
        for e in it.evidence:
            if e not in ids:
                ids.append(e)
    if not ids:
        return "(none — these are 'couldn't determine' items)"
    lines = []
    for e in ids:
        if e in ctx.finding_by_id:
            f = ctx.finding_by_id[e]
            msg = mask_secrets((f.raw_message or "").replace("\n", " "))[:_MSG_CLIP]
            lines.append(f"{e} · {f.file}:{f.line} · {f.detector} · {msg}")
        elif e in ctx.answer_by_id:
            a = ctx.answer_by_id[e]
            lines.append(f"{e} · answer · {a.afr_control} · {a.answer}")
    return "\n".join(lines)


def run_translate(model: StructuredModel, items: list[MapItem], ctx: MapContext) -> dict[int, tuple[str, str]]:
    if not items:
        return {}
    item_lines = []
    for i, it in enumerate(items):
        c = CONTROLS[it.afr_control]
        item_lines.append(
            f"[{i}] {it.afr_control} ({c.title}) · status={it.status} confidence={it.confidence} "
            f"· evidence={', '.join(it.evidence) or 'none'} · rationale: {it.rationale}"
        )
    user = mask_secrets(translate_user_prompt("\n".join(item_lines), _evidence_block(items, ctx)))
    out = model.complete(node="translate", system=TRANSLATE_SYSTEM, user=user, schema=TRANSLATE_SCHEMA)
    result: dict[int, tuple[str, str]] = {}
    for r in out.get("items") or []:
        try:
            idx = int(r["index"])
        except (KeyError, ValueError, TypeError):
            continue
        if 0 <= idx < len(items):
            result[idx] = (str(r.get("plain_explanation", "")).strip(), str(r.get("fix", "")).strip())
    return result


# --- synthesize (deterministic) ----------------------------------------------


_PATH_LINE_RE = re.compile(r"\b([\w./\\-]+\.[A-Za-z0-9]+):(\d+)\b")


def _prose_grounded(text: str, allowed_files: set[str]) -> bool:
    """True unless the prose names a ``file:line`` we don't actually have evidence
    for. The map node's *evidence ids* are validated, but the translated sentence
    the founder reads is free model text — this stops a hallucinated or transposed
    path from being surfaced as fact."""
    for m in _PATH_LINE_RE.finditer(text):
        if m.group(1).replace("\\", "/") not in allowed_files:
            return False
    return True


def _grounded_or(candidate: str, fallback: str, allowed_files: set[str]) -> str:
    candidate = (candidate or "").strip()
    if candidate and _prose_grounded(candidate, allowed_files):
        return candidate
    return fallback


def _control_generic(it: MapItem) -> tuple[str, str]:
    """A safe, control-derived explanation/fix with no file:line to hallucinate."""
    c = CONTROLS[it.afr_control]
    if it.confidence is Confidence.LOW:
        return (f"Couldn't determine {c.title} ({it.afr_control}) from the code.", c.question)
    if it.status is PostureStatus.GAP:
        return (f"The scan flags {c.title} ({it.afr_control}) as a gap.",
                "Confirm it and close it; the Agent Flight Rules describe what 'in place' looks like.")
    return (f"{c.title} ({it.afr_control}).", "Review this control and confirm it is in place.")


def assemble(
    report: ReadinessReport,
    items: list[MapItem],
    translations: dict[int, tuple[str, str]],
    answers: list[OperationalAnswer],
    notes: list[str],
) -> ReadinessReport:
    by_id = {f.finding_id: f for f in report.findings}
    posture: list[PostureItem] = []
    for i, it in enumerate(items):
        allowed = {by_id[e].file for e in it.evidence if e in by_id}
        gen_expl, gen_fix = _control_generic(it)
        t = translations.get(i) or ("", "")
        # explanation: prefer the translation, then the map rationale, then a
        # generic control line — each accepted only if its file:line claims ground.
        expl = _grounded_or(t[0], _grounded_or(it.rationale, gen_expl, allowed), allowed)
        fix = _grounded_or(t[1], gen_fix, allowed)
        posture.append(
            PostureItem(
                afr_control=it.afr_control,
                status=it.status,
                confidence=it.confidence,
                boldface=it.afr_control in BOLDFACE,
                evidence=it.evidence,
                plain_explanation=expl,
                fix=fix,
            )
        )
    grade = summarize(posture)

    unassessed_boldface = sorted(
        c for c in BOLDFACE if grade.status_by_control.get(c, PostureStatus.UNKNOWN) is PostureStatus.UNKNOWN
    )
    # Drop the Phase-0 "0 of 29 assessed" boilerplate — it's false once graded; the
    # interpretation adds its own accurate PROVISIONAL note below when warranted.
    all_notes = [n for n in report.notes if not n.startswith("PROVISIONAL:")] + notes
    if grade.verdict is Verdict.PROVISIONAL and unassessed_boldface:
        all_notes.append(
            "PROVISIONAL: "
            + str(len(unassessed_boldface))
            + " Boldface control(s) not yet assessed — "
            + ", ".join(unassessed_boldface)
            + ". Answer the operational overlay (or run without --non-interactive) to resolve."
        )

    return report.model_copy(
        update={
            "verdict": grade.verdict,
            "band": grade.band,
            "score": grade.score,
            "assessed_controls": grade.assessed_controls,
            "posture_items": posture,
            "operational_answers": list(answers),
            "notes": all_notes,
        }
    )
