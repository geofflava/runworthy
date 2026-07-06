"""The interpretation nodes as plain, testable functions.

``graph.py`` wires these into a LangGraph ``StateGraph``; the tests call them
directly with a replay-mode model. Splitting the logic out this way keeps the
anti-hallucination enforcement (evidence validation, retry, drop) in code the eval
suite exercises without booting the graph runtime.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..afr import summarize
from ..afr_catalog import CONTROLS
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


def _findings_digest(findings: list) -> tuple[str, set[str], dict[str, object], int]:
    if not findings:
        return "(no findings)", set(), {}, 0
    lines: list[str] = []
    citeable: set[str] = set()
    by_id: dict[str, object] = {}
    shown = 0
    for tag, group in _group_findings(findings):
        header = ", ".join(tag)
        lines.append(f"[{header}] {len(group)} finding(s):")
        take = min(EXAMPLES_PER_GROUP, MAX_TOTAL_EXAMPLES - shown)
        for f in group[:max(take, 0)]:
            msg = mask_secrets((f.raw_message or "").replace("\n", " "))[:_MSG_CLIP]
            lines.append(f"  {f.finding_id} · {f.file}:{f.line} · {f.detector} · {f.severity} · {msg}")
            citeable.add(f.finding_id)
            by_id[f.finding_id] = f
            shown += 1
        remaining = len(group) - min(len(group), max(take, 0))
        if remaining > 0:
            lines.append(f"  (+{remaining} more of the same kind, all in the report)")
        if shown >= MAX_TOTAL_EXAMPLES:
            break
    dropped = len(findings) - len(citeable)
    return "\n".join(lines), citeable, by_id, dropped


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
    findings_digest, citeable, by_id, dropped = _findings_digest(report.findings)
    answers_digest, ans_by_id = _answers_digest(answers)
    return MapContext(
        surface=_surface_text(report.agent_map),
        findings_digest=findings_digest,
        answers_digest=answers_digest,
        controls_text=_controls_text(),
        citeable_ids=citeable | set(ans_by_id),
        finding_by_id=by_id,
        answer_by_id=ans_by_id,
        dropped_examples=dropped,
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


def _validate(items: list[MapItem], citeable: set[str]) -> tuple[list[MapItem], list[MapItem], set[str]]:
    """Split items into (valid, invalid). Invalid = cites an id not in evidence, or
    asserts pass/gap without high-confidence grounding. Returns the offending ids too."""
    valid: list[MapItem] = []
    invalid: list[MapItem] = []
    bad_ids: set[str] = set()
    for it in items:
        if it.afr_control not in AFR_CONTROLS:
            invalid.append(it)
            continue
        unknown_ids = [e for e in it.evidence if e not in citeable]
        if unknown_ids:
            bad_ids.update(unknown_ids)
            invalid.append(it)
            continue
        if it.status in (PostureStatus.PASS, PostureStatus.GAP):
            # a confirmed pass/gap must be grounded and high-confidence
            if not it.evidence or it.confidence is not Confidence.HIGH:
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
        items = [mi for mi in (_coerce_item(r) for r in out.get("items", [])) if mi is not None]
        v, invalid, bad_ids = _validate(items, ctx.citeable_ids)
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
    for r in out.get("items", []):
        try:
            idx = int(r["index"])
        except (KeyError, ValueError, TypeError):
            continue
        if 0 <= idx < len(items):
            result[idx] = (str(r.get("plain_explanation", "")).strip(), str(r.get("fix", "")).strip())
    return result


# --- synthesize (deterministic) ----------------------------------------------


def _fallback_text(it: MapItem) -> tuple[str, str]:
    c = CONTROLS[it.afr_control]
    if it.confidence is Confidence.LOW:
        return (f"Couldn't determine {c.title} ({it.afr_control}) from the code.", c.question)
    return (it.rationale or f"{c.title} ({it.afr_control}).", "Review this control and confirm it is in place.")


def assemble(
    report: ReadinessReport,
    items: list[MapItem],
    translations: dict[int, tuple[str, str]],
    answers: list[OperationalAnswer],
    notes: list[str],
) -> ReadinessReport:
    posture: list[PostureItem] = []
    for i, it in enumerate(items):
        expl, fix = translations.get(i) or _fallback_text(it)
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
    all_notes = list(report.notes) + notes
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
