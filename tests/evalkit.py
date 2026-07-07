"""Eval-harness support: load a labeled case, replay recorded model output, and
check the graded report against its labels.

The eval runs the interpretation graph against **recorded** detector output (the
committed Phase-0 report) and **recorded** model output (``responses`` per node) —
no live rescanning, no key. It fails on: an unresolved evidence id, an uncited
pass/gap, a wrong band or verdict, a per-control status beyond the budget, or any
forbidden assertion in the rendered report.

The recorded ``responses`` are keyed by node ('map', 'translate') rather than by
prompt hash, so they survive prompt edits and stay human-editable. When a real key
is available, ``evals/record.py`` overwrites them with live model output and the
same labels must still pass.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from runworthy.afr import control_status
from runworthy.interpret import interpret
from runworthy.models import PostureStatus, ReadinessReport
from runworthy.render import render_markdown

REPO_ROOT = Path(__file__).resolve().parents[1]
EVALS_DIR = REPO_ROOT / "evals"


class ScriptedModel:
    """A StructuredModel stand-in that returns recorded output for each node."""

    def __init__(self, responses: dict[str, dict]):
        self.responses = responses
        self.calls: list[str] = []

    def complete(self, *, node: str, system: str, user: str, schema: dict) -> dict:
        self.calls.append(node)
        return self.responses.get(node, {"items": []})


@dataclass
class EvalCase:
    name: str
    report: ReadinessReport
    responses: dict[str, dict]
    labels: dict


def discover() -> list[Path]:
    return sorted(EVALS_DIR.glob("*.eval.json"))


def load_case(path: Path) -> EvalCase:
    raw = json.loads(path.read_text(encoding="utf-8"))
    report_path = (REPO_ROOT / raw["report"]).resolve()
    report = ReadinessReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    return EvalCase(name=path.stem.replace(".eval", ""), report=report, responses=raw["responses"], labels=raw["labels"])


def run(case: EvalCase) -> ReadinessReport:
    return interpret(case.report, model=ScriptedModel(case.responses))


def check(case: EvalCase, graded: ReadinessReport) -> list[str]:
    """Return a list of failures; empty means the case passes."""
    problems: list[str] = []
    labels = case.labels

    valid_ids = {f.finding_id for f in graded.findings} | {a.answer_id for a in graded.operational_answers}

    # AC3 — every posture item's evidence resolves; no uncited pass/gap.
    for p in graded.posture_items:
        for e in p.evidence:
            if e not in valid_ids:
                problems.append(f"{p.afr_control}: cites unresolved evidence id {e!r}")
        if p.status in (PostureStatus.PASS, PostureStatus.GAP) and not p.evidence:
            problems.append(f"{p.afr_control}: asserts {p.status} with no evidence")

    if "verdict" in labels and str(graded.verdict) != labels["verdict"]:
        problems.append(f"verdict: expected {labels['verdict']}, got {graded.verdict}")
    if "band" in labels and (graded.band or None) != labels["band"]:
        problems.append(f"band: expected {labels['band']!r}, got {graded.band!r}")

    # Per-control status vs labels, within the documented budget.
    status_by = control_status(graded.posture_items)
    wrong: list[str] = []
    for control, expected in labels.get("expected_status", {}).items():
        actual = status_by.get(control, PostureStatus.UNKNOWN)
        if str(actual) != expected:
            wrong.append(f"{control}: expected {expected}, got {actual}")
    budget = labels.get("max_wrong_status", 0)
    if len(wrong) > budget:
        problems.append(f"status mismatches {len(wrong)} > budget {budget}: {wrong}")

    # Forbidden assertions — things the model must not claim for this repo.
    rendered = render_markdown(graded).lower()
    for phrase in labels.get("forbidden_assertions", []):
        if phrase.lower() in rendered:
            problems.append(f"forbidden assertion present: {phrase!r}")

    return problems
