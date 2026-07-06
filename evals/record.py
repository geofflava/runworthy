"""Record live model output into an eval case, then re-check it against its labels.

Key-gated: needs ANTHROPIC_API_KEY. Replaces a case's hand-authored ``responses``
(kept as a keyless stand-in) with the actual model's map/translate output, so the
committed cassette reflects what the current prompt really produces. The labels are
the ground truth and must still pass — if they don't, fix the prompt or the labels,
not the recording.

    python evals/record.py evals/open_deep_research.eval.json
    python evals/record.py --all
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

import evalkit  # noqa: E402
from runworthy.interpret import interpret  # noqa: E402
from runworthy.model import StructuredModel, TokenBudget  # noqa: E402
from runworthy.model.client import DEFAULT_MODEL  # noqa: E402


class RecordingModel:
    """Delegates to a live model and keeps the last response per node."""

    def __init__(self, inner: StructuredModel):
        self.inner = inner
        self.responses: dict[str, dict] = {}

    def complete(self, *, node: str, system: str, user: str, schema: dict) -> dict:
        r = self.inner.complete(node=node, system=system, user=user, schema=schema)
        self.responses[node] = r
        return r


def record_case(path: Path, *, token_budget: int | None) -> bool:
    case = evalkit.load_case(path)
    inner = StructuredModel(
        mode="live", store=None,
        namespace=f"{case.report.commit_sha or 'local'}::{case.report.engine_version}",
        budget=TokenBudget(max_tokens=token_budget), model_id=DEFAULT_MODEL,
    )
    recorder = RecordingModel(inner)
    graded = interpret(case.report, model=recorder)

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["responses"] = {k: recorder.responses.get(k, {"items": []}) for k in ("map", "translate")}
    path.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    # re-check the recorded output against the (unchanged) labels
    case = evalkit.load_case(path)
    problems = evalkit.check(case, evalkit.run(case))
    tokens = inner.budget.total
    if problems:
        print(f"[FAIL] {case.name} ({tokens} tokens):")
        for p in problems:
            print(f"   - {p}")
        return False
    print(f"[ok]   {case.name} — {graded.verdict}, band {graded.band} ({tokens} tokens)")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description="Record live model output into eval cases.")
    ap.add_argument("cases", nargs="*", type=Path, help="case files (default: --all)")
    ap.add_argument("--all", action="store_true", help="record every evals/*.eval.json")
    ap.add_argument("--token-budget", type=int, default=120_000)
    args = ap.parse_args()

    cases = args.cases or (evalkit.discover() if args.all else [])
    if not cases:
        ap.error("give case paths or --all")
    budget = args.token_budget if args.token_budget > 0 else None
    ok = all(record_case(Path(c), token_budget=budget) for c in cases)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
