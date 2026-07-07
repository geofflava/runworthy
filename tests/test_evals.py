"""The eval harness (WP-03 definition of done, AC3/AC4).

Runs the interpretation graph against each labeled case's recorded detector +
model output (no live rescan, no key) and fails on any uncited assertion, wrong
band/verdict, out-of-budget status, or forbidden claim. Determinism is checked by
running each case twice (QA: back-to-back stability).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import evalkit  # noqa: E402  (tests/ dir, added to path above)

CASES = evalkit.discover()

pytestmark = pytest.mark.skipif(not CASES, reason="no eval cases under evals/*.eval.json")


@pytest.mark.parametrize("path", CASES, ids=[p.stem for p in CASES])
def test_eval_case(path):
    case = evalkit.load_case(path)
    graded = evalkit.run(case)
    problems = evalkit.check(case, graded)
    assert not problems, f"{case.name}:\n  " + "\n  ".join(problems)


@pytest.mark.parametrize("path", CASES, ids=[p.stem for p in CASES])
def test_eval_case_is_deterministic(path):
    """Same recorded inputs -> identical grade twice in a row (no ordering/temperature drift)."""
    case = evalkit.load_case(path)
    a = evalkit.run(case).model_dump(mode="json")
    b = evalkit.run(case).model_dump(mode="json")
    assert a == b
