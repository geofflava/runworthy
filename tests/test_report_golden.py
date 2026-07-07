"""Golden Markdown render for proof repo 1 (AC5).

Renders the graded open_deep_research report (from its eval case) and pins the
output. Regenerate after a prompt/label change or a fresh cassette recording:

    RW_UPDATE_GOLDEN=1 pytest tests/test_report_golden.py

The report's ``target_ref`` is set to the ``owner/repo`` slug so the render
exercises that deep-link form too (the fixture itself carries the full URL).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import evalkit  # noqa: E402

from runworthy.render import render_markdown  # noqa: E402

GOLDEN = Path(__file__).parent / "golden" / "open_deep_research.report.md"


def _rendered() -> str:
    case = evalkit.load_case(evalkit.EVALS_DIR / "open_deep_research.eval.json")
    graded = evalkit.run(case).model_copy(update={"target_ref": "langchain-ai/open_deep_research"})
    return render_markdown(graded)


def test_proof_repo_1_golden_render():
    md = _rendered()

    # Post-VF-1: the honest grade is PROVISIONAL. The placeholder in .env.example is
    # not a committed secret, so there is no Confirmed Boldface gap and the pipeline
    # refuses to invent one — the real AFR-10 vulnerable-deps gap still stands.
    assert "## Verdict: PROVISIONAL" in md
    assert "NO-GO" not in md
    assert "commit `408da44" in md and "gitleaks 8.30.1" in md  # provenance
    for gate in ("AFR-01", "AFR-04", "AFR-05", "AFR-09", "AFR-11", "AFR-12", "AFR-16", "AFR-17", "AFR-20", "AFR-25"):
        assert f"| {gate} |" in md
    assert "## Confirmed gaps" in md
    assert "AFR-10 — Scan the agent stack" in md
    # The false positive must be gone: no AFR-05 credential gap, no placeholder cited.
    assert "AFR-05 — Per-agent credentials" not in md
    assert ".env.example" not in md and "hardcoded" not in md
    assert "## Likely gaps — verify" in md
    assert "## Couldn't determine" in md
    assert "https://github.com/langchain-ai/open_deep_research/blob/408da44" in md  # deep link
    assert "CC BY 4.0" in md and "not a certification" in md  # footer

    if os.environ.get("RW_UPDATE_GOLDEN"):
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(md, encoding="utf-8")
    assert GOLDEN.exists(), "golden missing — regenerate with RW_UPDATE_GOLDEN=1"
    assert md == GOLDEN.read_text(encoding="utf-8"), "render drifted — regenerate with RW_UPDATE_GOLDEN=1"
