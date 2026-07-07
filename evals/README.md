# Eval corpus

Labeled scans that gate the interpretation layer. Each case runs the LangGraph
graph against **recorded** detector output (a committed Phase-0 report) and
**recorded** model output — no live rescanning, no API key — and the suite
(`tests/test_evals.py`) fails on any uncited assertion, wrong band/verdict,
out-of-budget status, or forbidden claim. It runs in CI.

## A case: `<name>.eval.json`

```jsonc
{
  "report": "examples/open_deep_research.json",   // a Phase-0 ReadinessReport (repo-relative)
  "responses": {                                   // recorded model output, keyed by node
    "map":       { "items": [ /* proposed PostureItems */ ] },
    "translate": { "items": [] }                   // [] -> deterministic fallback prose
  },
  "labels": {
    "verdict": "NO_GO",                            // expected GO | NO_GO | PROVISIONAL
    "band": "Exposed",                             // expected band, or null for provisional
    "expected_status": { "AFR-05": "gap", "AFR-10": "gap", "AFR-01": "unknown" },
    "max_wrong_status": 1,                          // false-positive budget for this case
    "forbidden_assertions": ["certified secure", "no vulnerabilities"]
  }
}
```

`responses` are keyed by node (not by prompt hash) so they survive prompt edits
and stay human-editable. The **labels are the ground truth**; the `responses` are a
stand-in for the model until a real key records them.

## Add a labeled repo

1. Scan it into a committed report: `runworthy scan <url> --no-llm -o examples/<name>.json`
   (a real scan at a pinned commit — needs the detector binaries).
2. Create `evals/<name>.eval.json` pointing `report` at it. Hand-write `labels`
   from the findings and the AFR rubric — this is the judgment the eval encodes.
   Cite only `finding_id`s that exist in the report.
3. Seed `responses` by hand, or record them live (below). Run `pytest tests/test_evals.py`.

## Record live model output (needs `ANTHROPIC_API_KEY`)

```
python evals/record.py evals/<name>.eval.json     # one case
python evals/record.py --all                      # every case
```

This overwrites `responses` with the model's actual output and re-checks it against
the unchanged labels. If a case fails after recording, fix the prompt or the labels
— never loosen a label to make a real miss pass. The documented budget:
**zero uncited claims tolerated; ≤1 wrong-status per repo.**

## Current cases

| Case | Repo | Findings | Expected |
|---|---|---|---|
| `open_deep_research` | langchain-ai/open_deep_research @ 408da44 | 33 | PROVISIONAL (vuln deps → AFR-10 gap; the `.env.example` placeholder is not a real secret) |
| `anthropics_skills` | anthropics/skills @ 9d2f1ae | 67 | PROVISIONAL (vuln deps, risky skill code) |
| `crewai_examples` | crewAIInc/crewAI-examples @ da94a91 | 364 | PROVISIONAL (breadth; 335 vuln deps) |
| `clean_agent_repo` | synthetic | 0 | PROVISIONAL (no findings → no invented gaps) |
