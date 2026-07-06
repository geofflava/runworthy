# Runworthy

**An agent operations scanner.** Runworthy scans a code repository for AI-agent
security and operational-safety gaps and returns a plain-English **GO / NO-GO /
PROVISIONAL** grade against the [**Agent Flight Rules (AFR)**](https://github.com/geofflava/agent-flight-rules)
— for the small teams shipping agents who can't read a SARIF file.

It is **defensive** tooling: it orchestrates published open-source scanners
(NVIDIA SkillSpector, gitleaks, OSV-Scanner) behind adapters and adds an
interpretation layer on top. It does **not** build exploits, malware, or attack
tooling.

> How it grades. Phase 0 is the deterministic core: fingerprint the agent
> surface, run the three contained detectors, and produce a self-contained
> `ReadinessReport` where every finding is evidence-bound to a `file:line` and
> secrets are redacted. Phase 1 adds the AFR *grade*: a LangGraph interpretation
> layer maps that evidence to controls, translates each into plain English, and
> computes the GO / NO-GO / PROVISIONAL verdict. Every claim traces to a finding,
> and it says "couldn't determine" wherever the code can't. Use `--no-llm` for the
> deterministic report alone.

---

## Install

```bash
pip install runworthy          # deterministic core + --no-llm
pip install "runworthy[llm]"   # + the AFR grade (interpretation layer)
```

The `[llm]` extra pulls `anthropic` and `langgraph`. A graded scan needs a Claude
API key on `ANTHROPIC_API_KEY` (bring your own — the CLI is BYOK, and only
redacted findings ever reach the model). Without the extra or a key, `runworthy
scan` still runs and returns the provisional report.

Runworthy orchestrates three external scanners. They are **version-pinned,
resolved on your `PATH`, and never vendored** — install them once and Runworthy
finds them:

| Tool | Pinned | Install |
|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | `8.30.1` | `scoop install gitleaks` · `brew install gitleaks` · [release binary](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1) |
| [osv-scanner](https://github.com/google/osv-scanner) | `2.4.0` | `scoop install osv-scanner` · `brew install osv-scanner` · [release binary](https://github.com/google/osv-scanner/releases/tag/v2.4.0) |
| [SkillSpector](https://github.com/NVIDIA/SkillSpector) | `2.3.9` | `pipx install "git+https://github.com/NVIDIA/skillspector.git@v2.3.9"` or `uv tool install git+https://github.com/NVIDIA/skillspector.git` |

Then verify:

```bash
runworthy doctor
```

`doctor` reports each tool's presence, resolved version, and any pin mismatch,
and **exits nonzero if a required tool is missing** — so CI fails loudly rather
than scanning with half a toolchain.

## Usage

```bash
# scan a public repo and print the AFR report as Markdown (needs a key)
runworthy scan https://github.com/langchain-ai/open_deep_research

# owner/repo shorthand; write the machine-readable report
runworthy scan langchain-ai/open_deep_research --format json -o report.json

# deterministic findings only — no model, no key, fully offline
runworthy scan ./path/to/repo --no-llm

# don't prompt (skip the operational overlay; stays PROVISIONAL)
runworthy scan ./repo --non-interactive
```

By default `scan` renders a plain-English Markdown report to stdout (`--format
json` for the self-contained `ReadinessReport`; `-o FILE` to write either, format
inferred from the extension). A one-line summary goes to stderr.

After the scan, the CLI asks the handful of Boldface questions code can't see (a
named owner for AFR-01, a tested kill-switch for AFR-20, an incident runbook for
AFR-25) and folds your answers into the grade. `--non-interactive` skips them.

Other flags: `--byok` (fail if no key rather than falling back), `--token-budget N`
(a per-scan ceiling; a breach fails loud), `--model ID`, `--pretty`.

### What a scan emits

- `verdict`: `GO` (every Boldface assessed ≥1 with evidence), `NO_GO` (a Boldface
  control confirmed at 0), or `PROVISIONAL` (a Boldface control not yet assessed —
  unknown never counts as a failure).
- `band`: the AFR band (`Exposed` … `Resilient`), or a provisional band with a
  count of controls assessed.
- `posture_items[]`: the interpreted assessment per control — status, confidence
  tier (Confirmed / Likely gap — verify / Couldn't determine), evidence ids,
  plain explanation, and the fix.
- `findings[]`: normalized, deduplicated, redacted findings, each with `file:line`
  and the detector(s) that found it — embedded, so the report renders offline.
- `agent_map` and full provenance (`commit_sha`, `engine_version`,
  `detector_versions`, `generated_at`).

On a repo with **no agent surface**, Runworthy exits early with an honest
"no agent surface detected" rather than inventing findings.

## How it works

```
scan target ─▶ intake ─▶ fingerprint ─▶ detectors ─▶ normalize ─▶ interpret ────────▶ overlay ─▶ ReadinessReport
              (clone/     (AgentMap)     gitleaks ·   (dedup,      (LangGraph:          (the       (graded, self-
               resolve                   OSV ·        redact)       map→translate→       Boldface   contained report)
               SHA)                      SkillSpector)               synthesize)          Q&A)
```

Design rule: **deterministic detectors produce evidence; they never produce the
grade.** The model only reasons over evidence that already exists and must cite
it; the band and verdict are computed in tested code (`afr.py`), not by the model.
Nothing is asserted that isn't traceable to a `file:line` or an explicit,
labeled "couldn't determine." See
[`docs/adapters.md`](docs/adapters.md) for the adapter containment rules — in
particular the SkillSpector filter that turns an 86-finding false-positive flood
into a handful of defensible findings.

## Privacy

Local and private scans run **entirely on your machine** — nothing is uploaded.
The engine's own network egress is limited to `git clone` (intake) and the
pinned detectors' own remote, OSV.dev. Secret *values* never appear in any
emitted artifact (gitleaks runs with `--redact`; a redaction pass masks every
other snippet).

## Development

```bash
git clone https://github.com/geofflava/runworthy && cd runworthy
python -m venv .venv && . .venv/Scripts/activate   # or .venv/bin/activate
pip install -e ".[dev,llm]"
python -m runworthy.schema_export schemas           # regenerate JSON Schemas
pytest                                              # grade, interpret, overlay, render, eval, golden
```

Tests tagged `@pytest.mark.tools` need the pinned detector binaries on `PATH` and
skip cleanly when a tool is absent. The eval suite (`tests/test_evals.py`) replays
recorded model output against labeled scans (no key needed) and is the release
gate for the grade; see [`evals/README.md`](evals/README.md) to add a labeled repo.

## License

Runworthy is **MIT** licensed. The orchestrated scanners retain their own
permissive licenses (SkillSpector — Apache-2.0, gitleaks — MIT, OSV-Scanner —
Apache-2.0); see [`NOTICE`](NOTICE). TruffleHog (AGPL-3.0) is deliberately
excluded. The Agent Flight Rules framework is **CC BY 4.0**.

Maintained by **Geoff "Lava" Lavagnino** · [Obsidicore LLC](https://obsidicore.com).
