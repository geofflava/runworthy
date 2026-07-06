# Runworthy

**An agent operations scanner.** Runworthy scans a code repository for AI-agent
security and operational-safety gaps and returns a plain-English **GO / NO-GO /
PROVISIONAL** grade against the [**Agent Flight Rules (AFR)**](https://github.com/geofflava/agent-flight-rules)
— for the small teams shipping agents who can't read a SARIF file.

It is **defensive** tooling: it orchestrates published open-source scanners
(NVIDIA SkillSpector, gitleaks, OSV-Scanner) behind adapters and adds an
interpretation layer on top. It does **not** build exploits, malware, or attack
tooling.

> **Phase 0** (this release) is the deterministic core: fingerprint the agent
> surface, run the three contained detectors, and emit a **provisional,
> self-contained `ReadinessReport`** as JSON — every finding evidence-bound to a
> `file:line`, secrets redacted, no LLM anywhere. The AFR *grade* (the GO/NO-GO
> verdict and plain-English translation) arrives in Phase 1.

---

## Install

```bash
pip install runworthy
```

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
# scan a local checkout
runworthy scan ./path/to/repo --pretty

# scan a public repo (shallow, read-only clone; code is never executed)
runworthy scan https://github.com/langchain-ai/open_deep_research

# owner/repo shorthand works too
runworthy scan langchain-ai/open_deep_research -o report.json

# module form
python -m runworthy scan ./repo
```

`scan` prints a `ReadinessReport` JSON to stdout (or `--output FILE`) and a
one-line human summary to stderr. The report is **self-contained**: it embeds
the findings it cites, so any downstream renderer works from the JSON offline.

### What Phase 0 emits

- `verdict`: always `PROVISIONAL` — no Boldface control can be *confirmed*
  without the Phase 1 interpretation layer and the operational overlay.
- `findings[]`: normalized, deduplicated, redacted findings, each with
  `file:line`, the detector(s) that found it, and the mechanically-mapped AFR
  control(s).
- `agent_map`: the fingerprinted agent surface (frameworks, entrypoints, tools,
  prompts, MCP servers, skills, memory stores).
- Full provenance: `commit_sha`, `engine_version`, `detector_versions`,
  `generated_at`.

On a repo with **no agent surface**, Runworthy exits early with an honest
"no agent surface detected" rather than inventing findings.

## How it works

```
scan target ─▶ intake ─▶ fingerprint ─▶ detectors (parallel, adapter-based) ─▶ normalize ─▶ ReadinessReport
              (clone/     (AgentMap)      gitleaks · OSV-Scanner ·              (dedup,        (provisional JSON)
               resolve                     SkillSpector — contained)            redact)
               SHA)
```

Design rule: **deterministic detectors produce evidence; they never produce the
grade.** Nothing is asserted that isn't traceable to a `file:line`. See
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
pip install -e ".[dev]"
python -m runworthy.schema_export schemas           # regenerate JSON Schemas
pytest                                              # golden + invariant + fingerprint suites
```

Tests tagged `@pytest.mark.tools` need the pinned detector binaries on `PATH`;
they skip cleanly when a tool is absent.

## License

Runworthy is **MIT** licensed. The orchestrated scanners retain their own
permissive licenses (SkillSpector — Apache-2.0, gitleaks — MIT, OSV-Scanner —
Apache-2.0); see [`NOTICE`](NOTICE). TruffleHog (AGPL-3.0) is deliberately
excluded. The Agent Flight Rules framework is **CC BY 4.0**.

Maintained by **Geoff "Lava" Lavagnino** · [Obsidicore LLC](https://obsidicore.com).
