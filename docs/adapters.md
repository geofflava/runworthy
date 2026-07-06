# Detector adapters — containment, dedup, mapping

Runworthy **orchestrates** open-source scanners; it does not reimplement them.
Each detector runs behind an adapter that normalizes its native output into the
one `Finding` schema (spec §4) and enforces the contract invariants. This
document is the authoritative record of the containment and dedup rules
(architecture spec §3).

## The three Phase-0 detectors

| Detector | Scope | Native output | Mechanical AFR mapping |
|---|---|---|---|
| **gitleaks** `8.30.1` | whole repo — hardcoded/long-lived secrets | JSON array (`--redact`) | AFR-05, AFR-06 |
| **OSV-Scanner** `2.4.0` | manifests/lockfiles — vulnerable deps | JSON (`results[].packages[]`) | AFR-10 |
| **SkillSpector** `2.3.9` | skill/MCP artifacts + app code (contained) | JSON (`issues[]`) | AFR-08, AFR-09 (code) · AFR-10 (SC4) |

Adapters prefill `afr_controls[]` for these **mechanical** mappings only.
Judgment mappings belong to the Phase 1 interpretation layer and never mutate a
`Finding`.

## gitleaks adapter

- Invoked as `gitleaks dir <repo> --report-format json --redact --no-banner`.
  `--redact` guarantees the secret value never leaves gitleaks; the adapter
  **never reads the flagged source line itself**.
- `snippet_redacted` is gitleaks' already-redacted `Match` (`"REDACTED"`).
- Severity: `high` by default, `critical` for `private-key` / AWS / GCP rules.
- `dedup_key = secret::{gitleaks Fingerprint}` (`file:rule:line`).

## OSV-Scanner adapter

- Invoked as `osv-scanner scan source --recursive --format json <repo>`.
- OSV reports at **package** granularity with **no line number**. The adapter
  resolves each package's declaration line in its manifest (`resolve_manifest_line`)
  so every finding still carries a real `file:line` (invariant 1). If the package
  is not textually locatable, it falls back to line 1 of the manifest — still a
  genuine location (the manifest is the evidence).
- Findings are **aggregated per package**, not per CVE — a package with 8 CVEs is
  one finding (accuracy over breadth; avoids a CVE flood), with the advisory
  count and CVE ids in `raw_message`.
- Severity from the max CVSS across the package's advisory groups.
- `dedup_key = dep::{ecosystem}::{package}::{manifest}`.

## SkillSpector adapter — the containment rule

**Empirical basis (verified by execution 2026-07-02):** SkillSpector is an
*install-vetting* scanner for agent skills. Run raw against an application
codebase (`langchain-ai/open_deep_research`) it produced **86 findings** and a
blanket `CRITICAL / DO_NOT_INSTALL` verdict — a false-positive flood that would
violate the accuracy-over-breadth rule on day one. The flood is dominated by
`Memory Poisoning` (Context-Window-Stuffing) heuristics, `Prompt Injection`
(Hidden-Instructions on notebooks), `Excessive Agency`, and unpinned-reference
noise — none of which is a real vulnerability in application code.

The adapter contains it with four rules:

1. **Deterministic only.** Always invoked with `--no-llm` (no model in Phase 0).

2. **Filter by category class.** Two modes, chosen from the fingerprint:
   - **App-code mode** (the default): keep **only** dangerous-code / exfil /
     secrets classes — SkillSpector's own category labels
     `{Dangerous Code Execution, Data Exfiltration, Data Flow, Privilege Escalation}`
     (`Data Flow` is its taint-tracking class) — and drop everything else
     (`Memory Poisoning`, `Prompt Injection`, `Excessive Agency`, `MCP Rug Pull`,
     `YARA Match`, `Tool Misuse`, `MCP Least Privilege`, …).
   - **Skill-artifact mode** — entered **only** when the repo actually contains a
     skill/MCP artifact bundle (a `SKILL.md`, or an `mcp.json` config file), which
     is SkillSpector's install-vetting home turf. Keeps the strict set **plus** the
     two attack classes that matter for an installable skill —
     `{Prompt Injection, MCP Tool Poisoning}`. A repo that merely *references* an
     MCP server (a command string in a doc or notebook) is app code, not an
     artifact bundle, and gets the strict filter.
   - The low-signal framing heuristics (`Excessive Agency` / Scope Creep,
     `Rogue Agent` / Session Persistence, `Output Handling`, `Tool Misuse`,
     `MCP Rug Pull`, `YARA Match`) are dropped in **both** modes — they flood
     legal, schema, and doc files with false positives.
   - **Non-reviewable files are excluded** in both modes: SkillSpector findings on
     legal text (`LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES`, …) and pure
     data/schema files (`.xsd`, `.svg`, `.csv`, `.lock`) are never real security
     findings and are dropped.
   - A confidence floor of `0.5` drops low-confidence heuristic noise in either
     mode.

3. **Never surface the install verdict.** SkillSpector's `risk_assessment`
   (score / severity / `DO_NOT_INSTALL`) is read by nothing in the adapter.
   Runworthy's verdict comes from the AFR grade alone.

4. **Route SC4 to the dependency path.** SkillSpector's `Supply Chain` (SC4)
   findings are vulnerable-dependency findings; they are emitted with
   `dedup_key = dep::{ecosystem}::{package}::{manifest}` and AFR-10, so they
   **merge with OSV** instead of double-reporting (see below).

`dedup_key` for kept code findings: `code::{rule_id}::{file}::{line}`.

### Result on the graded repo

On `langchain-ai/open_deep_research` (commit `408da44`), SkillSpector raw emits
**86** findings with a blanket `CRITICAL / DO_NOT_INSTALL` verdict, dominated by:

| Raw category | Count | Kept? |
|---|---|---|
| Memory Poisoning | 40 | dropped |
| Supply Chain (SC4) | 16 | → dependency dedup path (AFR-10) |
| Prompt Injection | 9 | dropped |
| MCP Rug Pull | 5 | dropped |
| Data Exfiltration | 5 | **kept** |
| Privilege Escalation | 4 | **kept** |
| Excessive Agency | 3 | dropped |
| Dangerous Code Execution | 2 | **kept** |
| Data Flow (taint) | 1 | **kept** |
| YARA Match | 1 | dropped |

Runworthy emits **11 SkillSpector code findings** (down from 86) — every one a
dangerous-code / exfil / secrets pattern at a real `file:line` (e.g. a critical
tainted-credential-flow at `src/legacy/utils.py:328`, env-var harvesting at
`src/security/auth.py:9`, credential access at `tests/run_evaluate.py:9`). The
16 SC4 dependency findings route to the dependency path; none of the
memory-poisoning / prompt-injection / rug-pull / YARA noise survives. See
`examples/open_deep_research.json` for the committed scan.

## Dedup & merge (invariant 4)

Findings are keyed on a detector-agnostic `dedup_key`:

- dependency findings → `dep::{ecosystem}::{package}::{manifest}`
- code findings → `code::{rule_class}::{file}::{line}`
- secret findings → `secret::{fingerprint}`

When two detectors produce the same key — e.g. OSV and SkillSpector-SC4 both see
the same vulnerable dependency — they **merge into one finding that lists both
detectors** (`detector` = the authoritative one, `also_reported_by` = the
corroborators), taking the max severity and the union of AFR controls.

## Redaction invariant (invariant 2)

`snippet_redacted` never contains a secret value. gitleaks redacts its own
output; every other snippet passes through `redact.mask_secrets()` (AWS / GitHub
/ Slack / Google / private-key / JWT / generic-assignment patterns) before
emission. The test-suite asserts that no planted fixture secret appears anywhere
in the emitted JSON.
