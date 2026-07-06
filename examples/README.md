# Example scans (receipts)

Committed, reproducible `ReadinessReport` outputs from Phase 0 on well-known
public agent repos. Each is a real scan at a pinned commit — regenerate with
`runworthy scan <url> -o examples/<name>.json`. These double as golden material
and as the raw input for the "receipts" content described in the spec (§7),
subject to the disclosure policy in §6 (all three repos are scanning-permissible
public projects; nothing here is a public "shaming" — it's a demonstration of
the engine on their own committed code).

All Phase-0 verdicts are **PROVISIONAL** by design (the AFR grade needs the
Phase 1 interpretation layer). Detector versions: gitleaks 8.30.1,
osv-scanner 2.4.0, SkillSpector 2.3.9.

| Report | Repo @ commit | Findings | Highlights |
|---|---|---|---|
| `open_deep_research.json` | `langchain-ai/open_deep_research` @ `408da44` | **33** (11 SkillSpector code, 21 dep, 1 secret) | The SkillSpector **containment** proof: 86 raw findings (40 memory-poisoning + 9 prompt-injection + rug-pull/scope-creep noise, blanket `DO_NOT_INSTALL`) → **11** defensible dangerous-code/exfil/secrets findings. Real gitleaks hit at `.env.example:1`; critical tainted-credential-flow at `src/legacy/utils.py:328`. |
| `anthropics_skills.json` | `anthropics/skills` @ `9d2f1ae` | **67** (61 SkillSpector code, 6 dep) | SkillSpector on its **home turf** (skill-artifact mode — the repo is full of `SKILL.md` bundles). Real `subprocess`, env-var-harvesting, and external-transmission findings across the skill scripts; legal/schema-file noise dropped. |
| `crewai_examples.json` | `crewAIInc/crewAI-examples` @ `da94a91` | **364** (29 SkillSpector code, 335 dep) | Breadth: fingerprints CrewAI + LangGraph + LangChain + OpenAI Agents SDK across many sub-crews; OSV surfaces 335 real vulnerable-dependency findings from the pinned `uv.lock` files (dep-heavy, all evidence-bound). |

**Invariants visible in every report:** every finding carries `file:line` and a
`dedup_key`; secret values are redacted (`snippet_redacted`); overlapping OSV +
SkillSpector-SC4 dependency findings are merged into one (`also_reported_by`);
`afr_controls[]` come only from the mechanical detector mappings; full provenance
(`commit_sha`, `engine_version`, `detector_versions`).
