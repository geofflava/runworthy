# Runworthy report — langchain-ai/open_deep_research

## Verdict: PROVISIONAL · provisional band — 1 of 29 controls assessed

commit `408da442a661ea5e40a6163329f82e3f22628949` · scanned 2026-07-06T01:28:12Z · runworthy 0.1.0 · detectors: gitleaks 8.30.1, osv-scanner 2.4.0, skillspector 2.3.9

**Agent surface:** Anthropic SDK, LangChain, LangGraph, MCP. 33 finding(s) — by detector: gitleaks: 1, osv-scanner: 5, skillspector: 27. By severity: critical: 5, high: 11, medium: 8, low: 8, info: 1.

## The Boldface — the ten non-negotiables

| Gate | Control | Status |
|---|---|---|
| AFR-01 | Agent registry with a named owner | ? not assessed |
| AFR-04 | Minimum scope | ? not assessed |
| AFR-05 | Per-agent credentials | ? not assessed |
| AFR-09 | Vet before you connect | ? not assessed |
| AFR-11 | Consequence classification | ? not assessed |
| AFR-12 | Approval gate on High | ? not assessed |
| AFR-16 | Action log | ? not assessed |
| AFR-17 | Anomaly alerts | ? not assessed |
| AFR-20 | Kill-switch | ? not assessed |
| AFR-25 | Incident runbook | ? not assessed |

## Confirmed gaps

_Grounded in a specific finding. Fix these first._

#### AFR-10 — Scan the agent stack
*Confirmed  ·  critical severity*

This checks whether the software components your agents depend on are scanned for known security holes. The scan found real, currently known vulnerabilities in four dependencies: langgraph (pyproject.toml:12), langchain-community (pyproject.toml:13), langchain-openai (pyproject.toml:14), and requests (pyproject.toml:28).

**Fix:** Update these four packages to their latest patched versions and re-run the scan to confirm the vulnerabilities are gone. Set up automatic dependency scanning going forward so new issues are caught early.

**Evidence:** [pyproject.toml:12](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/pyproject.toml#L12) · skillspector · [pyproject.toml:13](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/pyproject.toml#L13) · skillspector · [pyproject.toml:14](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/pyproject.toml#L14) · skillspector · [pyproject.toml:28](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/pyproject.toml#L28) · skillspector

## Likely gaps — verify

_Inferred from the code: the risk is there and the control isn't visible. Confirm before you rely on it._

#### AFR-08 — Treat all input as untrusted
*Likely gap — verify  ·  critical severity*

This checks whether the system treats external input (like user text or API responses) as potentially unsafe before acting on it. Several code patterns were found that move data from environment variables and credentials into outgoing network requests, for example src/legacy/utils.py:328 and src/legacy/utils.py:944, which are worth a closer look, though they don't prove input handling is unsafe.

**Fix:** Have someone review the flow from src/legacy/utils.py:305 through line 329 to confirm sensitive data isn't sent out based on untrusted input. Add input validation there if it's missing.

**Evidence:** [langgraph.json:7](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/langgraph.json#L7) · skillspector · [src/legacy/utils.py:414](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L414) · skillspector · [src/legacy/utils.py:328](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L328) · skillspector · [src/legacy/utils.py:328](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L328) · skillspector · [src/legacy/utils.py:329](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L329) · skillspector · [src/legacy/utils.py:944](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L944) · skillspector · [src/legacy/utils.py:454](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L454) · skillspector
#### AFR-09 — Vet before you connect
*Likely gap — verify  ·  high severity  ·  ★ Boldface*

This checks whether you vet a tool or server before letting an agent connect to it. Findings showing credential access at langgraph.json:7 and src/legacy/utils.py:414 hint that agents connect to external services, but there's no evidence about whether those connections were vetted first.

**Fix:** List the external tools and servers your agents connect to and confirm each was reviewed before being added. Document that review for future connections.

**Evidence:** [langgraph.json:7](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/langgraph.json#L7) · skillspector · [src/legacy/utils.py:414](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L414) · skillspector

## Couldn't determine — here's how to check

_The scan can't see these from code. They hold the verdict at PROVISIONAL until you answer._

- **AFR-01 Agent registry with a named owner ★** — Do you keep a list of every agent you run in production, and does each one have a single named owner?
- **AFR-04 Minimum scope ★** — Does each agent have access only to the tools and data its job needs, and nothing extra 'just in case'?
- **AFR-05 Per-agent credentials ★** — Does each agent use its own revocable credentials rather than a shared or master key?
- **AFR-11 Consequence classification ★** — Have you labeled each action an agent can take as low, high, or critical consequence?
- **AFR-12 Approval gate on High ★** — Do high-consequence actions wait for a human to approve them before they run?
- **AFR-16 Action log ★** — Do you record every agent action (what triggered it, what it did, and the result) in a log you can replay?
- **AFR-17 Anomaly alerts ★** — Does something alert a human in real time when an agent does something unusual (odd spend, new connector, off-hours)?
- **AFR-20 Kill-switch ★** — Do you have a tested way to stop any agent (or all of them at once) right now, and have you tried it recently?
- **AFR-25 Incident runbook ★** — Is there a one-page written plan for when an agent goes wrong (who's notified, how to contain, who decides), and can the team find it?

Plus 17 supporting controls the scan can't read from code — the operational overlay walks through them: AFR-02 Blast-radius record · AFR-03 Decommissioning · AFR-06 No standing production secrets · AFR-07 Sandbox by default · AFR-13 Dual control on Critical · AFR-14 Default-deny on unclassified · AFR-15 Hard spending limits · AFR-18 Live visibility · AFR-19 Retention · AFR-21 Circuit breakers · AFR-22 Blast-radius limits · AFR-23 Memory hygiene · AFR-24 Rollback plan · AFR-26 Severity levels · AFR-27 Test changes before they ship · AFR-28 Blameless post-incident review · AFR-29 Continuous review.

## Notes

- 2 proposed assessment(s) had template/example-file evidence stripped; those left with no other evidence were downgraded to 'couldn't determine'.
- 16 finding(s) were summarised rather than shown individually to the model (all remain in the report).
- PROVISIONAL: 10 Boldface control(s) not yet assessed — AFR-01, AFR-04, AFR-05, AFR-09, AFR-11, AFR-12, AFR-16, AFR-17, AFR-20, AFR-25. Answer the operational overlay (or run without --non-interactive) to resolve.

---

This is a Runworthy scan against the Agent Flight Rules ([AFR v0.2.0](https://github.com/geofflava/agent-flight-rules)), CC BY 4.0. It reports findings and gaps from static analysis and your answers — it is not a certification that your agents are secure, and it can't see how they behave at runtime. Verify anything marked "likely" or "couldn't determine" before you rely on it.
