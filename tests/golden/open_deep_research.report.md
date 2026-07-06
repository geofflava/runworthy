# Runworthy report — langchain-ai/open_deep_research

## Verdict: NO-GO · band: **Exposed**

commit `408da442a661ea5e40a6163329f82e3f22628949` · scanned 2026-07-06T01:28:12Z · runworthy 0.1.0 · detectors: gitleaks 8.30.1, osv-scanner 2.4.0, skillspector 2.3.9

**Agent surface:** Anthropic SDK, LangChain, LangGraph, MCP. 33 finding(s) — by detector: gitleaks: 1, osv-scanner: 5, skillspector: 27. By severity: critical: 5, high: 12, medium: 8, low: 8.

## The Boldface — the ten non-negotiables

| Gate | Control | Status |
|---|---|---|
| AFR-01 | Agent registry with a named owner | ? not assessed |
| AFR-04 | Minimum scope | ? not assessed |
| AFR-05 | Per-agent credentials | ✕ gap |
| AFR-09 | Vet before you connect | ? not assessed |
| AFR-11 | Consequence classification | ? not assessed |
| AFR-12 | Approval gate on High | ? not assessed |
| AFR-16 | Action log | ? not assessed |
| AFR-17 | Anomaly alerts | ? not assessed |
| AFR-20 | Kill-switch | ? not assessed |
| AFR-25 | Incident runbook | ? not assessed |

## Confirmed gaps

_Grounded in a specific finding. Fix these first._

#### AFR-05 — Per-agent credentials
*Confirmed  ·  high severity  ·  ★ Boldface*

The scan flags Per-agent credentials (AFR-05) as a gap.

**Fix:** Give each agent its own scoped key from a secret manager, and rotate the one in the repo now in case it is real.

**Evidence:** [.env.example:1](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/.env.example#L1) · gitleaks
#### AFR-10 — Scan the agent stack
*Confirmed  ·  medium severity*

Several pinned dependencies have known security advisories open against them — for example langchain and pygments. Your agent inherits every one of those.

**Fix:** Run a dependency scan on a schedule and upgrade the flagged packages; treat critical advisories as work to close, not noise.

**Evidence:** [uv.lock:1686](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/uv.lock#L1686) · osv-scanner · [uv.lock:1954](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/uv.lock#L1954) · osv-scanner

## Likely gaps — verify

_Inferred from the code: the risk is there and the control isn't visible. Confirm before you rely on it._

#### AFR-08 — Treat all input as untrusted
*Likely gap — verify  ·  critical severity*

At src/legacy/utils.py:328 a value read from the environment flows straight into an outbound web request. If that value is a credential, this is a path for it to leave your systems.

**Fix:** Confirm what is being sent, and make sure an agent's privileges come from your configuration, not from data it reads.

**Evidence:** [src/legacy/utils.py:328](https://github.com/langchain-ai/open_deep_research/blob/408da442a661ea5e40a6163329f82e3f22628949/src/legacy/utils.py#L328) · skillspector

## Couldn't determine — here's how to check

_The scan can't see these from code. They hold the verdict at PROVISIONAL until you answer._

- **AFR-01 Agent registry with a named owner ★** — Do you keep a list of every agent you run in production, and does each one have a single named owner?
- **AFR-04 Minimum scope ★** — Does each agent have access only to the tools and data its job needs, and nothing extra 'just in case'?
- **AFR-09 Vet before you connect ★** — Before you connect a tool, skill, or MCP server, do you review what it does and pin it to a version?
- **AFR-11 Consequence classification ★** — Have you labeled each action an agent can take as low, high, or critical consequence?
- **AFR-12 Approval gate on High ★** — Do high-consequence actions wait for a human to approve them before they run?
- **AFR-16 Action log ★** — Do you record every agent action (what triggered it, what it did, and the result) in a log you can replay?
- **AFR-17 Anomaly alerts ★** — Does something alert a human in real time when an agent does something unusual (odd spend, new connector, off-hours)?
- **AFR-20 Kill-switch ★** — Do you have a tested way to stop any agent (or all of them at once) right now, and have you tried it recently?
- **AFR-25 Incident runbook ★** — Is there a one-page written plan for when an agent goes wrong (who's notified, how to contain, who decides), and can the team find it?

## Notes

- 16 finding(s) were summarised rather than shown individually to the model (all remain in the report).

---

This is a Runworthy scan against the Agent Flight Rules ([AFR v0.2.0](https://github.com/geofflava/agent-flight-rules)), CC BY 4.0. It reports findings and gaps from static analysis and your answers — it is not a certification that your agents are secure, and it can't see how they behave at runtime. Verify anything marked "likely" or "couldn't determine" before you rely on it.
