"""The AFR control catalog — reference data for AFR v0.2.0 (29 controls).

The canonical prose lives in ``docs/agent-flight-rules.md`` (published at
``geofflava/agent-flight-rules``). This module is the machine-readable index the
engine needs: titles, domains, the Boldface flag, and — for the two things the
renderer and the operational overlay require — a plain-language ``question`` (what
to ask the operator when code can't show the control) and a ``check`` line (how a
non-expert verifies it themselves).

Kept deliberately terse. It is an index into the framework, not a second copy of
it; if a control's meaning changes, change the framework doc first, then this.
"""

from __future__ import annotations

from dataclasses import dataclass

from .models import BOLDFACE


@dataclass(frozen=True)
class Control:
    id: str
    title: str
    domain: str
    boldface: bool
    #: Plain, non-expert question — asked in the CLI overlay for a Boldface
    #: control the scan couldn't ground, and shown in the "couldn't determine"
    #: section as "here's how to check."
    question: str


_DOMAINS = {
    1: "Inventory & Ownership",
    2: "Least Privilege, Access & Supply Chain",
    3: "Authorization & Dual Control",
    4: "Monitoring & Audit Trail",
    5: "Containment & Kill-Switch",
    6: "Change Control, Incident Response & Review",
}

# (id_num, title, domain_num, question). ★ Boldface is derived from models.BOLDFACE
# so the two never drift.
_ROWS: tuple[tuple[int, str, int, str], ...] = (
    (1, "Agent registry with a named owner", 1,
     "Do you keep a list of every agent you run in production, and does each one have a single named owner?"),
    (2, "Blast-radius record", 1,
     "For each agent, have you written down what it can do, what data it can reach, and how much it can spend?"),
    (3, "Decommissioning", 1,
     "When an agent is no longer needed, do you retire it and revoke its access?"),
    (4, "Minimum scope", 2,
     "Does each agent have access only to the tools and data its job needs, and nothing extra 'just in case'?"),
    (5, "Per-agent credentials", 2,
     "Does each agent use its own revocable credentials rather than a shared or master key?"),
    (6, "No standing production secrets", 2,
     "Do agent tokens for production expire in hours rather than months?"),
    (7, "Sandbox by default", 2,
     "Can a brand-new or untrusted agent reach production data or spend money without a deliberate promotion step?"),
    (8, "Treat all input as untrusted", 2,
     "Do an agent's privileges come only from your configuration, never from content it reads (web pages, emails, other agents)?"),
    (9, "Vet before you connect", 2,
     "Before you connect a tool, skill, or MCP server, do you review what it does and pin it to a version?"),
    (10, "Scan the agent stack", 2,
     "Do you scan the agent's code and dependencies for known vulnerabilities and leaked secrets on a schedule?"),
    (11, "Consequence classification", 3,
     "Have you labeled each action an agent can take as low, high, or critical consequence?"),
    (12, "Approval gate on High", 3,
     "Do high-consequence actions wait for a human to approve them before they run?"),
    (13, "Dual control on Critical", 3,
     "Do the rare, irreversible actions need two people, or a hard limit the agent can't cross alone?"),
    (14, "Default-deny on unclassified", 3,
     "If an action hasn't been classified, is the agent blocked from taking it?"),
    (15, "Hard spending limits", 3,
     "Are spending caps enforced at the tool or payment provider, not just written into the prompt?"),
    (16, "Action log", 4,
     "Do you record every agent action (what triggered it, what it did, and the result) in a log you can replay?"),
    (17, "Anomaly alerts", 4,
     "Does something alert a human in real time when an agent does something unusual (odd spend, new connector, off-hours)?"),
    (18, "Live visibility", 4,
     "Can someone answer 'what are our agents doing right now?' without grepping raw logs?"),
    (19, "Retention", 4,
     "Do you keep logs long enough to investigate an incident discovered weeks later?"),
    (20, "Kill-switch", 5,
     "Do you have a tested way to stop any agent (or all of them at once) right now, and have you tried it recently?"),
    (21, "Circuit breakers", 5,
     "Does an agent automatically pause when it crosses a threshold (spend, error rate), before a human reacts?"),
    (22, "Blast-radius limits", 5,
     "Are there per-agent rate limits and segmentation so one compromised agent can't reach everything?"),
    (23, "Memory hygiene", 5,
     "Can you point to each agent's memory store, expire what it stores, and wipe it on demand?"),
    (24, "Rollback plan", 5,
     "For each high-consequence action, do you know how to undo it?"),
    (25, "Incident runbook", 6,
     "Is there a one-page written plan for when an agent goes wrong (who's notified, how to contain, who decides), and can the team find it?"),
    (26, "Severity levels", 6,
     "Have you defined what counts as a Sev1 / Sev2 / Sev3 incident?"),
    (27, "Test changes before they ship", 6,
     "Do prompt, model, and tool changes run against a fixed set of checks (including an injection probe) before deploy?"),
    (28, "Blameless post-incident review", 6,
     "After an incident or near-miss, do you write up what happened and which control gets added or tightened?"),
    (29, "Continuous review", 6,
     "Do you re-run this assessment on a schedule and after every incident?"),
)


def _control(num: int, title: str, domain_num: int, question: str) -> Control:
    cid = f"AFR-{num:02d}"
    return Control(
        id=cid,
        title=title,
        domain=_DOMAINS[domain_num],
        boldface=cid in BOLDFACE,
        question=question,
    )


#: Every AFR control, indexed by id, in canonical order.
CONTROLS: dict[str, Control] = {
    f"AFR-{num:02d}": _control(num, title, dom, q) for (num, title, dom, q) in _ROWS
}


def control(afr_id: str) -> Control:
    """Look up a control by id (e.g. ``"AFR-12"``). Raises KeyError if unknown."""
    return CONTROLS[afr_id]


def boldface_controls() -> list[Control]:
    """The ten Boldface controls, in canonical order."""
    return [c for c in CONTROLS.values() if c.boldface]
