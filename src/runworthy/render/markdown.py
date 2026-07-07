"""The Markdown report renderer (spec build item 3).

Reads only the self-contained ReadinessReport. Renders: the verdict + band header
with a provenance line, the full ten-gate Boldface panel (always all ten), the
interpreted assessments as cards grouped by confidence tier, what's in place, a
"couldn't determine" section, and the disclaimer + AFR version + CC BY footer.

Prose here is chrome; the per-item explanations come from the (voice-gated)
translate node. Chrome stays plain: sentence case, no jargon, findings-and-gaps
language — never "certified secure."
"""

from __future__ import annotations

import re

from ..afr import control_status
from ..afr_catalog import CONTROLS, boldface_controls
from ..models import (
    BOLDFACE,
    AFR_CONTROLS,
    Confidence,
    Finding,
    PostureItem,
    PostureStatus,
    ReadinessReport,
    Severity,
    Verdict,
)

AFR_VERSION = "v0.2.0"
AFR_REPO = "https://github.com/geofflava/agent-flight-rules"

_SEV_RANK = {
    Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0,
}


# --- helpers -----------------------------------------------------------------


def _github_slug(target_ref: str) -> str | None:
    m = re.match(r"^https?://github\.com/([^/]+/[^/#?]+?)(?:\.git)?/?$", target_ref.strip())
    if m:
        return m.group(1)
    if re.match(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", target_ref.strip()):
        return target_ref.strip()
    return None


def _evidence_link(f: Finding, slug: str | None, sha: str | None) -> str:
    loc = f"{f.file}:{f.line}"
    if slug and sha:
        return f"[{loc}](https://github.com/{slug}/blob/{sha}/{f.file}#L{f.line}) · {f.detector}"
    return f"`{loc}` · {f.detector}"


def _tier_label(p: PostureItem) -> str:
    if p.status is PostureStatus.PASS:
        return "In place"
    if p.status is PostureStatus.GAP:
        return "Confirmed"
    if p.confidence is Confidence.MEDIUM:
        return "Likely gap — verify"
    return "Couldn't determine"


def _item_severity(p: PostureItem, by_id: dict[str, Finding]) -> Severity | None:
    sevs = [by_id[e].severity for e in p.evidence if e in by_id]
    if not sevs:
        return None
    return max(sevs, key=lambda s: _SEV_RANK[s])


def _panel_symbol(status: PostureStatus) -> str:
    return {PostureStatus.PASS: "✓ in place", PostureStatus.GAP: "✕ gap", PostureStatus.UNKNOWN: "? not assessed"}[status]


def _verdict_line(report: ReadinessReport) -> str:
    v = report.verdict
    label = {Verdict.GO: "GO", Verdict.NO_GO: "NO-GO", Verdict.PROVISIONAL: "PROVISIONAL"}[v]
    if report.band:
        band = f"band: **{report.band}**"
    else:
        band = f"provisional band — {report.assessed_controls} of {report.total_controls} controls assessed"
    return f"## Verdict: {label} · {band}"


# --- sections ----------------------------------------------------------------


def _card(p: PostureItem, by_id: dict[str, Finding], slug: str | None, sha: str | None) -> str:
    c = CONTROLS[p.afr_control]
    bits = [_tier_label(p)]
    sev = _item_severity(p, by_id)
    if sev is not None:
        bits.append(f"{sev} severity")
    if p.boldface:
        bits.append("★ Boldface")
    lines = [f"#### {p.afr_control} — {c.title}", "*" + "  ·  ".join(bits) + "*", "", p.plain_explanation]
    if p.fix:
        lines += ["", f"**Fix:** {p.fix}"]
    ev = [_evidence_link(by_id[e], slug, sha) for e in p.evidence if e in by_id]
    if ev:
        lines += ["", "**Evidence:** " + " · ".join(ev)]
    return "\n".join(lines)


def _boldface_panel(report: ReadinessReport) -> str:
    status_by = control_status(report.posture_items)
    rows = ["| Gate | Control | Status |", "|---|---|---|"]
    for c in boldface_controls():
        st = status_by.get(c.id, PostureStatus.UNKNOWN)
        rows.append(f"| {c.id} | {c.title} | {_panel_symbol(st)} |")
    return "\n".join(rows)


def _findings_summary(findings: list[Finding]) -> str:
    if not findings:
        return "_No deterministic findings._"
    by_det: dict[str, int] = {}
    by_sev: dict[Severity, int] = {}
    for f in findings:
        by_det[f.detector] = by_det.get(f.detector, 0) + 1
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    det = ", ".join(f"{k}: {v}" for k, v in sorted(by_det.items()))
    sev = ", ".join(f"{s}: {by_sev[s]}" for s in Severity if s in by_sev)
    return f"{len(findings)} finding(s) — by detector: {det}. By severity: {sev}."


# --- top level ---------------------------------------------------------------


def render_markdown(report: ReadinessReport) -> str:
    slug = _github_slug(report.target_ref)
    sha = report.commit_sha
    by_id = {f.finding_id: f for f in report.findings}

    confirmed = [p for p in report.posture_items if p.status is PostureStatus.GAP]
    likely = [p for p in report.posture_items if p.status is PostureStatus.UNKNOWN and p.confidence is Confidence.MEDIUM]
    positives = [p for p in report.posture_items if p.status is PostureStatus.PASS]

    out: list[str] = []
    out.append(f"# Runworthy report — {report.target_ref}")
    out.append("")
    out.append(_verdict_line(report))

    # provenance line — receipts, not assertions
    det = ", ".join(f"{k} {v}" for k, v in sorted(report.detector_versions.items())) or "none"
    prov = (
        f"commit `{sha or 'local (uncommitted)'}` · scanned {report.generated_at} · "
        f"runworthy {report.engine_version} · detectors: {det}"
    )
    out += ["", prov]

    fw = ", ".join(report.agent_map.frameworks) or "none detected"
    out += ["", f"**Agent surface:** {fw}. {_findings_summary(report.findings)}"]

    out += ["", "## The Boldface — the ten non-negotiables", "", _boldface_panel(report)]

    if confirmed:
        out += ["", "## Confirmed gaps", "", "_Grounded in a specific finding. Fix these first._"]
        out += ["", *[_card(p, by_id, slug, sha) for p in confirmed]]

    if likely:
        out += ["", "## Likely gaps — verify", "",
                "_Inferred from the code: the risk is there and the control isn't visible. Confirm before you rely on it._"]
        out += ["", *[_card(p, by_id, slug, sha) for p in likely]]

    if positives:
        out += ["", "## What's in place", ""]
        for p in positives:
            out.append(f"- **{p.afr_control} {CONTROLS[p.afr_control].title}** — {p.plain_explanation}")

    couldnt = _couldnt_determine(report)
    if couldnt:
        out += ["", "## Couldn't determine — here's how to check", "",
                "_The scan can't see these from code. They hold the verdict at PROVISIONAL until you answer._", ""]
        out += couldnt

    if report.notes:
        out += ["", "## Notes", ""]
        out += [f"- {n}" for n in report.notes]

    out += ["", "---", "", _footer()]
    return "\n".join(out) + "\n"


def _couldnt_determine(report: ReadinessReport) -> list[str]:
    """Low-confidence items plus any Boldface with no assessment at all. The
    Boldface gates each keep their plain question — they hold the verdict — but
    supporting controls compress to a single line, so ten gates don't drown in a
    wall of twenty-nine bullets. Excludes controls already shown as confirmed
    gaps, likely gaps, or positives, so nothing is listed twice."""
    addressed: set[str] = set()
    low_controls: set[str] = set()
    for p in report.posture_items:
        if p.status in (PostureStatus.PASS, PostureStatus.GAP):
            addressed.add(p.afr_control)
        elif p.confidence is Confidence.MEDIUM:  # likely gap — shown as a card
            addressed.add(p.afr_control)
        else:  # low-confidence unknown — belongs here
            low_controls.add(p.afr_control)

    gates: list[str] = []
    supporting: list[str] = []
    for c in AFR_CONTROLS:
        is_low = c in low_controls
        # a Boldface control with no assessment at all still owes the reader a question
        is_unassessed_boldface = c in BOLDFACE and c not in addressed and c not in low_controls
        if not (is_low or is_unassessed_boldface):
            continue
        ctl = CONTROLS[c]
        if ctl.boldface:
            gates.append(f"- **{c} {ctl.title} ★** — {ctl.question}")
        else:
            supporting.append(f"{c} {ctl.title}")

    shown = gates
    if supporting:
        if shown:
            shown.append("")
        n = len(supporting)
        plural = "s" if n != 1 else ""
        shown.append(
            f"Plus {n} supporting control{plural} the scan can't read from code — "
            "the operational overlay walks through them: " + " · ".join(supporting) + "."
        )
    return shown


def _footer() -> str:
    return (
        f"This is a Runworthy scan against the Agent Flight Rules ([AFR {AFR_VERSION}]({AFR_REPO})), "
        "CC BY 4.0. It reports findings and gaps from static analysis and your answers — it is not a "
        "certification that your agents are secure, and it can't see how they behave at runtime. "
        'Verify anything marked "likely" or "couldn\'t determine" before you rely on it.'
    )
