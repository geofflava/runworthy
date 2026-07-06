"""SkillSpector adapter — contained per spec §3.

SkillSpector is an *install-vetting* scanner for agent skills. Run raw against
an application codebase it floods (86 findings + a blanket CRITICAL/DO_NOT_INSTALL
verdict on a well-known public LangGraph repo — verified 2026-07-02). The adapter
therefore:
  (a) runs SkillSpector deterministically (``--no-llm``);
  (b) on app code, keeps only dangerous-code / exfil / secrets classes and drops
      skill-framing + blanket memory-poisoning heuristics (containment filter);
  (c) never surfaces SkillSpector's ``risk_assessment`` (score / DO_NOT_INSTALL);
  (d) routes SC4 (vulnerable dependency) findings to the dependency dedup path so
      they merge with OSV instead of double-reporting.

The full filter rule is documented in ``docs/adapters.md``.
"""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from ..models import Confidence, Finding
from ..normalize import code_dedup_key, dep_dedup_key, ecosystem_for
from ..redact import mask_secrets
from .base import (
    AdapterContext,
    ToolUnavailable,
    conf_from_float,
    rel_posix,
    resolve_exe,
    run_tool,
    sev_from_str,
)

DETECTOR = "skillspector"
AFR_CODE = ["AFR-08", "AFR-09"]  # mechanical detector mapping (spec §3 table)
AFR_DEP = ["AFR-10"]  # SC4 aligns with OSV so merges are coherent

# App-code KEEP set: dangerous-code / exfil / secrets only. Category strings are
# SkillSpector's own labels (verified against its output): "Data Flow" is its
# taint-tracking class; "Privilege Escalation" (PE*) is its credential-access class.
KEEP_APP_CODE = frozenset(
    {"Dangerous Code Execution", "Data Exfiltration", "Data Flow", "Privilege Escalation"}
)

# Skill-artifact KEEP set: the strict app set PLUS the attack classes that
# actually matter when vetting an installable skill — prompt injection and MCP
# tool poisoning. The low-signal framing heuristics (Excessive Agency / Scope
# Creep, Rogue Agent / Session Persistence, Output Handling, Tool Misuse, MCP Rug
# Pull, YARA) are dropped in *both* modes — they flood legal/schema/doc files.
KEEP_SKILL = KEEP_APP_CODE | frozenset({"Prompt Injection", "MCP Tool Poisoning"})

# Actual skill/MCP artifact files (not mere references) that make a repo
# SkillSpector's home turf and warrant the skill-mode filter.
_MCP_ARTIFACT_NAMES = frozenset({"mcp.json", ".mcp.json", "claude_desktop_config.json"})
# Always dropped, in either mode: the blanket memory-poisoning heuristic that
# fires on any large string and produced ~40 of the 86-finding flood.
DROP_ALWAYS = frozenset({"Memory Poisoning"})
# Never surfaced under any circumstance (containment rule c).
SUPPLY_CHAIN = "Supply Chain"

CONFIDENCE_FLOOR = 0.5  # drop low-confidence heuristic noise (e.g. the 0.15 hits)

# Files SkillSpector scans but which never carry a real security finding — legal
# text and pure data/schema files. Its heuristics (Scope Creep on a LICENSE,
# Session Persistence on an .xsd) fire on these as pure false positives.
_NONREVIEWABLE_STEMS = (
    "license", "licence", "notice", "copying", "authors", "changelog",
    "contributing", "code_of_conduct", "third_party", "third-party", "codeowners",
)
_NONREVIEWABLE_EXTS = frozenset({".xsd", ".svg", ".csv", ".tsv", ".lock"})


def _is_reviewable(file: str) -> bool:
    name = Path(file).name.lower()
    if any(stem in name for stem in _NONREVIEWABLE_STEMS):
        return False
    return Path(file).suffix.lower() not in _NONREVIEWABLE_EXTS

_PKG_SPLIT = re.compile(r"[<>=!~;\[\s]")
_PKG_FROM_PATTERN = re.compile(r"Dependency:?\s+([A-Za-z0-9._-]+)")


def _mode(ctx: AdapterContext) -> str:
    """Skill-artifact mode only when the repo actually *contains* a skill/MCP
    artifact bundle (a SKILL.md, or an mcp.json/config file) — SkillSpector's
    install-vetting home turf. An application that merely *references* an MCP
    server (a command string in a doc or notebook) is app code and gets the
    strict containment filter."""
    if ctx.agent_map.skills:
        return "skill"
    if any(Path(f).name.lower() in _MCP_ARTIFACT_NAMES for f in ctx.target.file_tree):
        return "skill"
    return "app"


def _keep_code(category: str, mode: str) -> bool:
    if category in DROP_ALWAYS:
        return False
    return category in (KEEP_APP_CODE if mode == "app" else KEEP_SKILL)


def _package_name(issue: dict) -> str | None:
    finding = (issue.get("finding") or "").strip()
    if finding:
        head = _PKG_SPLIT.split(finding)[0]
        if head:
            return head
    m = _PKG_FROM_PATTERN.search(issue.get("pattern") or "")
    return m.group(1) if m else None


def run(ctx: AdapterContext) -> list[Finding]:
    try:
        exe = resolve_exe("skillspector")
    except ToolUnavailable:
        return []
    version = ctx.versions.get(DETECTOR, "unknown")

    with tempfile.TemporaryDirectory(prefix="rw-skillspector-") as td:
        out_file = Path(td) / "skillspector.json"  # outside the repo — never rescanned
        proc = run_tool(
            [exe, "scan", str(ctx.root), "--no-llm", "--format", "json", "--output", str(out_file)],
            timeout=300,
        )
        if not out_file.exists():
            return []
        try:
            data = json.loads(out_file.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            return []
    _ = proc  # returncode intentionally ignored (nonzero == issues found)
    if not isinstance(data, dict):
        return []

    mode = _mode(ctx)
    findings: list[Finding] = []
    for issue in data.get("issues", []) or []:  # NB: risk_assessment deliberately untouched
        category = issue.get("category", "")
        rid = issue.get("id", "?")
        loc = issue.get("location", {}) or {}
        file = rel_posix(loc.get("file", ""), ctx.root)
        line = int(loc.get("start_line", 0) or 0)
        if not file or line < 1:
            continue

        if category == SUPPLY_CHAIN:
            pkg = _package_name(issue)
            if not pkg:
                continue
            ecosystem = ecosystem_for(file)
            findings.append(
                Finding(
                    finding_id="",
                    detector=DETECTOR,
                    detector_version=version,
                    afr_controls=list(AFR_DEP),
                    severity=sev_from_str(issue.get("severity")),
                    confidence=Confidence.HIGH,
                    file=file,
                    line=line,
                    # mask BEFORE truncating so a split secret can't slip through
                    snippet_redacted=(mask_secrets(issue.get("finding")) or pkg)[:120],
                    raw_message=f"Vulnerable dependency {pkg} (via SkillSpector SC4)",
                    dedup_key=dep_dedup_key(ecosystem, pkg, file),
                )
            )
            continue

        if not _keep_code(category, mode):
            continue
        if not _is_reviewable(file):  # legal/schema/data files carry no real code finding
            continue
        conf = issue.get("confidence")
        if isinstance(conf, (int, float)) and conf < CONFIDENCE_FLOOR:
            continue

        pattern = issue.get("pattern") or category
        findings.append(
            Finding(
                finding_id="",
                detector=DETECTOR,
                detector_version=version,
                afr_controls=list(AFR_CODE),
                severity=sev_from_str(issue.get("severity")),
                confidence=conf_from_float(conf if isinstance(conf, (int, float)) else None),
                file=file,
                line=line,
                # mask BEFORE truncating (a private-key block split at 200 chars
                # would otherwise miss the BEGIN/END pattern and leak key bytes)
                snippet_redacted=(mask_secrets(issue.get("finding")) or "")[:200] or None,
                raw_message=f"{rid} {pattern}",
                dedup_key=code_dedup_key(rid, file, line),
            )
        )
    return findings
