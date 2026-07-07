"""File classification and evidence-class rules shared across the engine.

Two pure predicates the whole pipeline agrees on:

- ``is_template_path`` — a secret match in a template/example/docs file is a
  placeholder, not a committed credential. Both the gitleaks adapter (to cap
  confidence at source) and the interpretation layer consult it so they can't
  disagree about what counts as a real finding.
- ``is_direct_evidence`` — whether a finding, by itself, demonstrates a control
  *state* (**direct**), or merely that a risky *mechanism* exists (**pattern**).
  The interpretation layer's confirmed-gap guard uses it: only direct-class
  evidence may confirm a gap. This is VF-1's lesson generalized — SkillSpector's
  ``high`` means "high confidence the pattern exists", not "high confidence the
  control is absent", so a working agent that reads an env var and calls an API
  must not NO-GO on that pattern alone.
"""

from __future__ import annotations

from .models import Confidence

_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".md")
_TEMPLATE_DIR_PREFIXES = ("test", "fixture", "example", "sample", "doc")

#: The dependency route (spec §3 → AFR-10). We key the direct-evidence test on the
#: AFR mapping rather than the detector so that OSV matches *and* SkillSpector SC4
#: dependency findings — which dedup-merge onto the same path and can blur the
#: ``detector`` field — are treated identically.
_OSV_ROUTE = ("AFR-10",)


def is_template_path(path: str) -> bool:
    """True for template/example/docs paths where a 'secret' is almost certainly a
    placeholder: ``*.example`` / ``*.sample`` / ``*.template`` / ``*.dist`` /
    ``*.md``, any path containing ``example`` or ``sample``, or a component under a
    ``test*`` / ``fixture*`` / ``example*`` / ``doc*`` directory."""
    p = path.replace("\\", "/").lower()
    base = p.rsplit("/", 1)[-1]
    if base.endswith(_TEMPLATE_SUFFIXES):
        return True
    if "example" in p or "sample" in p:
        return True
    dirs = p.split("/")[:-1]
    return any(d.startswith(_TEMPLATE_DIR_PREFIXES) for d in dirs)


def is_direct_evidence(finding) -> bool:
    """True when a finding is **direct-class** — by itself it demonstrates a control
    state, so it is allowed to confirm a gap. Two routes:

    - the dependency route: any finding mapped solely to AFR-10 (OSV database
      matches, plus SkillSpector SC4 findings merged onto the same dep path); and
    - a gitleaks secret that survived the VF-1 guard — high confidence in real
      source. A template or low-entropy match is capped ``low``/``info`` at the
      adapter and is pattern-class, not direct.

    Everything else is **pattern-class**: every SkillSpector code-route lead (Data
    Flow, Dangerous Code Execution, Data Exfiltration, Privilege Escalation, and the
    skill-mode categories) shows a mechanism exists, never that a control is absent.
    ``finding`` is duck-typed — it needs ``.afr_controls``, ``.detector``,
    ``.confidence`` and ``.file`` — so this stays a pure predicate over the contract
    without importing it (no ``Finding`` change; spec §4)."""
    if tuple(finding.afr_controls) == _OSV_ROUTE:
        return True
    return (
        finding.detector == "gitleaks"
        and finding.confidence is Confidence.HIGH
        and not is_template_path(finding.file)
    )
