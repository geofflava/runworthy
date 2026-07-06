"""File classification shared by the detectors and the grade guard.

A secret match in a template, example, or docs file is not a committed
credential — it's a placeholder. Both the gitleaks adapter (to cap confidence at
source) and the interpretation layer's Boldface-confirmation guard (defense in
depth) consult the same rule so they can't disagree about what counts as a real
finding.
"""

from __future__ import annotations

_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".md")
_TEMPLATE_DIR_PREFIXES = ("test", "fixture", "example", "sample", "doc")


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
