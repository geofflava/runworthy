"""Redaction guard — the contract's non-negotiable invariant.

Secret *values* never appear in any emitted artifact or model input (spec §4).
gitleaks already redacts its own output (``--redact``); this module is
defense-in-depth for every other snippet that could carry a hardcoded secret
(e.g. a SkillSpector code snippet on a credential file).
"""

from __future__ import annotations

import re

_PLACEHOLDER = "[REDACTED]"

# Secret-shaped patterns (a pragmatic subset of common gitleaks rules). Order
# matters only for readability; all are applied.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"-----BEGIN[ A-Z]*PRIVATE KEY-----[\s\S]*?-----END[ A-Z]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bA3T[A-Z0-9]{13,}\b"),  # AWS (other prefixes)
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"),  # GitHub tokens
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b"),
    re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),  # Slack
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),  # Google API key
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),  # OpenAI-style
    re.compile(r"\bsk_live_[A-Za-z0-9]{16,}\b"),  # Stripe
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),  # JWT
    # connection string / DSN with inline credentials: scheme://user:password@host
    re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s:/@]+@", re.IGNORECASE),
    # generic: assignment of a long opaque value to a secret-named key
    re.compile(
        r"""(?ix)
        \b(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|
            client[_-]?secret|private[_-]?key|auth)\b
        \s*[:=]\s*
        ['"]?[A-Za-z0-9/+=_\-]{16,}['"]?
        """
    ),
)


def mask_secrets(text: str | None) -> str | None:
    """Replace any secret-shaped substring with a placeholder. Idempotent."""
    if not text:
        return text
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub(_PLACEHOLDER, out)
    return out


def contains_secret(text: str | None) -> bool:
    """True if any secret-shaped substring is present (used by the invariant test)."""
    if not text:
        return False
    return any(pat.search(text) for pat in _SECRET_PATTERNS)
