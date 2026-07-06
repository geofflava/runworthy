"""The model layer — structured-output calls, a token budget, and a
replay/record cache that makes the interpretation layer testable offline.

Nothing here is imported by the deterministic Phase-0 engine; ``--no-llm`` never
touches it, so the core stays dependency-light and fully offline.
"""

from __future__ import annotations

from .client import (
    BudgetExceeded,
    CassetteMiss,
    FileResponseStore,
    ModelUnavailable,
    StructuredModel,
    TokenBudget,
)

__all__ = [
    "BudgetExceeded",
    "CassetteMiss",
    "FileResponseStore",
    "ModelUnavailable",
    "StructuredModel",
    "TokenBudget",
]
