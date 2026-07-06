"""Shared test fixtures.

Tests split into two tiers:
 - toolless unit/contract tests always run;
 - ``@requires_tools`` integration tests run only when the pinned detector
   binaries are on PATH (they are in CI; locally, put ``.tools/bin`` on PATH).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from runworthy.engine import scan
from runworthy.tools import TOOLS

FIXTURES = Path(__file__).parent / "fixtures"
FIXED_TIME = "2026-07-05T00:00:00Z"  # pin generated_at for reproducible reports

TOOLS_PRESENT = all(shutil.which(t.exe) for t in TOOLS.values())
requires_tools = pytest.mark.skipif(
    not TOOLS_PRESENT, reason="pinned detector tools (gitleaks/osv-scanner/skillspector) not on PATH"
)


@pytest.fixture(scope="session")
def scanned():
    """Memoizing scanner — each fixture repo is scanned at most once per session."""
    cache: dict[str, object] = {}

    def _scan(name: str):
        if name not in cache:
            cache[name] = scan(str(FIXTURES / name), generated_at=FIXED_TIME)
        return cache[name]

    return _scan
