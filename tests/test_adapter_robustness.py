"""Adapter plumbing robustness (regressions from the adversarial review)."""

from __future__ import annotations

from runworthy.adapters.base import run_tool


def test_run_tool_missing_binary_is_nonfatal():
    """A detector that can't launch degrades to an empty result, never a crash."""
    result = run_tool(["this_binary_does_not_exist_rw_xyz", "--version"], timeout=5)
    assert result.returncode != 0
    assert result.stdout == ""
