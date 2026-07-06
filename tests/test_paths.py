"""Path normalization (regression for the dotfile-stripping bug)."""

from __future__ import annotations

from pathlib import Path

from runworthy.adapters.base import rel_posix

ROOT = Path("/repo")


def test_rel_posix_preserves_dotfiles():
    # the bug: lstrip("./") ate the leading dot, corrupting the cited path
    assert rel_posix(".env.example", ROOT) == ".env.example"
    assert rel_posix(".github/workflows/ci.yml", ROOT) == ".github/workflows/ci.yml"


def test_rel_posix_strips_only_leading_dotslash():
    assert rel_posix("./src/app.py", ROOT) == "src/app.py"
    assert rel_posix("src/app.py", ROOT) == "src/app.py"


def test_rel_posix_normalizes_backslashes():
    assert rel_posix("src\\pkg\\mod.py", ROOT) == "src/pkg/mod.py"
