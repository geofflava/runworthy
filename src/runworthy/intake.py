"""Intake & source resolution (spec §3 [1]).

Resolve a scan target (local path or public repo URL) into a working directory
plus a ``ScanTarget`` (file tree, languages, resolved commit SHA). Remote repos
are **shallow, read-only** clones; repo code is never installed or executed
(static analysis only — this protects *us* from a hostile repo).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .models import ScanTarget, SourceType

# Safety caps (basic Phase-0 zip-bomb / runaway defenses; the hardened sandbox
# is a Phase-2 milestone, spec §7).
MAX_FILES = 60_000
MAX_TREE_BYTES = 2_000_000_000  # 2 GB total working tree
CLONE_TIMEOUT_S = 240

_URL_RE = re.compile(r"^(https?://|git@|ssh://|git://)", re.IGNORECASE)
_SHORTHAND_RE = re.compile(r"^[\w.-]+/[\w.-]+$")  # owner/repo

_IGNORE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".idea",
    ".vscode",
}

_LANG_BY_EXT: dict[str, str] = {
    ".py": "Python",
    ".ipynb": "Jupyter",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".go": "Go",
    ".rs": "Rust",
    ".java": "Java",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++",
    ".c": "C",
    ".sh": "Shell",
    ".md": "Markdown",
    ".json": "JSON",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".toml": "TOML",
}


def is_url(ref: str) -> bool:
    return bool(_URL_RE.match(ref)) or (
        bool(_SHORTHAND_RE.match(ref)) and not Path(ref).exists()
    )


def _normalize_url(ref: str) -> str:
    if _SHORTHAND_RE.match(ref) and not _URL_RE.match(ref):
        return f"https://github.com/{ref}.git"
    return ref


@dataclass
class ScanSource:
    root: Path
    target: ScanTarget


def _git(args: list[str], cwd: Path | None = None, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def _resolve_head(root: Path) -> str | None:
    try:
        r = _git(["rev-parse", "HEAD"], cwd=root)
    except (OSError, subprocess.SubprocessError):
        return None
    sha = r.stdout.strip()
    return sha or None


def _walk_tree(root: Path) -> tuple[list[str], dict[str, int]]:
    """Return (repo-relative POSIX file paths, language -> file count). Capped."""
    files: list[str] = []
    languages: dict[str, int] = {}
    total_bytes = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
        for name in filenames:
            if len(files) >= MAX_FILES or total_bytes >= MAX_TREE_BYTES:
                return files, languages
            full = Path(dirpath) / name
            rel = full.relative_to(root).as_posix()
            files.append(rel)
            try:
                total_bytes += full.stat().st_size
            except OSError:
                pass
            lang = _LANG_BY_EXT.get(full.suffix.lower())
            if lang:
                languages[lang] = languages.get(lang, 0) + 1
    return files, languages


@contextmanager
def open_target(ref: str) -> Iterator[ScanSource]:
    """Yield a :class:`ScanSource` for ``ref``. Remote clones are cleaned up on
    exit; local paths are left untouched."""
    if is_url(ref):
        url = _normalize_url(ref)
        tmp = Path(tempfile.mkdtemp(prefix="runworthy-clone-"))
        clone_dir = tmp / "repo"
        try:
            try:
                r = _git(
                    ["clone", "--depth", "1", "--single-branch", url, str(clone_dir)],
                    timeout=CLONE_TIMEOUT_S,
                )
            except (subprocess.SubprocessError, OSError) as exc:
                raise RuntimeError(f"git clone failed for {url!r}: {exc}") from exc
            if r.returncode != 0:
                raise RuntimeError(f"git clone failed for {url!r}:\n{r.stderr.strip()}")
            commit_sha = _resolve_head(clone_dir)
            file_tree, languages = _walk_tree(clone_dir)
            target = ScanTarget(
                source_type=SourceType.GIT,
                ref=ref,
                commit_sha=commit_sha,
                file_tree=file_tree,
                languages=languages,
            )
            yield ScanSource(root=clone_dir, target=target)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        root = Path(ref).expanduser().resolve()
        if not root.exists():
            raise FileNotFoundError(f"scan target not found: {ref!r}")
        if root.is_file():
            raise ValueError(f"scan target must be a directory or repo URL, got file: {ref!r}")
        commit_sha = _resolve_head(root)
        file_tree, languages = _walk_tree(root)
        target = ScanTarget(
            source_type=SourceType.LOCAL,
            ref=str(root),
            commit_sha=commit_sha,
            file_tree=file_tree,
            languages=languages,
        )
        yield ScanSource(root=root, target=target)
