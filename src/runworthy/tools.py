"""External-tool registry, discovery, and version pinning.

Detectors are **pinned, PATH-resolved, not vendored** (spec §5). ``runworthy
doctor`` reports presence / version / pin-mismatch for each and exits nonzero if
any required tool is missing.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass

_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+)")


@dataclass(frozen=True)
class ExternalTool:
    key: str  # detector key used in Finding.detector / detector_versions
    exe: str  # executable name resolved on PATH
    pinned_version: str
    version_args: tuple[str, ...]
    install_hint: str

    def resolve(self) -> str | None:
        """Absolute path to the executable on PATH, or None if not found."""
        return shutil.which(self.exe)

    def detect_version(self) -> str | None:
        """Run the tool's version command and extract an X.Y.Z string."""
        path = self.resolve()
        if not path:
            return None
        try:
            out = subprocess.run(
                [path, *self.version_args],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        blob = (out.stdout or "") + "\n" + (out.stderr or "")
        m = _VERSION_RE.search(blob)
        return m.group(1) if m else None


#: The three Phase-0 detectors, version-pinned (spec §3 table).
TOOLS: dict[str, ExternalTool] = {
    "gitleaks": ExternalTool(
        key="gitleaks",
        exe="gitleaks",
        pinned_version="8.30.1",
        version_args=("version",),
        install_hint="scoop install gitleaks  |  brew install gitleaks  |  "
        "download from github.com/gitleaks/gitleaks/releases",
    ),
    "osv-scanner": ExternalTool(
        key="osv-scanner",
        exe="osv-scanner",
        pinned_version="2.4.0",
        version_args=("--version",),
        install_hint="scoop install osv-scanner  |  brew install osv-scanner  |  "
        "download from github.com/google/osv-scanner/releases",
    ),
    "skillspector": ExternalTool(
        key="skillspector",
        exe="skillspector",
        pinned_version="2.3.9",
        version_args=("--version",),
        # NVIDIA/SkillSpector has no git tags; pin to the 2.3.9 release commit.
        install_hint="pipx install "
        "'git+https://github.com/NVIDIA/skillspector.git@dde36f258729b5aec7c835295a9556e64a2def0c'  |  "
        "uv tool install git+https://github.com/NVIDIA/skillspector.git",
    ),
}


@dataclass
class ToolStatus:
    key: str
    present: bool
    version: str | None
    pinned: str
    path: str | None
    install_hint: str

    @property
    def pin_match(self) -> bool:
        return self.present and self.version == self.pinned

    @property
    def state(self) -> str:
        if not self.present:
            return "MISSING"
        if self.version is None:
            return "UNKNOWN_VERSION"
        return "OK" if self.version == self.pinned else "PIN_MISMATCH"


def check_tools() -> list[ToolStatus]:
    """Probe every registered tool. Order is stable for reproducible reports."""
    statuses: list[ToolStatus] = []
    for tool in TOOLS.values():
        path = tool.resolve()
        version = tool.detect_version() if path else None
        statuses.append(
            ToolStatus(
                key=tool.key,
                present=path is not None,
                version=version,
                pinned=tool.pinned_version,
                path=path,
                install_hint=tool.install_hint,
            )
        )
    return statuses


def detector_versions() -> dict[str, str]:
    """{detector_key: resolved_version} for tools present — embedded in the report."""
    out: dict[str, str] = {}
    for tool in TOOLS.values():
        v = tool.detect_version()
        if v:
            out[tool.key] = v
    return out
