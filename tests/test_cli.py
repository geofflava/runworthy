"""CLI surface: --version, module form, and the honest no-agent report."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def test_version():
    out = subprocess.run(
        [sys.executable, "-m", "runworthy", "--version"], capture_output=True, encoding="utf-8"
    )
    assert out.returncode == 0
    assert "runworthy" in out.stdout


def test_scan_noagent_via_module(tmp_path):
    outfile = tmp_path / "report.json"
    r = subprocess.run(
        [sys.executable, "-m", "runworthy", "scan", str(FIXTURES / "noagent_repo"), "-o", str(outfile)],
        capture_output=True,
        encoding="utf-8",
    )
    assert r.returncode == 0
    data = json.loads(outfile.read_text(encoding="utf-8"))
    assert data["verdict"] == "PROVISIONAL"
    assert data["findings"] == []
    assert any("no agent surface" in n for n in data["notes"])


def test_scan_missing_target_fails_informatively():
    r = subprocess.run(
        [sys.executable, "-m", "runworthy", "scan", str(FIXTURES / "does_not_exist_xyz")],
        capture_output=True,
        encoding="utf-8",
    )
    assert r.returncode != 0
    assert "scan failed" in r.stderr
