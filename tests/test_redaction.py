"""Redaction invariant (criterion 5 / invariant 2)."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from runworthy.redact import contains_secret, mask_secrets
from runworthy.tools import TOOLS

FIXTURES = Path(__file__).parent / "fixtures"
PLANTED = "ghp_FAKE0123456789abcdefghijklmnopqrSTUV"
requires_tools = pytest.mark.skipif(
    not all(shutil.which(t.exe) for t in TOOLS.values()), reason="detector tools not on PATH"
)


def test_mask_secrets_masks_known_shapes():
    assert PLANTED not in (mask_secrets(f"token = {PLANTED}") or "")
    assert "AKIA" not in (mask_secrets("key AKIAQYLPMN5HGXFAKE99 here") or "")
    assert contains_secret(f"GITHUB_TOKEN={PLANTED}")


def test_mask_secrets_leaves_clean_text():
    clean = "subprocess.call(cmd, shell=True)"
    assert mask_secrets(clean) == clean
    assert not contains_secret(clean)


def test_mask_secrets_masks_connection_string_credentials():
    dsn = "postgres://admin:s3cr3tP4ssw0rd@db.example.com:5432/prod"
    masked = mask_secrets(dsn) or ""
    assert "s3cr3tP4ssw0rd" not in masked


def test_mask_secrets_idempotent():
    once = mask_secrets(f"secret={PLANTED}")
    assert mask_secrets(once) == once


@requires_tools
@pytest.mark.tools
def test_planted_secret_never_appears_in_report(scanned):
    """Scan a repo with a planted fake secret: the finding is emitted, but the
    value appears nowhere in the emitted JSON."""
    report = scanned("secret_repo")
    blob = json.dumps(report.model_dump(mode="json"))
    assert PLANTED not in blob
    secret_findings = [f for f in report.findings if "AFR-05" in f.afr_controls]
    assert secret_findings, "expected gitleaks to flag the planted secret"
    for f in secret_findings:
        assert not contains_secret(f.snippet_redacted or "")
        assert PLANTED not in (f.snippet_redacted or "")
