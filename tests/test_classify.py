"""Unit tests for the secret-confidence guard (VF-1 root cause) — pure functions,
no gitleaks binary required, so they run in CI on every push.

These pin the rule that keeps a placeholder in a template file from ever grading a
repo NO-GO, while making sure a real secret in real source is untouched.
"""

from __future__ import annotations

from runworthy.adapters.gitleaks_adapter import classify_secret
from runworthy.classify import is_template_path
from runworthy.models import Confidence, Severity


def test_is_template_path_flags_templates_and_docs():
    for p in [
        ".env.example",
        "config/.env.sample",
        "settings.template",
        "deploy.dist",
        "README.md",
        "docs/setup.md",
        "examples/agent.py",
        "tests/fixtures/data.py",
        "my_example_config.py",  # contains 'example'
    ]:
        assert is_template_path(p), p


def test_is_template_path_leaves_real_source_alone():
    for p in ["src/config.py", "app/settings.py", ".env", "main.py", "lib/keys.py"]:
        assert not is_template_path(p), p


def test_env_example_placeholder_drops_to_low_info():
    # The exact VF-1 shape: generic rule over-matched across the CRLF in a template
    # of empty assignments. High entropy on the captured bytes must not save it —
    # the template path alone caps it.
    item = {"Match": "OPENAI_API_KEY=\r\nREDACTED\r", "Entropy": 4.2}
    conf, sev = classify_secret(item, ".env.example", "generic-api-key")
    assert conf is Confidence.LOW
    assert sev is Severity.INFO


def test_low_entropy_match_drops_to_low_info():
    item = {"Match": "REDACTED", "Entropy": 2.0}
    conf, sev = classify_secret(item, "src/config.py", "generic-api-key")
    assert conf is Confidence.LOW
    assert sev is Severity.INFO


def test_real_secret_in_real_source_stays_high():
    item = {"Match": "REDACTED", "Entropy": 4.6}
    conf, sev = classify_secret(item, "src/config.py", "generic-api-key")
    assert conf is Confidence.HIGH
    assert sev is Severity.HIGH


def test_private_key_in_real_source_is_critical():
    item = {"Match": "REDACTED", "Entropy": 5.1}
    conf, sev = classify_secret(item, "deploy/id_rsa", "private-key")
    assert conf is Confidence.HIGH
    assert sev is Severity.CRITICAL


def test_env_var_secret_is_not_falsely_downgraded():
    """A real committed ``.env`` (not a template) with a high-entropy value is a
    genuine leak — the redacted Match reads ``API_KEY=REDACTED`` but we must not
    treat that variable-name context as a placeholder."""
    item = {"Match": "API_KEY=REDACTED", "Entropy": 4.8}
    conf, _ = classify_secret(item, ".env", "generic-api-key")
    assert conf is Confidence.HIGH
