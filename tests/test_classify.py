"""Unit tests for the secret-confidence guard (VF-1 root cause) — pure functions,
no gitleaks binary required, so they run in CI on every push.

These pin the rule that keeps a placeholder in a template file from ever grading a
repo NO-GO, while making sure a real secret in real source is untouched.
"""

from __future__ import annotations

from runworthy.adapters.gitleaks_adapter import classify_secret
from runworthy.classify import is_direct_evidence, is_template_path
from runworthy.models import Confidence, Finding, Severity


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


def test_docs_dirs_match_exactly_not_by_prefix():
    # "doc"/"docs" are template dirs, but startswith("doc") swallowed skills/docx/ —
    # a Word-format skill's executable code, not documentation.
    assert is_template_path("doc/setup.py")
    assert is_template_path("docs/conf.py")
    assert not is_template_path("skills/docx/scripts/soffice.py")


def test_dunder_test_dirs_are_template():
    # __tests__/ is the standard JS spelling of tests/ — an injection string in a
    # repo's own test fixtures is the repo testing its defenses, not a finding to
    # cite (found live on Research-Cascade's prompt-injection pattern tests).
    assert is_template_path("servers/cascade-engine/src/__tests__/e2e.test.ts")
    assert is_template_path("src/trust/__tests__/patterns.test.ts")
    assert not is_template_path("src/trust/patterns.ts")


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


# --- evidence class (VF-3): direct vs pattern --------------------------------


def _f(detector, controls, conf, file):
    return Finding(
        finding_id="rw-x", detector=detector, detector_version="x", afr_controls=controls,
        severity=Severity.HIGH, confidence=conf, file=file, line=1,
        raw_message="m", dedup_key="k",
    )


def test_direct_evidence_dependency_route():
    # OSV database match and SkillSpector SC4 both map solely to AFR-10 -> direct,
    # keyed on the AFR route so a dedup-merge can't blur the detector field.
    assert is_direct_evidence(_f("osv-scanner", ["AFR-10"], Confidence.HIGH, "requirements.txt"))
    assert is_direct_evidence(_f("skillspector", ["AFR-10"], Confidence.HIGH, "requirements.txt"))


def test_direct_evidence_real_source_secret():
    # A gitleaks secret that survived the VF-1 guard (high confidence, real source).
    assert is_direct_evidence(_f("gitleaks", ["AFR-05", "AFR-06"], Confidence.HIGH, ".env"))


def test_pattern_evidence_is_not_direct():
    # SkillSpector code-route lead (env-read -> outbound call): high confidence in
    # real source, but a *mechanism*, not a control state -> pattern, not direct.
    assert not is_direct_evidence(_f("skillspector", ["AFR-08", "AFR-09"], Confidence.HIGH, "src/agent.py"))
    # Template / low-entropy secret (already capped low/info at the adapter).
    assert not is_direct_evidence(_f("gitleaks", ["AFR-05", "AFR-06"], Confidence.LOW, ".env.example"))
    # A high-confidence gitleaks hit in a template path is still not direct.
    assert not is_direct_evidence(_f("gitleaks", ["AFR-05", "AFR-06"], Confidence.HIGH, ".env.example"))


def test_template_path_dep_finding_is_not_direct():
    # A vulnerable dep manifest under examples/ is a demo's stack, not the running
    # stack — the OSV route must not floor a confirmed gap citing a template path.
    assert not is_direct_evidence(_f("osv-scanner", ["AFR-10"], Confidence.HIGH, "examples/requirements.txt"))
    assert not is_direct_evidence(_f("skillspector", ["AFR-10"], Confidence.HIGH, "docs/requirements.txt"))


def test_direct_evidence_survives_plain_string_confidence():
    # The predicate promises duck-typing; a Finding would coerce "high" to the enum,
    # so use a plain object to pin that == (not `is`) does the comparison.
    from types import SimpleNamespace

    f = SimpleNamespace(afr_controls=["AFR-05", "AFR-06"], detector="gitleaks",
                        confidence="high", file=".env")
    assert is_direct_evidence(f)
