"""Schema validity (criterion 2): every emitted ReadinessReport validates
against the persisted JSON Schema."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import jsonschema
import pytest

from runworthy.models import (
    AgentMap,
    Confidence,
    Finding,
    ReadinessReport,
    Severity,
    Verdict,
)
from runworthy.schema_export import export_schemas
from runworthy.tools import TOOLS

SCHEMAS = Path(__file__).parents[1] / "schemas"
requires_tools = pytest.mark.skipif(
    not all(shutil.which(t.exe) for t in TOOLS.values()), reason="detector tools not on PATH"
)


def _report_schema() -> dict:
    return json.loads((SCHEMAS / "readiness_report.schema.json").read_text(encoding="utf-8"))


def test_schemas_are_exportable(tmp_path):
    written = export_schemas(tmp_path)
    assert any(p.name == "readiness_report.schema.json" for p in written)


def test_synthetic_report_validates():
    report = ReadinessReport(
        verdict=Verdict.PROVISIONAL,
        findings=[
            Finding(
                finding_id="rw-abc",
                detector="gitleaks",
                detector_version="8.30.1",
                afr_controls=["AFR-05", "AFR-06"],
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                file="config.py",
                line=3,
                snippet_redacted="REDACTED",
                raw_message="secret",
                dedup_key="secret::config.py:github-pat:3",
            )
        ],
        target_ref="./x",
        generated_at="2026-07-05T00:00:00Z",
        engine_version="0.1.0",
        agent_map=AgentMap(frameworks=["LangGraph"]),
    )
    jsonschema.validate(report.model_dump(mode="json"), _report_schema())


@requires_tools
@pytest.mark.tools
def test_real_scan_validates(scanned):
    for name in ("langgraph_app", "noagent_repo"):
        report = scanned(name)
        jsonschema.validate(report.model_dump(mode="json"), _report_schema())
