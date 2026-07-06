"""Emit JSON Schema files for the contract objects (spec §4).

The persisted schemas under ``schemas/`` are the machine-checkable form of the
contract; the test-suite validates every emitted ``ReadinessReport`` against
``schemas/readiness_report.schema.json``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import (
    AgentMap,
    Finding,
    OperationalAnswer,
    PostureItem,
    ReadinessReport,
    ScanTarget,
)

SCHEMA_MODELS = {
    "scan_target": ScanTarget,
    "agent_map": AgentMap,
    "finding": Finding,
    "operational_answer": OperationalAnswer,
    "posture_item": PostureItem,
    "readiness_report": ReadinessReport,
}


def export_schemas(out_dir: str | Path) -> list[Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for name, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema()
        path = out / f"{name}.schema.json"
        path.write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":  # pragma: no cover
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "schemas"
    for p in export_schemas(target):
        print(f"wrote {p}")
