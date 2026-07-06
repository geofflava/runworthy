"""JSON schemas the model nodes are forced to emit (structured output).

Kept as hand-written dicts (not derived from pydantic) because they double as the
model's tool ``input_schema`` and we want tight, model-facing enums and
descriptions, not the full pydantic serialization.
"""

from __future__ import annotations

from ..models import AFR_CONTROLS

MAP_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "description": "One assessment per AFR control you can speak to from the evidence.",
            "items": {
                "type": "object",
                "properties": {
                    "afr_control": {"type": "string", "enum": list(AFR_CONTROLS)},
                    "status": {
                        "type": "string",
                        "enum": ["pass", "gap", "unknown"],
                        "description": "pass = in place; gap = a confirmed failure; unknown = can't tell from evidence.",
                    },
                    "confidence": {
                        "type": "string",
                        "enum": ["high", "medium", "low"],
                        "description": (
                            "high = grounded in a specific finding or answer (Confirmed); "
                            "medium = an inferred absence (Likely gap - verify); "
                            "low = no grounding (Couldn't determine)."
                        ),
                    },
                    "evidence": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "finding_id or answer_id values, copied verbatim from the evidence given. Empty only for low-confidence 'couldn't determine' items.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "One line, for the translator. Why this status/confidence, tied to the evidence.",
                    },
                },
                "required": ["afr_control", "status", "confidence", "evidence", "rationale"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["items"],
    "additionalProperties": False,
}


TRANSLATE_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "items": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "index": {"type": "integer", "description": "The item's index from the input list."},
                    "plain_explanation": {
                        "type": "string",
                        "description": "<=3 sentences, plain English for a non-expert founder: what it is and why it matters. Cite file:line inline where there's a finding.",
                    },
                    "fix": {
                        "type": "string",
                        "description": "<=3 sentences: the concrete next step. For 'couldn't determine' items, say how to check.",
                    },
                },
                "required": ["index", "plain_explanation", "fix"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["items"],
    "additionalProperties": False,
}
