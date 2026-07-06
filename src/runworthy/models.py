"""Core data model — the shared contract (spec v0.2 §4).

Every component in the engine speaks these objects. ``ReadinessReport`` is the
single source of truth and is **self-contained**: it embeds the ``findings[]`` it
cites so any renderer (CLI, web, CI, SARIF, badge) can work from the persisted
report alone, offline.

Do not drift from spec §4 without updating the spec first.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum

from pydantic import BaseModel, Field

# --- Framework constants -----------------------------------------------------

#: Every AFR control id (AFR v0.2.0 — 29 controls).
AFR_CONTROLS: tuple[str, ...] = tuple(f"AFR-{n:02d}" for n in range(1, 30))
TOTAL_CONTROLS: int = len(AFR_CONTROLS)

#: The Boldface — the ten non-negotiable controls (AFR v0.2.0 §"The Boldface").
BOLDFACE: frozenset[str] = frozenset(
    {"AFR-01", "AFR-04", "AFR-05", "AFR-09", "AFR-11", "AFR-12", "AFR-16", "AFR-17", "AFR-20", "AFR-25"}
)


# --- Enums -------------------------------------------------------------------


class SourceType(StrEnum):
    LOCAL = "local"
    GIT = "git"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(StrEnum):
    """Deterministic finding = ``high``; the interpretation layer (Phase 1)
    adds ``likely``/``low`` tiers for inferred absences. Detector adapters emit
    only these three tiers."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Verdict(StrEnum):
    GO = "GO"
    NO_GO = "NO_GO"
    PROVISIONAL = "PROVISIONAL"


class PostureStatus(StrEnum):
    PASS = "pass"
    GAP = "gap"
    UNKNOWN = "unknown"


# --- Core objects (spec §4) --------------------------------------------------


class ScanTarget(BaseModel):
    """``{ source_type, ref, commit_sha, file_tree, languages }`` — provenance
    starts here: the resolved commit SHA is captured at intake."""

    source_type: SourceType
    ref: str  # local path or repo URL as given by the user
    commit_sha: str | None = None  # resolved at intake; None for a dirty local dir
    file_tree: list[str] = Field(default_factory=list)  # repo-relative POSIX paths
    languages: dict[str, int] = Field(default_factory=dict)  # language -> file count


class AgentMap(BaseModel):
    """The fingerprinted agent surface. Empty everywhere == no agent detected."""

    frameworks: list[str] = Field(default_factory=list)
    entrypoints: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)
    prompts: list[str] = Field(default_factory=list)
    mcp_servers: list[str] = Field(default_factory=list)
    skills: list[str] = Field(default_factory=list)
    memory_stores: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            (
                self.frameworks,
                self.entrypoints,
                self.tools,
                self.prompts,
                self.mcp_servers,
                self.skills,
                self.memory_stores,
            )
        )


class Finding(BaseModel):
    """One normalized detector finding. **Every finding carries file + line +
    dedup_key** — a finding without a location is dropped before emission
    (invariant 1). ``snippet_redacted`` never contains a secret value
    (invariant 2)."""

    finding_id: str
    detector: str
    detector_version: str
    afr_controls: list[str] = Field(default_factory=list)  # mechanical mappings only (spec §3)
    severity: Severity
    confidence: Confidence
    file: str
    line: int
    snippet_redacted: str | None = None
    raw_message: str
    dedup_key: str
    # When a finding is corroborated by more than one detector (dedup rule,
    # spec §3/§4 invariant 4), the primary detector is in ``detector`` and the
    # corroborating ones are listed here — "one finding listing both detectors".
    also_reported_by: list[str] = Field(default_factory=list)

    @staticmethod
    def make_id(dedup_key: str) -> str:
        """Content-derived, stable id (no timestamps) so merged findings sharing
        a dedup_key share an id and golden fixtures stay reproducible."""
        return "rw-" + hashlib.sha1(dedup_key.encode("utf-8")).hexdigest()[:10]


class OperationalAnswer(BaseModel):
    """An answer to a Boldface question code can't see (Phase 2 overlay).
    Empty in Phase 0."""

    answer_id: str
    afr_control: str
    question: str
    answer: str
    answered_at: str


class PostureItem(BaseModel):
    """An interpreted control assessment (Phase 1). Empty in Phase 0 — no
    control can be confirmed without the interpretation layer / overlay."""

    afr_control: str
    status: PostureStatus
    boldface: bool
    evidence: list[str] = Field(default_factory=list)  # finding_id | answer_id
    plain_explanation: str
    fix: str


class ReadinessReport(BaseModel):
    """The single, self-contained source of truth. Embeds the findings it cites.

    Phase 0 always emits ``verdict = PROVISIONAL`` with ``posture_items = []``:
    no Boldface control can be *confirmed* without the interpretation layer, so
    the honest verdict is provisional (spec §4 "Verdict semantics under partial
    observability")."""

    band: str | None = None  # no band without interpretation; renderers show "provisional"
    verdict: Verdict = Verdict.PROVISIONAL
    score: int = 0
    assessed_controls: int = 0
    total_controls: int = TOTAL_CONTROLS
    posture_items: list[PostureItem] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)  # embedded — renderers need them
    operational_answers: list[OperationalAnswer] = Field(default_factory=list)
    target_ref: str
    commit_sha: str | None = None
    generated_at: str
    engine_version: str
    detector_versions: dict[str, str] = Field(default_factory=dict)
    # Honest, non-fabricated context the fingerprint earned (rendered, not scored).
    agent_map: AgentMap = Field(default_factory=AgentMap)
    notes: list[str] = Field(default_factory=list)  # e.g. "no agent surface detected"
