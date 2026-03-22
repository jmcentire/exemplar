"""
Data Models & Schemas for the Exemplar system.

Frozen Pydantic v2 models and StrEnums forming the shared data contract.
All models use frozen=True and extra='forbid'. Shallow-freeze semantics.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Annotated, Any, Callable, ClassVar, Optional

from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from pydantic.functional_validators import AfterValidator


# ============================================================================
# Timestamp Validation
# ============================================================================

def validate_iso_timestamp(value: str) -> str:
    """Validate that a string conforms to ISO 8601 datetime format.

    Returns the original string unchanged if valid, raises ValueError otherwise.
    """
    if not value:
        raise ValueError("Timestamp must not be empty")
    try:
        datetime.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Timestamp must be valid ISO 8601 format: {value}") from exc
    return value


IsoTimestamp = Annotated[str, AfterValidator(validate_iso_timestamp)]


# ============================================================================
# Enums
# ============================================================================

class Severity(StrEnum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(StrEnum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"


class ReviewStage(StrEnum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


class ReviewDecision(StrEnum):
    """Final decision on a pull request review: block merging, warn, or pass."""
    block = "block"
    warn = "warn"
    # 'pass' is a Python keyword but works as an enum member name via explicit assignment
    pass_ = "pass"

    @classmethod
    def _missing_(cls, value: object) -> ReviewDecision | None:
        # Allow construction via ReviewDecision("pass")
        for member in cls:
            if member.value == value:
                return member
        return None


class ClassificationLabel(StrEnum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"


class _ChroniclerEventTypeMeta(type(StrEnum)):
    """Metaclass allowing bracket access by value (e.g., ChroniclerEventType["review.started"])."""

    def __getitem__(cls, key: str) -> ChroniclerEventType:
        try:
            return super().__getitem__(key)
        except KeyError:
            # Fall back to value-based lookup for dotted names
            for member in cls:
                if member.value == key:
                    return member
            raise KeyError(key)


class ChroniclerEventType(StrEnum, metaclass=_ChroniclerEventTypeMeta):
    """Well-known Chronicler event types emitted throughout the review lifecycle."""
    review_started = "review.started"
    stage_started = "stage.started"
    stage_complete = "stage.complete"
    assessment_merged = "assessment.merged"
    report_sealed = "report.sealed"
    review_complete = "review.complete"
    policy_violation = "policy.violation"
    pattern_detected = "pattern.detected"
    learning_recorded = "learning.recorded"


class LearnerPhase(StrEnum):
    """Apprentice learning phase progression stage."""
    shadow = "shadow"
    canary = "canary"
    primary = "primary"


class StigmergyVerb(StrEnum):
    """Stigmergy signal verb for inter-agent coordination."""
    deposit = "deposit"
    reinforce = "reinforce"
    decay = "decay"
    query = "query"


class CliExitCode(IntEnum):
    """CLI process exit codes mapping to review outcomes."""
    pass_ = 0
    warn = 1
    block = 2
    error = 3


class OutputFormat(StrEnum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"


# ============================================================================
# Rank Functions
# ============================================================================

_SEVERITY_RANKS: dict[Severity, int] = {
    Severity.critical: 4,
    Severity.high: 3,
    Severity.medium: 2,
    Severity.low: 1,
    Severity.info: 0,
}


def severity_rank(severity: Severity) -> int:
    """Return integer rank for a Severity enum value. Higher = more severe."""
    if not isinstance(severity, Severity):
        raise TypeError(f"Expected Severity enum member, got {type(severity).__name__}")
    try:
        return _SEVERITY_RANKS[severity]
    except KeyError:
        raise ValueError(f"Unknown severity value: {severity}")


_CONFIDENCE_RANKS: dict[Confidence, int] = {
    Confidence.high: 2,
    Confidence.medium: 1,
    Confidence.low: 0,
}


def confidence_rank(confidence: Confidence) -> int:
    """Return integer rank for a Confidence enum value. Higher = more confident."""
    if not isinstance(confidence, Confidence):
        raise TypeError(f"Expected Confidence enum member, got {type(confidence).__name__}")
    try:
        return _CONFIDENCE_RANKS[confidence]
    except KeyError:
        raise ValueError(f"Unknown confidence value: {confidence}")


_LEARNER_PHASE_RANKS: dict[LearnerPhase, int] = {
    LearnerPhase.shadow: 0,
    LearnerPhase.canary: 1,
    LearnerPhase.primary: 2,
}


def learner_phase_rank(phase: LearnerPhase) -> int:
    """Return integer rank for a LearnerPhase enum value. Higher = more advanced."""
    if not isinstance(phase, LearnerPhase):
        raise TypeError(f"Expected LearnerPhase enum member, got {type(phase).__name__}")
    try:
        return _LEARNER_PHASE_RANKS[phase]
    except KeyError:
        raise ValueError(f"Unknown learner phase value: {phase}")


# ============================================================================
# Base Model
# ============================================================================

class _ExemplarBase(BaseModel):
    """Shared frozen Pydantic v2 base model.

    Provides canonical_bytes() and canonical_hash() methods for deterministic
    hashing. All domain models inherit from this.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    PACT_KEY: ClassVar[str] = "exemplar.schemas"

    def canonical_bytes(self) -> bytes:
        """Return deterministic JSON bytes suitable for SHA-256 hashing.

        Uses model_dump(mode='json') serialized with sort_keys=True and
        compact separators (',', ':'). Attributed to _ExemplarBase.PACT_KEY.
        """
        return json.dumps(
            self.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def canonical_hash(self) -> str:
        """Return hex SHA-256 digest of canonical_bytes().

        Used by TesseraSeal for hash-chain integrity verification.
        Attributed to _ExemplarBase.PACT_KEY.
        """
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def __hash__(self) -> int:
        """Hash based on canonical bytes for models with list/dict fields."""
        return hash(self.canonical_bytes())


def canonical_hash(instance: _ExemplarBase) -> str:
    """Module-level convenience: return hex SHA-256 of an _ExemplarBase instance.

    Delegates to ``instance.canonical_hash()``.
    """
    return instance.canonical_hash()


# ============================================================================
# Domain Models (in dependency order)
# ============================================================================

class DiffHunk(_ExemplarBase):
    """A single parsed hunk from a unified diff, with metadata and classification labels."""
    id: str
    file_path: str
    start_line_old: int
    count_old: int
    start_line_new: int
    count_new: int
    context_before: list[str] = []
    added_lines: list[str] = []
    removed_lines: list[str] = []
    context_after: list[str] = []
    raw_header: str
    classifications: list[ClassificationLabel] = []
    language: Optional[str] = None


class ReviewRequest(_ExemplarBase):
    """The output of intake: a complete review request containing parsed and classified hunks."""
    id: str
    source: str
    hunks: list[DiffHunk]
    file_paths: list[str]
    created_at: str
    metadata: dict[str, str] = {}


class Finding(_ExemplarBase):
    """A single issue found by a reviewer in a specific hunk."""
    id: str
    hunk_id: str
    file_path: str
    line_number: Optional[int] = None
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    suggestion: Optional[str] = None
    rule_id: str
    stage: ReviewStage


class Assessment(_ExemplarBase):
    """A single reviewer's complete assessment of the diff hunks it was given."""
    id: str
    review_request_id: str
    stage: ReviewStage
    reviewer_id: str
    decision: ReviewDecision
    findings: list[Finding] = []
    confidence: Confidence
    is_partial: bool = False
    error_message: Optional[str] = None
    duration_ms: int
    created_at: str


class TrustScore(_ExemplarBase):
    """Arbiter trust weight for a reviewer agent, used in weighted assessment merging."""
    reviewer_id: str
    stage: ReviewStage
    weight: float
    accepted_count: int = 0
    dismissed_count: int = 0
    updated_at: str

    @field_validator("weight")
    @classmethod
    def _validate_weight(cls, v: float) -> float:
        if not (0.0 <= v <= 1.0):
            raise ValueError("Trust weight must be between 0.0 and 1.0")
        return v


class TesseraSeal(_ExemplarBase):
    """A hash-chain tamper-proof seal over serialized content, verifiable independently."""
    content_hash: str
    previous_hash: Optional[str] = None
    chain_hash: str
    sealed_at: str
    sealer_id: str


class ReviewReport(_ExemplarBase):
    """The final merged review report with trust-weighted scoring and a tamper-proof seal."""
    id: str
    review_request_id: str
    decision: ReviewDecision
    findings: list[Finding]
    assessments: list[Assessment]
    confidence: Confidence
    trust_scores: list[TrustScore]
    conflict_notes: list[str] = []
    summary: str
    seal: Optional[TesseraSeal] = None
    created_at: str
    metadata: dict[str, str] = {}


class ReviewerCredential(_ExemplarBase):
    """Signet identity credential for a reviewer agent."""
    reviewer_id: str
    display_name: str
    stage: ReviewStage
    public_key_hex: str
    created_at: str
    is_active: bool = True


class PolicyToken(_ExemplarBase):
    """Agent-Safe policy token defining what a reviewer agent is permitted to access and do."""
    token_id: str
    reviewer_id: str
    allowed_file_patterns: list[str] = ["**/*"]
    denied_file_patterns: list[str] = []
    allowed_classifications: list[ClassificationLabel] = [ClassificationLabel.public]
    max_severity: Severity = Severity.critical
    issued_at: str
    expires_at: Optional[str] = None


class ChroniclerEvent(_ExemplarBase):
    """A structured event emitted at review lifecycle boundaries for audit trail."""
    event_id: str
    event_type: ChroniclerEventType
    review_request_id: str
    timestamp: str
    stage: Optional[ReviewStage] = None
    reviewer_id: Optional[str] = None
    payload: dict[str, str] = {}
    message: str


class StigmergySignal(_ExemplarBase):
    """A recurring pattern signal detected by Stigmergy."""
    signal_id: str
    pattern_key: str
    description: str
    occurrences: int = 1
    first_seen_at: str
    last_seen_at: str
    reviewer_id: Optional[str] = None
    stage: Optional[ReviewStage] = None
    metadata: dict[str, str] = {}


class LearningRecord(_ExemplarBase):
    """A single learning observation: AI finding paired with human decision."""
    record_id: str
    finding_id: str
    reviewer_id: str
    stage: ReviewStage
    rule_id: str
    severity: Severity
    accepted: bool
    human_comment: Optional[str] = None
    recorded_at: str


class KindexEntry(_ExemplarBase):
    """A Kindex knowledge store entry representing a past review or codebase context artifact."""
    key: str
    kind: str
    summary: str
    data: dict[str, str]
    tags: list[str] = []
    created_at: str
    updated_at: str


class PipelineResult(_ExemplarBase):
    """End-to-end pipeline result returned by the core pipeline."""
    review_request: ReviewRequest
    assessments: list[Assessment]
    report: ReviewReport
    events: list[ChroniclerEvent] = []
    formatted_output: str
    output_format: OutputFormat
    exit_code: int


# ============================================================================
# Emission wrapper
# ============================================================================

def _classify_inputs(*args, **kwargs) -> list:
    """Classify input types for PACT event emission."""
    result = []
    for a in args:
        result.append(type(a).__name__)
    for k, v in kwargs.items():
        result.append(f"{k}:{type(v).__name__}")
    return result


class Schemas:
    """Unified schemas class with optional PACT event emission."""

    def __init__(self, event_handler: Optional[Callable] = None):
        self._handler = event_handler

    def _emit_event(self, pact_key: str, event: str, **extra):
        if self._handler:
            payload = {"pact_key": pact_key, "event": event}
            payload.update(extra)
            self._handler(payload)

    def _wrap(self, method_name: str, fn, *args, **kwargs):
        pact_key = f"PACT:schemas:{method_name}"
        self._emit_event(
            pact_key, "invoked",
            input_classification=_classify_inputs(*args, **kwargs),
        )
        try:
            result = fn(*args, **kwargs)
            self._emit_event(pact_key, "completed")
            return result
        except Exception as e:
            self._emit_event(pact_key, "error", error=str(e))
            raise

    def severity_rank(self, *args, **kwargs):
        return self._wrap("severity_rank", severity_rank, *args, **kwargs)

    def confidence_rank(self, *args, **kwargs):
        return self._wrap("confidence_rank", confidence_rank, *args, **kwargs)

    def learner_phase_rank(self, *args, **kwargs):
        return self._wrap("learner_phase_rank", learner_phase_rank, *args, **kwargs)

    def canonical_bytes(self, *args, **kwargs):
        return self._wrap("canonical_bytes", lambda *a, **kw: _ExemplarBase.canonical_bytes(*a, **kw), *args, **kwargs)

    def canonical_hash(self, *args, **kwargs):
        return self._wrap("canonical_hash", canonical_hash, *args, **kwargs)

    def validate_iso_timestamp(self, *args, **kwargs):
        return self._wrap("validate_iso_timestamp", validate_iso_timestamp, *args, **kwargs)


# ============================================================================
# __all__
# ============================================================================

__all__ = [
    # Annotated type
    "IsoTimestamp",
    # Validator
    "validate_iso_timestamp",
    # Enums
    "Severity",
    "Confidence",
    "ReviewStage",
    "ReviewDecision",
    "ClassificationLabel",
    "ChroniclerEventType",
    "LearnerPhase",
    "StigmergyVerb",
    "CliExitCode",
    "OutputFormat",
    # Rank functions
    "severity_rank",
    "confidence_rank",
    "learner_phase_rank",
    # Standalone helpers
    "canonical_hash",
    # Base model
    "_ExemplarBase",
    # Domain models
    "DiffHunk",
    "ReviewRequest",
    "Finding",
    "Assessment",
    "TrustScore",
    "TesseraSeal",
    "ReviewReport",
    "ReviewerCredential",
    "PolicyToken",
    "ChroniclerEvent",
    "StigmergySignal",
    "LearningRecord",
    "KindexEntry",
    "PipelineResult",
    # Emission wrapper
    "Schemas",
]
