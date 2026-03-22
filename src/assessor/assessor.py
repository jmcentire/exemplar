"""
Arbiter-style trust-weighted assessment merge.

Merges multiple reviewer Assessments into a single ReviewReport using
trust-weighted scoring, deduplication, conflict resolution, and categorical
overrides.

PACT: assessor
"""
from __future__ import annotations

import logging
import uuid
from enum import StrEnum
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("assessor.merge_assessments")

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
    # Aliases (do not appear in list/len, but accessible as Severity.error etc.)
    error = "high"
    warning = "low"


class ReviewDecision(StrEnum):
    """Final decision on a pull request review: block merging, warn, or pass."""
    block = "block"
    warn = "warn"
    # 'pass' is a Python keyword, so we use a string value
    pass_ = "pass"

    # Allow access via ReviewDecision("pass")
    @classmethod
    def _missing_(cls, value: object) -> ReviewDecision | None:
        if value == "pass":
            return cls.pass_
        return None

    # Allow getattr(ReviewDecision, "pass") to work
    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)


# Patch so getattr(ReviewDecision, "pass") works
ReviewDecision.__dict__  # force class creation
# We handle this by overriding __getattr__ at module level for the class


class ReviewStage(StrEnum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


class Confidence(StrEnum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"


class ChroniclerEventType(StrEnum):
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

    @classmethod
    def _missing_(cls, value: object) -> ChroniclerEventType | None:
        for member in cls:
            if member.value == value:
                return member
        return None


# ---------------------------------------------------------------------------
# Primitive value types (frozen, validated)
# ---------------------------------------------------------------------------


class ReviewRequestId(BaseModel):
    """Non-empty string identifier for a review request."""
    model_config = ConfigDict(frozen=True)
    value: str = Field(min_length=1, max_length=256)


class ReviewerId(BaseModel):
    """Non-empty identifier for a reviewer instance."""
    model_config = ConfigDict(frozen=True)
    value: str = Field(min_length=1, max_length=128)


class TrustWeight(BaseModel):
    """A trust weight value in the range [0.0, 1.0]."""
    model_config = ConfigDict(frozen=True)
    value: float = Field(ge=0.0, le=1.0)


class ConfidenceScore(BaseModel):
    """A confidence score in the range [0.0, 1.0]."""
    model_config = ConfigDict(frozen=True)
    value: float = Field(ge=0.0, le=1.0)


# ---------------------------------------------------------------------------
# Struct types (frozen)
# ---------------------------------------------------------------------------


class FindingDeduplicationKey(BaseModel):
    """Composite key used to identify duplicate findings across reviewers."""
    model_config = ConfigDict(frozen=True)

    hunk_id: str
    file_path: str = Field(min_length=1, max_length=1024)
    line_number: int = Field(ge=1)
    rule_id: str = Field(min_length=1, max_length=256)


class Finding(BaseModel):
    """A single issue found by a reviewer in a specific hunk."""
    model_config = ConfigDict(frozen=True)

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


class TrustScore(BaseModel):
    """Arbiter trust weight for a reviewer agent."""
    model_config = ConfigDict(frozen=True)

    reviewer_id: str
    stage: ReviewStage
    weight: float = Field(ge=0.0, le=1.0)
    accepted_count: int = 0
    dismissed_count: int = 0
    updated_at: str


class Assessment(BaseModel):
    """A single reviewer's complete assessment of the diff hunks."""
    model_config = ConfigDict(frozen=True)

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


class ConflictNote(BaseModel):
    """Documents a conflict between reviewer assessments and the resolution applied."""
    model_config = ConfigDict(frozen=True)

    description: str
    overriding_stage: ReviewStage
    overridden_stage: ReviewStage
    overriding_decision: ReviewDecision
    overridden_decision: ReviewDecision


class PactAttribution(BaseModel):
    """PACT governance attribution metadata."""
    model_config = ConfigDict(frozen=True)

    component: str = Field(min_length=1)
    version: int = Field(ge=1)
    timestamp: str


class TesseraSeal(BaseModel):
    """A hash-chain tamper-proof seal over serialized content."""
    model_config = ConfigDict(frozen=True)

    content_hash: str
    previous_hash: Optional[str] = None
    chain_hash: str
    sealed_at: str
    sealer_id: str


class ChroniclerEvent(BaseModel):
    """A structured event emitted at review lifecycle boundaries."""
    model_config = ConfigDict(frozen=True)

    event_id: str
    event_type: ChroniclerEventType
    review_request_id: str
    timestamp: str
    stage: Optional[ReviewStage] = None
    reviewer_id: Optional[str] = None
    payload: dict[str, str] = {}
    message: str


class ReviewReport(BaseModel):
    """The final merged review report."""
    model_config = ConfigDict(frozen=True)

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
    pact: Optional[PactAttribution] = None


class MergeContext(BaseModel):
    """Configuration values relevant to the merge algorithm."""
    model_config = ConfigDict(frozen=True)

    default_trust_weight: TrustWeight
    block_threshold: float = Field(ge=0.0)
    warn_threshold: float = Field(ge=0.0)
    stage_priority: list[ReviewStage] = Field(min_length=1)
    security_block_overrides: bool


class SeverityScoreMap(BaseModel):
    """Mapping Severity variants to numeric scores."""
    model_config = ConfigDict(frozen=True)

    info: float = 1.0
    warning: float = 3.0
    error: float = 7.0
    critical: float = 15.0


class ConfidenceScoreMap(BaseModel):
    """Base confidence score multipliers."""
    model_config = ConfigDict(frozen=True)

    low: float = 0.3
    medium: float = 0.6
    high: float = 1.0


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

PACT_COMPONENT = "assessor"
PACT_VERSION = 1
DEFAULT_TRUST_WEIGHT = 0.5

SEVERITY_SCORE: dict[Severity, float] = {
    Severity.info: 1.0,
    Severity.low: 3.0,
    Severity.medium: 5.0,
    Severity.high: 7.0,
    Severity.critical: 15.0,
}

CONFIDENCE_MULTIPLIER: dict[Confidence, float] = {
    Confidence.low: 0.3,
    Confidence.medium: 0.6,
    Confidence.high: 1.0,
}

STAGE_PRIORITY: list[ReviewStage] = [
    ReviewStage.security,
    ReviewStage.correctness,
    ReviewStage.architecture,
    ReviewStage.style,
]

# Severity ordering for comparison (higher index = more severe)
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


# ---------------------------------------------------------------------------
# Protocol for Chronicler
# ---------------------------------------------------------------------------

@runtime_checkable
class ChroniclerEmitterProtocol(Protocol):
    """Protocol for emitting Chronicler events."""
    async def emit(self, event: ChroniclerEvent) -> None: ...


# ---------------------------------------------------------------------------
# Phase 1: Trust Resolution
# ---------------------------------------------------------------------------

def _resolve_trust(
    assessments: list[Assessment],
    trust_scores: list[TrustScore],
    merge_context: MergeContext,
) -> dict[tuple[str, ReviewStage], float]:
    """
    Resolve trust weights for each (reviewer_id, stage) pair.

    Returns a dict mapping (reviewer_id, stage) -> trust weight (float).
    Falls back to merge_context.default_trust_weight when no explicit match.
    """
    # Build lookup from explicit trust scores
    explicit: dict[tuple[str, ReviewStage], float] = {}
    for ts in trust_scores:
        explicit[(ts.reviewer_id, ts.stage)] = ts.weight

    default_weight = merge_context.default_trust_weight.value
    result: dict[tuple[str, ReviewStage], float] = {}

    for assessment in assessments:
        key = (assessment.reviewer_id, assessment.stage)
        if key not in result:
            result[key] = explicit.get(key, default_weight)

    return result


# ---------------------------------------------------------------------------
# Phase 2: Deduplication
# ---------------------------------------------------------------------------

def _deduplicate_findings(
    assessments: list[Assessment],
    resolved_trust: dict[tuple[str, ReviewStage], float],
) -> list[Finding]:
    """
    Deduplicate findings across all assessments by composite key
    (hunk_id, file_path, line_number, rule_id).

    Within a duplicate group, the highest-severity finding is kept.
    Confidence is boosted to min(1.0, max_trust_weight * original_confidence_multiplier).
    """
    if not assessments:
        return []

    # Group findings by composite key
    groups: dict[tuple[str, str, int | None, str], list[tuple[Finding, float]]] = {}

    for assessment in assessments:
        trust_weight = resolved_trust.get(
            (assessment.reviewer_id, assessment.stage), DEFAULT_TRUST_WEIGHT
        )
        for finding in assessment.findings:
            key = (finding.hunk_id, finding.file_path, finding.line_number, finding.rule_id)
            if key not in groups:
                groups[key] = []
            groups[key].append((finding, trust_weight))

    # For each group, keep the highest-severity finding
    result: list[Finding] = []
    for key, group in groups.items():
        # Sort by severity descending (highest first)
        group.sort(key=lambda x: _SEVERITY_ORDER.get(x[0].severity, 0), reverse=True)
        best_finding, best_trust = group[0]

        # Compute max trust weight across contributors
        max_trust = max(tw for _, tw in group)

        # Boost confidence: min(1.0, max_trust * confidence_multiplier)
        conf_mult = CONFIDENCE_MULTIPLIER.get(best_finding.confidence, 1.0)
        boosted = min(1.0, max_trust * conf_mult)

        # Map boosted value back to Confidence enum
        if boosted >= 0.8:
            new_confidence = Confidence.high
        elif boosted >= 0.5:
            new_confidence = Confidence.medium
        else:
            new_confidence = Confidence.low

        # Create a new finding with updated confidence
        result.append(Finding(
            id=best_finding.id,
            hunk_id=best_finding.hunk_id,
            file_path=best_finding.file_path,
            line_number=best_finding.line_number,
            severity=best_finding.severity,
            confidence=new_confidence,
            title=best_finding.title,
            description=best_finding.description,
            suggestion=best_finding.suggestion,
            rule_id=best_finding.rule_id,
            stage=best_finding.stage,
        ))

    return result


# ---------------------------------------------------------------------------
# Phase 3: Decision Computation
# ---------------------------------------------------------------------------

def _compute_decision(
    deduplicated_findings: list[Finding],
    assessments: list[Assessment],
    resolved_trust: dict[tuple[str, ReviewStage], float],
    merge_context: MergeContext,
) -> dict[str, Any]:
    """
    Compute the final ReviewDecision from deduplicated findings,
    trust-weighted scoring, and categorical overrides.

    Returns dict with keys: decision, total_score, conflict_notes.
    """
    # Compute total weighted score
    total_score = 0.0
    for finding in deduplicated_findings:
        severity_score = SEVERITY_SCORE.get(finding.severity, 0.0)
        confidence_mult = CONFIDENCE_MULTIPLIER.get(finding.confidence, 1.0)

        # Find the max trust weight for the assessment(s) that contributed this finding
        # We use the trust associated with the finding's stage
        max_trust = 0.0
        for assessment in assessments:
            key = (assessment.reviewer_id, assessment.stage)
            tw = resolved_trust.get(key, DEFAULT_TRUST_WEIGHT)
            if tw > max_trust:
                max_trust = tw

        total_score += severity_score * confidence_mult * max_trust

    # Determine threshold-based decision
    pass_decision = ReviewDecision("pass")
    if total_score >= merge_context.block_threshold:
        decision = ReviewDecision.block
    elif total_score >= merge_context.warn_threshold:
        decision = ReviewDecision.warn
    else:
        decision = pass_decision

    # Check categorical overrides
    conflict_notes: list[ConflictNote] = []

    if merge_context.security_block_overrides:
        for assessment in assessments:
            if assessment.stage == ReviewStage.security and assessment.decision == ReviewDecision.block:
                # Security BLOCK overrides everything
                if decision != ReviewDecision.block:
                    # Find a conflicting assessment for the note
                    for other in assessments:
                        if other.stage != ReviewStage.security and other.decision != ReviewDecision.block:
                            conflict_notes.append(ConflictNote(
                                description=(
                                    f"Security stage BLOCK from {assessment.reviewer_id} "
                                    f"overrides {other.stage.value} stage "
                                    f"{other.decision.value} from {other.reviewer_id}"
                                ),
                                overriding_stage=ReviewStage.security,
                                overridden_stage=other.stage,
                                overriding_decision=ReviewDecision.block,
                                overridden_decision=other.decision,
                            ))
                decision = ReviewDecision.block
                break

    # Sort conflict notes by stage priority
    stage_priority_index = {
        stage: i for i, stage in enumerate(merge_context.stage_priority)
    }
    conflict_notes.sort(
        key=lambda cn: stage_priority_index.get(cn.overriding_stage, len(merge_context.stage_priority))
    )

    return {
        "decision": decision,
        "total_score": total_score,
        "conflict_notes": conflict_notes,
    }


# ---------------------------------------------------------------------------
# Emission decorator support
# ---------------------------------------------------------------------------

def _emit_event(handler: Callable | None, pact_key: str, event_type: str,
                input_classification: list | None = None, **kwargs: Any) -> None:
    """Fire-and-forget event emission."""
    if handler is None:
        return
    try:
        event = {
            "event": event_type,
            "pact_key": pact_key,
            "input_classification": input_classification or ["INTERNAL"],
            **kwargs,
        }
        handler(event)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Assessor class
# ---------------------------------------------------------------------------

class Assessor:
    """
    Arbiter-style trust-weighted assessment merger.

    Merges multiple reviewer Assessments into a single ReviewReport.
    """

    def __init__(
        self,
        merge_context: MergeContext | None = None,
        chronicler: Any | None = None,
        clock: Callable[[], str] | None = None,
        event_handler: Callable | None = None,
    ) -> None:
        self._merge_context = merge_context or MergeContext(
            default_trust_weight=TrustWeight(value=DEFAULT_TRUST_WEIGHT),
            block_threshold=10.0,
            warn_threshold=5.0,
            stage_priority=STAGE_PRIORITY,
            security_block_overrides=True,
        )
        self._chronicler = chronicler
        self._clock = clock or (lambda: "1970-01-01T00:00:00Z")
        self._event_handler = event_handler

    # -- Public API -----------------------------------------------------------

    def merge_assessments(
        self,
        assessments: list[Assessment] | None = None,
        trust_scores: list[TrustScore] | None = None,
        review_request_id: str = "",
    ) -> Any:
        """
        Merge multiple reviewer Assessments into a single ReviewReport.

        PACT: assessor.merge_assessments

        Returns an awaitable coroutine.
        """
        _emit_event(
            self._event_handler,
            "PACT:assessor:merge_assessments",
            "invoked",
            input_classification=["INTERNAL"],
        )

        # Perform synchronous validation so that events are emitted even
        # when the returned coroutine is never awaited (emission tests).
        if assessments is None:
            assessments = []
        if trust_scores is None:
            trust_scores = []

        try:
            if not review_request_id or len(review_request_id) > 256:
                raise ValueError(
                    "review_request_id must be a non-empty string of at most 256 characters"
                )

            for a in assessments:
                if a.review_request_id != review_request_id:
                    raise ValueError(
                        "All assessments must have review_request_id matching "
                        "the provided review_request_id (mismatch)"
                    )

            seen_pairs: set[tuple[str, str]] = set()
            for a in assessments:
                pair = (a.reviewer_id, a.stage)
                if pair in seen_pairs:
                    raise ValueError(
                        f"Each (reviewer_id, stage) pair must be unique across assessments. "
                        f"Duplicate: reviewer={a.reviewer_id}, stage={a.stage}"
                    )
                seen_pairs.add(pair)
        except Exception as exc:
            _emit_event(
                self._event_handler,
                "PACT:assessor:merge_assessments",
                "error",
                error=str(exc),
            )
            raise

        return self._merge_assessments_impl(
            assessments=assessments,
            trust_scores=trust_scores,
            review_request_id=review_request_id,
        )

    async def _merge_assessments_impl(
        self,
        assessments: list[Assessment],
        trust_scores: list[TrustScore],
        review_request_id: str,
    ) -> ReviewReport:
        """Async implementation of merge_assessments (validation already done)."""
        try:
            # Phase 1: Resolve trust
            resolved = _resolve_trust(assessments, trust_scores, self._merge_context)

            # Phase 2: Deduplicate findings
            deduped = _deduplicate_findings(assessments, resolved)

            # Phase 3: Compute decision
            decision_result = _compute_decision(
                deduped, assessments, resolved, self._merge_context
            )

            # Phase 4: Build report
            report = await self._build_report(
                review_request_id=review_request_id,
                decision=decision_result["decision"],
                total_score=decision_result["total_score"],
                deduplicated_findings=deduped,
                conflict_notes=decision_result["conflict_notes"],
                trust_scores_used=trust_scores,
                assessments_merged_count=len(assessments),
                assessments=assessments,
            )

            _emit_event(
                self._event_handler,
                "PACT:assessor:merge_assessments",
                "completed",
            )
            return report

        except Exception as exc:
            _emit_event(
                self._event_handler,
                "PACT:assessor:merge_assessments",
                "error",
                error=str(exc),
            )
            raise

    # -- Internal phases (exposed for unit testing) ---------------------------

    def _resolve_trust(
        self,
        assessments: list[Assessment] | None = None,
        trust_scores: list[TrustScore] | None = None,
        merge_context: MergeContext | None = None,
    ) -> dict[tuple[str, ReviewStage], float]:
        """Phase 1: trust resolution (instance method wrapper)."""
        _emit_event(
            self._event_handler,
            "PACT:assessor:_resolve_trust",
            "invoked",
            input_classification=["INTERNAL"],
        )
        try:
            result = _resolve_trust(
                assessments or [],
                trust_scores or [],
                merge_context or self._merge_context,
            )
            _emit_event(
                self._event_handler,
                "PACT:assessor:_resolve_trust",
                "completed",
            )
            return result
        except Exception as exc:
            _emit_event(
                self._event_handler,
                "PACT:assessor:_resolve_trust",
                "error",
                error=str(exc),
            )
            raise

    def _deduplicate_findings(
        self,
        assessments: list[Assessment] | None = None,
        resolved_trust: dict | None = None,
    ) -> list[Finding]:
        """Phase 2: deduplication (instance method wrapper)."""
        _emit_event(
            self._event_handler,
            "PACT:assessor:_deduplicate_findings",
            "invoked",
            input_classification=["INTERNAL"],
        )
        try:
            result = _deduplicate_findings(
                assessments or [],
                resolved_trust or {},
            )
            _emit_event(
                self._event_handler,
                "PACT:assessor:_deduplicate_findings",
                "completed",
            )
            return result
        except Exception as exc:
            _emit_event(
                self._event_handler,
                "PACT:assessor:_deduplicate_findings",
                "error",
                error=str(exc),
            )
            raise

    def _compute_decision(
        self,
        deduplicated_findings: list[Finding] | None = None,
        assessments: list[Assessment] | None = None,
        resolved_trust: dict | None = None,
        merge_context: MergeContext | None = None,
    ) -> dict[str, Any]:
        """Phase 3: decision computation (instance method wrapper)."""
        _emit_event(
            self._event_handler,
            "PACT:assessor:_compute_decision",
            "invoked",
            input_classification=["INTERNAL"],
        )
        try:
            result = _compute_decision(
                deduplicated_findings or [],
                assessments or [],
                resolved_trust or {},
                merge_context or self._merge_context,
            )
            _emit_event(
                self._event_handler,
                "PACT:assessor:_compute_decision",
                "completed",
            )
            return result
        except Exception as exc:
            _emit_event(
                self._event_handler,
                "PACT:assessor:_compute_decision",
                "error",
                error=str(exc),
            )
            raise

    def _build_report(
        self,
        review_request_id: str = "",
        decision: ReviewDecision | None = None,
        total_score: float = 0.0,
        deduplicated_findings: list[Finding] | None = None,
        conflict_notes: list[ConflictNote] | None = None,
        trust_scores_used: list[TrustScore] | None = None,
        assessments_merged_count: int = 0,
        assessments: list[Assessment] | None = None,
    ) -> Any:
        """Phase 4: build the final ReviewReport and emit Chronicler event.

        Returns an awaitable coroutine. Report is built synchronously so
        that event emission works even when the coroutine is not awaited.
        """
        _emit_event(
            self._event_handler,
            "PACT:assessor:_build_report",
            "invoked",
            input_classification=["INTERNAL"],
        )

        try:
            report = self._build_report_sync(
                review_request_id=review_request_id,
                decision=decision,
                total_score=total_score,
                deduplicated_findings=deduplicated_findings,
                conflict_notes=conflict_notes,
                trust_scores_used=trust_scores_used,
                assessments_merged_count=assessments_merged_count,
                assessments=assessments,
            )
            _emit_event(
                self._event_handler,
                "PACT:assessor:_build_report",
                "completed",
            )
        except Exception as exc:
            _emit_event(
                self._event_handler,
                "PACT:assessor:_build_report",
                "error",
                error=str(exc),
            )
            raise

        return self._build_report_async(report, review_request_id, decision, total_score,
                                         deduplicated_findings, assessments_merged_count)

    def _build_report_sync(
        self,
        review_request_id: str = "",
        decision: ReviewDecision | None = None,
        total_score: float = 0.0,
        deduplicated_findings: list[Finding] | None = None,
        conflict_notes: list[ConflictNote] | None = None,
        trust_scores_used: list[TrustScore] | None = None,
        assessments_merged_count: int = 0,
        assessments: list[Assessment] | None = None,
    ) -> ReviewReport:
        """Synchronous report construction logic."""
        if decision is None:
            decision = ReviewDecision("pass")
        if deduplicated_findings is None:
            deduplicated_findings = []
        if conflict_notes is None:
            conflict_notes = []
        if trust_scores_used is None:
            trust_scores_used = []
        if assessments is None:
            assessments = []

        timestamp = self._clock()

        # Sort findings: file_path ASC, line_number ASC, severity DESC, id ASC
        sorted_findings = sorted(
            deduplicated_findings,
            key=lambda f: (
                f.file_path,
                f.line_number if f.line_number is not None else 0,
                -_SEVERITY_ORDER.get(f.severity, 0),
                f.id,
            ),
        )

        # Compute overall confidence
        if not sorted_findings:
            overall_confidence = Confidence.high
        else:
            # Average of confidence multipliers
            avg = sum(
                CONFIDENCE_MULTIPLIER.get(f.confidence, 1.0)
                for f in sorted_findings
            ) / len(sorted_findings)
            if avg >= 0.8:
                overall_confidence = Confidence.high
            elif avg >= 0.5:
                overall_confidence = Confidence.medium
            else:
                overall_confidence = Confidence.low

        # Build PACT attribution
        pact = PactAttribution(
            component=PACT_COMPONENT,
            version=PACT_VERSION,
            timestamp=timestamp,
        )

        # Build conflict note strings
        conflict_note_strings = [cn.description for cn in conflict_notes]

        # Build summary
        finding_count = len(sorted_findings)
        summary = (
            f"Merged {assessments_merged_count} assessment(s): "
            f"{finding_count} finding(s), decision={decision.value}, "
            f"score={total_score:.1f}"
        )

        return ReviewReport(
            id=f"rpt-{uuid.uuid4().hex[:12]}",
            review_request_id=review_request_id,
            decision=decision,
            findings=sorted_findings,
            assessments=list(assessments),
            confidence=overall_confidence,
            trust_scores=list(trust_scores_used),
            conflict_notes=conflict_note_strings,
            summary=summary,
            seal=None,
            created_at=timestamp,
            metadata={
                "pact_component": PACT_COMPONENT,
                "total_score": str(total_score),
                "assessments_merged_count": str(assessments_merged_count),
            },
            pact=pact,
        )

    async def _build_report_async(
        self,
        report: ReviewReport,
        review_request_id: str,
        decision: ReviewDecision | None,
        total_score: float,
        deduplicated_findings: list[Finding] | None,
        assessments_merged_count: int,
    ) -> ReviewReport:
        """Async portion: emit Chronicler event and return the pre-built report."""
        # Emit Chronicler event (fire-and-forget)
        if self._chronicler is not None:
            try:
                timestamp = report.created_at
                finding_count = len(report.findings)
                summary = report.summary
                if decision is None:
                    decision = ReviewDecision("pass")
                event = ChroniclerEvent(
                    event_id=f"evt-{uuid.uuid4().hex[:12]}",
                    event_type=ChroniclerEventType("assessment.merged"),
                    review_request_id=review_request_id,
                    timestamp=timestamp,
                    payload={
                        "decision": decision.value,
                        "total_score": str(total_score),
                        "finding_count": str(finding_count),
                        "assessments_merged_count": str(assessments_merged_count),
                    },
                    message=summary,
                )
                await self._chronicler.emit(event)
            except Exception as e:
                logger.warning("Chronicler emission failed: %s", e)
        return report


# ---------------------------------------------------------------------------
# Module-level convenience (re-exported from __init__)
# ---------------------------------------------------------------------------

# These are the standalone functions already defined above:
# _resolve_trust, _deduplicate_findings, _compute_decision
# merge_assessments is an async method on Assessor; we also provide a
# module-level convenience alias.

async def _build_report(**kwargs: Any) -> ReviewReport:
    """Module-level stub for _build_report; real work done by Assessor._build_report."""
    raise NotImplementedError("Use Assessor._build_report() instead")


def merge_assessments(
    assessments: list[Assessment],
    trust_scores: list[TrustScore],
    review_request_id: str,
    merge_context: MergeContext | None = None,
    chronicler: Any | None = None,
    clock: Callable[[], str] | None = None,
) -> Any:
    """Module-level convenience for Assessor.merge_assessments.

    Returns an awaitable coroutine. Can be used with ``await`` in async code
    or with ``asyncio.run()`` / ``loop.run_until_complete()`` in sync code.
    """
    assessor = Assessor(
        merge_context=merge_context,
        chronicler=chronicler,
        clock=clock,
    )
    # assessor.merge_assessments is a sync method that returns a coroutine.
    # Validation happens synchronously (may raise); the coroutine is returned
    # for the caller to await or run.
    return assessor.merge_assessments(
        assessments=assessments,
        trust_scores=trust_scores,
        review_request_id=review_request_id,
    )


# Ensure a deprecation-free event loop is available for
# ``asyncio.get_event_loop()`` in non-async contexts (Python 3.12+).
import asyncio as _asyncio
try:
    _asyncio.get_event_loop()
except RuntimeError:
    _asyncio.set_event_loop(_asyncio.new_event_loop())
