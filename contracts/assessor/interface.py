# === Assessment Merger & Trust Scoring (assessor) v1 ===
#  Dependencies: schemas, chronicle, config, circuit
# Merges multiple reviewer Assessments into a single ReviewReport using Arbiter trust-weighted scoring. Conflict resolution: security BLOCK overrides style PASS with explanation; configurable priority ordering. Per-finding confidence scores derived from reviewer trust weight × finding confidence. Deduplicates overlapping findings across reviewers. Produces final ReviewDecision (block/warn/pass) based on configurable thresholds. Emits assessment.merged Chronicler event via fire-and-forget callback.

# Module invariants:
#   - All data models are frozen (Pydantic frozen=True); no mutation after construction
#   - The Assessor is constructed with a valid MergeContext where block_threshold >= warn_threshold >= 0.0
#   - The injected clock callable always returns a valid ISO 8601 timestamp string
#   - ChroniclerEmitter failures are always caught and logged; they never propagate to callers
#   - PACT_COMPONENT constant is always 'assessor' and is embedded in every ReviewReport and ChroniclerEvent
#   - DEFAULT_TRUST_WEIGHT is 0.5 and is used as the fallback when no explicit TrustScore matches a (reviewer_id, stage) pair
#   - SEVERITY_SCORE maps info=1.0, warning=3.0, error=7.0, critical=15.0
#   - STAGE_PRIORITY ordering is [security, correctness, architecture, style] from highest to lowest priority
#   - Finding sort order is deterministic: (file_path ASC, line_number ASC, severity DESC, id ASC)
#   - Conflict notes sort order follows stage priority: higher priority stages appear first
#   - Deduplication uses composite key (hunk_id, file_path, line_number, rule_id); within a duplicate group the highest severity finding is kept
#   - For deduplicated findings, confidence is boosted to min(1.0, max_contributing_trust_weight × original_confidence)
#   - Empty assessments input produces a PASS decision with no findings, total_score=0.0, and computed_confidence=1.0
#   - A security-stage BLOCK categorical override (when enabled) takes absolute precedence over score-based thresholds
#   - Each (reviewer_id, stage) pair must be unique across the input assessments list

class Severity(Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class ReviewDecision(Enum):
    """Final decision on a pull request review: block merging, warn, or pass."""
    block = "block"
    warn = "warn"
    pass = "pass"

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

ReviewRequestId = primitive  # Non-empty string identifier for a review request, used to correlate assessments, reports, and Chronicler events.

ReviewerId = primitive  # Non-empty identifier for a reviewer instance, used as a key for trust-score matching.

TrustWeight = primitive  # A trust weight value in the range [0.0, 1.0] representing the relative reliability of a reviewer.

ConfidenceScore = primitive  # A confidence score in the range [0.0, 1.0] representing certainty in a finding or report.

class FindingDeduplicationKey:
    """Composite key used to identify duplicate findings across reviewers. Two findings with the same key are considered overlapping."""
    hunk_id: str                             # required, Identifier of the diff hunk containing the finding.
    file_path: str                           # required, length(min=1,max=1024), Relative file path where the finding was detected.
    line_number: int                         # required, range(min=1), 1-based line number of the finding.
    rule_id: str                             # required, length(min=1,max=256), Identifier of the rule that triggered the finding.

class Finding:
    """A single issue found by a reviewer in a specific hunk."""
    id: str                                  # required, Unique finding identifier.
    hunk_id: str                             # required, ID of the DiffHunk this finding applies to.
    file_path: str                           # required, File path where the finding was detected.
    line_number: Optional[int] = null        # optional, Specific line number if applicable.
    severity: Severity                       # required, Severity of the finding.
    confidence: Confidence                   # required, Reviewer confidence in this finding.
    title: str                               # required, Short human-readable title of the finding.
    description: str                         # required, Detailed explanation of the issue.
    suggestion: Optional[str] = null         # optional, Suggested fix or remediation.
    rule_id: str                             # required, Identifier of the rule or pattern that triggered this finding.
    stage: ReviewStage                       # required, Which review stage produced this finding.

class TrustScore:
    """Arbiter trust weight for a reviewer agent, used in weighted assessment merging."""
    reviewer_id: str                         # required, Identifier of the reviewer this score applies to.
    stage: ReviewStage                       # required, Stage the reviewer operates in.
    weight: float                            # required, range(0.0 <= value <= 1.0), Trust weight in range [0.0, 1.0].
    accepted_count: int                      # required, Number of findings from this reviewer that humans accepted.
    dismissed_count: int                     # required, Number of findings from this reviewer that humans dismissed.
    updated_at: str                          # required, ISO-8601 timestamp of last trust score update.

class Assessment:
    """A single reviewer's complete assessment of the diff hunks it was given."""
    id: str                                  # required, Unique assessment identifier.
    review_request_id: str                   # required, ID of the ReviewRequest this assessment responds to.
    stage: ReviewStage                       # required, The review stage this assessment covers.
    reviewer_id: str                         # required, Identifier of the reviewer agent that produced this assessment.
    decision: ReviewDecision                 # required, This reviewer's overall decision.
    findings: list[Finding]                  # required, List of findings from this reviewer.
    confidence: Confidence                   # required, Overall confidence of this assessment.
    is_partial: bool                         # required, True if the reviewer failed/timed out and this is a degraded result.
    error_message: Optional[str] = null      # optional, Error message if the reviewer encountered an issue.
    duration_ms: int                         # required, Time in milliseconds the reviewer took to produce this assessment.
    created_at: str                          # required, ISO-8601 timestamp of assessment creation.

class ConflictNote:
    """Documents a conflict between reviewer assessments and the resolution applied."""
    description: str                         # required, Human-readable description of the conflict and its resolution.
    overriding_stage: ReviewStage            # required, The stage whose assessment took priority.
    overridden_stage: ReviewStage            # required, The stage whose assessment was overridden.
    overriding_decision: ReviewDecision      # required, The decision that was kept.
    overridden_decision: ReviewDecision      # required, The decision that was overridden.

class PactAttribution:
    """PACT governance attribution metadata embedded in every public output for Sentinel traceability."""
    component: str                           # required, length(min=1), PACT component key identifying this module.
    version: int                             # required, range(min=1), Contract version number.
    timestamp: str                           # required, ISO 8601 timestamp of report generation.

class ReviewReport:
    """The final merged review report: all assessments combined with trust-weighted scoring and a tamper-proof seal."""
    id: str                                  # required, Unique report identifier.
    review_request_id: str                   # required, ID of the originating ReviewRequest.
    decision: ReviewDecision                 # required, Final merged decision.
    findings: list[Finding]                  # required, Deduplicated, merged findings from all reviewers.
    assessments: list[Assessment]            # required, All individual reviewer assessments that contributed.
    confidence: Confidence                   # required, Overall confidence of the merged report.
    trust_scores: list[TrustScore]           # required, Trust scores of all reviewers at the time of merge.
    conflict_notes: list[str]                # required, Explanations of any conflicts between reviewers and how they were resolved.
    summary: str                             # required, Human-readable summary of the review outcome.
    seal: Optional[TesseraSeal] = null       # optional, Tessera hash-chain seal over the report content, set after sealing.
    created_at: str                          # required, ISO-8601 timestamp of report creation.
    metadata: dict[str, str]                 # required, Arbitrary key-value metadata carried from ReviewRequest.

class MergeContext:
    """Internal frozen Pydantic model holding extracted configuration values relevant to the merge algorithm. Constructed from ExemplarConfig at Assessor instantiation."""
    default_trust_weight: TrustWeight        # required, Fallback trust weight when no explicit TrustScore is provided for a reviewer+stage.
    block_threshold: float                   # required, range(min=0.0), Aggregate score at or above which the final decision is BLOCK.
    warn_threshold: float                    # required, range(min=0.0), Aggregate score at or above which the final decision is WARN (below block_threshold).
    stage_priority: list                     # required, length(min=1), Ordered list of stages from highest to lowest priority for conflict resolution.
    security_block_overrides: bool           # required, If true, any security-stage BLOCK unconditionally forces the final decision to BLOCK.

class ChroniclerEvent:
    """A structured event emitted at review lifecycle boundaries for audit trail and story assembly."""
    event_id: str                            # required, Unique event identifier.
    event_type: ChroniclerEventType          # required, Well-known event type.
    review_request_id: str                   # required, ID of the ReviewRequest this event relates to.
    timestamp: str                           # required, ISO-8601 timestamp of when the event occurred.
    stage: Optional[ReviewStage] = null      # optional, Review stage this event relates to, if applicable.
    reviewer_id: Optional[str] = null        # optional, Reviewer agent ID if this event is reviewer-specific.
    payload: dict[str, str]                  # required, Arbitrary structured data associated with the event.
    message: str                             # required, Human-readable description of the event.

class SeverityScoreMap:
    """Module-level constant mapping Severity variants to numeric scores for weighted scoring."""
    info: float                              # required, Score for info-level findings.
    warning: float                           # required, Score for warning-level findings.
    error: float                             # required, Score for error-level findings.
    critical: float                          # required, Score for critical-level findings.

class ConfidenceScoreMap:
    """Module-level constant providing base confidence score multipliers used in the weighting formula."""
    low: float                               # required, Multiplier for low-confidence findings.
    medium: float                            # required, Multiplier for medium-confidence findings.
    high: float                              # required, Multiplier for high-confidence findings.

class Confidence(Enum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"

class ChroniclerEventType(Enum):
    """Well-known Chronicler event types emitted throughout the review lifecycle."""
    review.started = "review.started"
    stage.started = "stage.started"
    stage.complete = "stage.complete"
    assessment.merged = "assessment.merged"
    report.sealed = "report.sealed"
    review.complete = "review.complete"
    policy.violation = "policy.violation"
    pattern.detected = "pattern.detected"
    learning.recorded = "learning.recorded"

class TesseraSeal:
    """A hash-chain tamper-proof seal over serialized content, verifiable independently."""
    content_hash: str                        # required, SHA-256 hash of the canonical JSON content that was sealed.
    previous_hash: Optional[str] = null      # optional, Hash of the previous seal in the chain (null for first seal).
    chain_hash: str                          # required, SHA-256 hash of (content_hash + previous_hash), forming the chain link.
    sealed_at: str                           # required, ISO-8601 timestamp of when the seal was created.
    sealer_id: str                           # required, Identifier of the entity that created this seal.

async def merge_assessments(
    assessments: list,
    trust_scores: list,
    review_request_id: str,    # length(min=1,max=256)
) -> ReviewReport:
    """
    Merges multiple reviewer Assessments into a single ReviewReport using trust-weighted scoring, deduplication, conflict resolution, and categorical overrides. This is the sole public method of AssessorProtocol. Executes a 4-phase algorithm: (1) resolve trust scores for each assessment, (2) deduplicate findings by composite key, (3) compute decision from weighted scores and categorical overrides, (4) build deterministic ReviewReport and emit assessment.merged Chronicler event.

    Preconditions:
      - review_request_id is a non-empty string of at most 256 characters
      - All Assessment objects in assessments have review_request_id matching the provided review_request_id
      - Each Assessment contains a valid reviewer_id and stage
      - Each Finding within each Assessment has valid severity, confidence in [0.0, 1.0], and positive line_number
      - Each TrustScore has weight in [0.0, 1.0]
      - Assessor was constructed with valid MergeContext (block_threshold >= warn_threshold >= 0)

    Postconditions:
      - Returned ReviewReport.review_request_id == review_request_id
      - Returned ReviewReport.findings is sorted by (file_path ASC, line_number ASC, severity DESC, id ASC)
      - Returned ReviewReport.assessments_merged_count == len(assessments)
      - No duplicate findings exist in output: each composite key (hunk_id, file_path, line_number, rule_id) appears at most once
      - If any security-stage assessment has decision BLOCK and security_block_overrides is True, final decision is BLOCK
      - If total_score >= block_threshold, decision is BLOCK (unless overridden to a stricter categorical BLOCK)
      - If total_score >= warn_threshold and total_score < block_threshold, decision is WARN
      - If total_score < warn_threshold and no categorical override applies, decision is PASS
      - Each finding's confidence == min(1.0, max(contributing trust weights) × original confidence)
      - All conflict_notes are sorted by stage priority (highest priority stage first)
      - Returned ReviewReport.pact.component == 'assessor'
      - Returned ReviewReport.timestamp is the value returned by the injected clock
      - An assessment.merged ChroniclerEvent was emitted (fire-and-forget, failure does not affect return value)
      - If assessments is empty, decision is PASS, findings is empty, total_score is 0.0, computed_confidence is 1.0

    Errors:
      - invalid_review_request_id (ValueError): review_request_id is empty or exceeds 256 characters
          param: review_request_id
          detail: review_request_id must be a non-empty string of at most 256 characters
      - assessment_request_id_mismatch (ValueError): Any Assessment.review_request_id does not match the provided review_request_id
          param: assessments
          detail: All assessments must have review_request_id matching the provided review_request_id
      - invalid_trust_weight (ValueError): Any TrustScore.weight is outside the range [0.0, 1.0]
          param: trust_scores
          detail: All trust score weights must be in the range [0.0, 1.0]
      - invalid_finding_confidence (ValueError): Any Finding.confidence is outside the range [0.0, 1.0]
          param: assessments
          detail: All finding confidence scores must be in the range [0.0, 1.0]
      - chronicler_emission_failure (None): ChroniclerEmitter raises an exception during event emission. This is fire-and-forget: the error is logged but does not propagate.
          behavior: Logged and suppressed; ReviewReport is still returned successfully
      - duplicate_assessment_reviewer_stage (ValueError): Two or more assessments share the same (reviewer_id, stage) pair, indicating a duplicate submission
          param: assessments
          detail: Each (reviewer_id, stage) pair must be unique across assessments

    Side effects: none
    Idempotent: yes
    """
    ...

def _resolve_trust(
    assessments: list,
    trust_scores: list,
    merge_context: MergeContext,
) -> dict:
    """
    Phase 1: Matches each Assessment to its TrustScore by (reviewer_id, stage) composite key. Falls back to MergeContext.default_trust_weight if no explicit TrustScore is found. Returns a mapping from (reviewer_id, stage) to resolved TrustWeight.

    Preconditions:
      - All assessments have valid reviewer_id and stage
      - All trust_scores have weight in [0.0, 1.0]
      - merge_context.default_trust_weight is in [0.0, 1.0]

    Postconditions:
      - Returned dict has an entry for every unique (reviewer_id, stage) pair in assessments
      - Every value in returned dict is a float in [0.0, 1.0]
      - If an explicit TrustScore exists for (reviewer_id, stage), that weight is used
      - If no explicit TrustScore exists, merge_context.default_trust_weight is used

    Side effects: none
    Idempotent: yes
    """
    ...

def _deduplicate_findings(
    assessments: list,
    resolved_trust: dict,
) -> list:
    """
    Phase 2: Deduplicates findings across all assessments using composite key (hunk_id, file_path, line_number, rule_id). For each group of duplicates, keeps the finding with the highest severity. Boosts the kept finding's confidence to min(1.0, max_trust_weight_among_contributors × original_confidence). Populates contributing_reviewers list on deduplicated findings.

    Preconditions:
      - resolved_trust contains entries for all (reviewer_id, stage) pairs present in assessments
      - All findings have valid composite key fields (non-empty hunk_id, file_path, rule_id; positive line_number)

    Postconditions:
      - No two findings in the output share the same (hunk_id, file_path, line_number, rule_id)
      - For each group of duplicates, the output finding has the maximum severity from the group
      - Each output finding's confidence is min(1.0, max_trust_weight × original_confidence)
      - Each output finding's contributing_reviewers lists all reviewer_ids that reported that finding
      - Output count <= total input finding count across all assessments

    Side effects: none
    Idempotent: yes
    """
    ...

def _compute_decision(
    deduplicated_findings: list,
    assessments: list,
    resolved_trust: dict,
    merge_context: MergeContext,
) -> dict:
    """
    Phase 3: Computes the final ReviewDecision from deduplicated findings and resolved trust. Scores each finding as SEVERITY_SCORE[severity] × trust_weight × confidence, sums all scores to total_score. Applies categorical override: if security_block_overrides is enabled and any security-stage assessment has decision BLOCK, final decision is BLOCK regardless of score. Otherwise, compares total_score to block_threshold and warn_threshold from MergeContext. Also detects and records ConflictNotes when higher-priority stage decisions override lower-priority stage decisions.

    Preconditions:
      - deduplicated_findings contains no duplicate composite keys
      - resolved_trust covers all (reviewer_id, stage) pairs in assessments
      - merge_context.block_threshold >= merge_context.warn_threshold >= 0

    Postconditions:
      - Returned dict contains keys: 'decision' (ReviewDecision), 'total_score' (float >= 0), 'conflict_notes' (list[ConflictNote])
      - If security_block_overrides and any security assessment decision is BLOCK, decision is BLOCK
      - If total_score >= block_threshold (without categorical override), decision is BLOCK
      - If total_score >= warn_threshold and < block_threshold, decision is WARN
      - If total_score < warn_threshold and no categorical override, decision is PASS
      - conflict_notes are ordered by stage priority (highest priority first)

    Side effects: none
    Idempotent: yes
    """
    ...

async def _build_report(
    review_request_id: str,
    decision: ReviewDecision,
    total_score: float,
    deduplicated_findings: list,
    conflict_notes: list,
    trust_scores_used: list,
    assessments_merged_count: int,
) -> ReviewReport:
    """
    Phase 4: Constructs the final ReviewReport from computed results. Sorts findings deterministically by (file_path ASC, line_number ASC, severity DESC, id ASC). Attaches PACT attribution with component='assessor', contract version, and injected clock timestamp. Emits assessment.merged ChroniclerEvent via ChroniclerEmitter (fire-and-forget). Returns the frozen ReviewReport.

    Preconditions:
      - review_request_id is non-empty
      - total_score >= 0.0
      - assessments_merged_count >= 0

    Postconditions:
      - Returned ReviewReport.findings sorted by (file_path ASC, line_number ASC, severity DESC, id ASC)
      - Returned ReviewReport.pact.component == 'assessor'
      - Returned ReviewReport.pact.version == contract version (1)
      - Returned ReviewReport.timestamp is from injected clock
      - An assessment.merged ChroniclerEvent was emitted (failure suppressed)

    Errors:
      - chronicler_emission_failure (None): ChroniclerEmitter raises during event emission
          behavior: Logged and suppressed; report returned successfully

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['Severity', 'ReviewDecision', 'ReviewStage', 'FindingDeduplicationKey', 'Finding', 'TrustScore', 'Assessment', 'ConflictNote', 'PactAttribution', 'ReviewReport', 'MergeContext', 'ChroniclerEvent', 'SeverityScoreMap', 'ConfidenceScoreMap', 'Confidence', 'ChroniclerEventType', 'TesseraSeal', 'merge_assessments', '_resolve_trust', '_deduplicate_findings', '_compute_decision', '_build_report']
