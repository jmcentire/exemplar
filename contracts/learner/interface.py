# === Apprentice Learning Module (learner) v1 ===
#  Dependencies: schemas, config, chronicle
# Shadow mode implementation for the Apprentice learning system. Accepts AI review output and human review decisions (as JSON input), compares them, records acceptance/dismissal rates per reviewer and per finding type. Stores learning state in JSON files (.exemplar/learner/). Feeds acceptance patterns back as trust score adjustments using weight = base_weight * (accepted/total) clamped [0.1, 1.0]. Phase progression tracking (shadow → canary → primary) based on configurable accuracy thresholds with no regression. Stigmergy integration reports recurring patterns (e.g., 'SecurityReviewer false-positive rate on test files is 40%') to pattern store. All I/O is async. Fire-and-forget for optional integrations (chronicler, stigmergy). PACT keys on all public methods.

# Module invariants:
#   - LearnerPhase transitions are monotonic: shadow → canary → primary. No regression to a prior phase is permitted.
#   - Trust adjustments are only produced when total_count >= MIN_OBSERVATIONS (default 10) for the given reviewer+rule combination (cold-start protection).
#   - Trust weight is always clamped to [0.1, 1.0] and rounded to 4 decimal places for deterministic output.
#   - All file writes use atomic write semantics: write to a temporary file then os.replace to the target path. No partial writes are observable.
#   - Single-writer concurrency model: only one learner instance writes to .exemplar/learner/ at a time.
#   - LearnerState.records list in records.json is append-only; existing records are never modified or deleted.
#   - Phase transition thresholds are read from ApprenticeConfig and never hard-coded.
#   - All public methods carry PACT keys for Sentinel attribution.
#   - Chronicler and stigmergy integrations are fire-and-forget: unreachable services never block or raise to callers.

class LearnerPhase(Enum):
    """Apprentice learning phase progression stage."""
    shadow = "shadow"
    canary = "canary"
    primary = "primary"

class HumanDecision(Enum):
    """The human reviewer's disposition on an AI-generated finding."""
    accepted = "accepted"
    dismissed = "dismissed"
    modified = "modified"

class PatternKind(Enum):
    """Classification of a detected recurring pattern for stigmergy reporting."""
    high_false_positive_rate = "high_false_positive_rate"
    high_acceptance_rate = "high_acceptance_rate"
    category_bias = "category_bias"
    file_pattern_bias = "file_pattern_bias"
    severity_mismatch = "severity_mismatch"

ReviewerId = primitive  # Canonical reviewer identifier string. Must be non-empty and match the pattern used in schemas.ReviewerId.

RuleId = primitive  # Canonical rule identifier string. Non-empty, dot-separated namespace.

TrustWeight = primitive  # A trust weight value clamped to [0.1, 1.0] and rounded to 4 decimal places.

AcceptanceRate = primitive  # A rate value in [0.0, 1.0] representing the fraction of accepted findings.

MinObservations = primitive  # Minimum number of observations before trust adjustments are applied. Default 10.

FilePath = primitive  # A validated file path string.

class PactKey:
    """PACT attribution key embedded in public methods for Sentinel tracing."""
    namespace: str                           # required, regex(^EXEMPLAR\.CLI$), Module-level PACT namespace, always 'EXEMPLAR.CLI'
    function_key: str                        # required, regex(^EXEMPLAR\.CLI\.[a-z_]+$), Per-function PACT key, e.g. 'EXEMPLAR.CLI.handle_review'

class HumanDecisionInput:
    """Validated input schema for a single human feedback decision on an AI-generated finding. Frozen Pydantic model."""
    finding_id: str                          # required, length(min=1,max=256), Unique identifier of the AI-generated finding being adjudicated.
    reviewer_id: ReviewerId                  # required, Identifier of the AI reviewer that produced the finding.
    rule_id: RuleId                          # required, The rule that triggered the finding.
    decision: HumanDecision                  # required, The human's disposition on this finding.
    file_path: FilePath                      # required, Path of the file the finding pertains to.
    severity: str                            # required, regex(^(critical|high|medium|low|info)$), Severity of the original finding (maps to schemas.Severity).
    review_stage: str                        # required, length(min=1,max=64), The review stage in which the finding was produced (maps to schemas.ReviewStage).
    comment: str = None                      # optional, Optional human-provided rationale for the decision.
    timestamp_iso: str = None                # optional, regex(^$|^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}), ISO 8601 timestamp of the decision. If omitted, current UTC time is used.

class LearningRecord:
    """A single learning observation: an AI finding paired with human decision (accepted or dismissed)."""
    record_id: str                           # required, Unique record identifier.
    finding_id: str                          # required, ID of the Finding this record is about.
    reviewer_id: str                         # required, Reviewer that produced the finding.
    stage: ReviewStage                       # required, Stage the finding belongs to.
    rule_id: str                             # required, Rule ID of the finding.
    severity: Severity                       # required, Severity of the original finding.
    accepted: bool                           # required, True if the human accepted/agreed with the finding, false if dismissed.
    human_comment: Optional[str] = null      # optional, Optional comment from the human reviewer.
    recorded_at: str                         # required, ISO-8601 timestamp of when this learning was recorded.

class ReviewerRuleStats:
    """Aggregated acceptance/dismissal statistics for a specific reviewer + rule_id + review_stage combination. Frozen Pydantic model."""
    reviewer_id: ReviewerId                  # required, The AI reviewer identifier.
    rule_id: RuleId                          # required, The rule identifier.
    review_stage: str                        # required, The review stage.
    accepted_count: int                      # required, range(min=0), Number of times findings for this reviewer+rule+stage were accepted.
    dismissed_count: int                     # required, range(min=0), Number of times findings were dismissed.
    modified_count: int                      # required, range(min=0), Number of times findings were modified (accepted with changes).
    total_count: int                         # required, range(min=0), Total observations (accepted + dismissed + modified).
    acceptance_rate: AcceptanceRate          # required, Fraction of findings accepted (including modified). Computed as (accepted + modified) / total.

class ReviewerStats:
    """Coarse aggregated statistics for a reviewer across all rules within a review stage. Frozen Pydantic model."""
    reviewer_id: ReviewerId                  # required, The AI reviewer identifier.
    review_stage: str                        # required, The review stage.
    accepted_count: int                      # required, range(min=0), Total accepted findings.
    dismissed_count: int                     # required, range(min=0), Total dismissed findings.
    modified_count: int                      # required, range(min=0), Total modified findings.
    total_count: int                         # required, range(min=0), Total observations.
    acceptance_rate: AcceptanceRate          # required, Overall acceptance rate for this reviewer+stage.
    rule_stats: list                         # required, Per-rule breakdown.

class PhaseTransition:
    """A record of a phase transition event. Frozen Pydantic model."""
    from_phase: LearnerPhase                 # required, The phase before transition.
    to_phase: LearnerPhase                   # required, The phase after transition.
    timestamp_iso: str                       # required, ISO 8601 timestamp of the transition.
    acceptance_rate_at_transition: AcceptanceRate # required, The overall acceptance rate that triggered the transition.
    total_observations: int                  # required, range(min=0), Total observations at the time of transition.

class PhaseState:
    """Tracks the current phase and full transition history. Frozen Pydantic model."""
    current_phase: LearnerPhase              # required, The current operational phase.
    transition_history: list                 # required, Ordered list of PhaseTransition records.
    entered_current_phase_iso: str           # required, ISO 8601 timestamp when the current phase was entered.

class LearnerState:
    """Top-level persisted state container for the learner. Written atomically to .exemplar/learner/state.json. Frozen Pydantic model."""
    schema_version: int                      # required, range(min=1,max=100), Schema version for forward compatibility.
    phase_state: PhaseState                  # required, Current phase and transition history.
    reviewer_stats: list                     # required, List of ReviewerStats, one per reviewer+stage combination.
    reviewer_rule_stats: list                # required, List of ReviewerRuleStats, one per reviewer+rule+stage combination.
    total_records: int                       # required, range(min=0), Total number of LearningRecords persisted.
    last_updated_iso: str                    # required, ISO 8601 timestamp of the last state update.

class TrustScore:
    """Arbiter trust weight for a reviewer agent, used in weighted assessment merging."""
    reviewer_id: str                         # required, Identifier of the reviewer this score applies to.
    stage: ReviewStage                       # required, Stage the reviewer operates in.
    weight: float                            # required, range(0.0 <= value <= 1.0), Trust weight in range [0.0, 1.0].
    accepted_count: int                      # required, Number of findings from this reviewer that humans accepted.
    dismissed_count: int                     # required, Number of findings from this reviewer that humans dismissed.
    updated_at: str                          # required, ISO-8601 timestamp of last trust score update.

class StigmergySignal:
    """A recurring pattern signal detected by Stigmergy, recorded for cross-review pattern discovery."""
    signal_id: str                           # required, Unique signal identifier.
    pattern_key: str                         # required, Machine-readable key identifying the pattern (e.g., 'security.false_positive.test_files').
    description: str                         # required, Human-readable description of the detected pattern.
    occurrences: int                         # required, Number of times this pattern has been observed.
    first_seen_at: str                       # required, ISO-8601 timestamp of first observation.
    last_seen_at: str                        # required, ISO-8601 timestamp of most recent observation.
    reviewer_id: Optional[str] = null        # optional, Reviewer associated with the pattern, if applicable.
    stage: Optional[ReviewStage] = null      # optional, Stage associated with the pattern, if applicable.
    metadata: dict[str, str]                 # required, Additional context about the pattern.

class LearnerStatsReport:
    """A structured report of the learner's current state for CLI display and debugging."""
    current_phase: LearnerPhase              # required, The current operational phase.
    total_records: int                       # required, Total learning records persisted.
    overall_acceptance_rate: AcceptanceRate  # required, Aggregate acceptance rate across all reviewers.
    reviewer_stats: list                     # required, List of ReviewerStats.
    phase_state: PhaseState                  # required, Full phase state with transition history.
    active_trust_adjustments: int            # required, range(min=0), Number of reviewer+rule combinations with sufficient observations for trust adjustments.

class RecordDecisionResult:
    """Result returned from record_decision indicating what happened."""
    records_persisted: int                   # required, range(min=0), Number of learning records successfully persisted.
    stats_updated: bool                      # required, Whether aggregated stats were successfully updated.
    phase_changed: bool                      # required, Whether a phase transition occurred as a result of this recording.
    new_phase: LearnerPhase                  # required, The phase after recording (may be same as before).

class Severity(Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

async def record_decision(
    records: list,             # length(min=1,max=1000)
) -> RecordDecisionResult:
    """
    Accepts one or more LearningRecords, persists them to .exemplar/learner/records.json (append-only), updates aggregated ReviewerRuleStats and ReviewerStats in state.json, evaluates phase progression, and emits a learning.recorded ChroniclerEvent. Atomic file writes. PACT key: pact:learner:record_decision.

    Preconditions:
      - All records in the list must have unique record_id values.
      - All records must have valid reviewer_id, rule_id, and decision fields.
      - The .exemplar/learner/ directory must be writable.

    Postconditions:
      - All provided records are appended to records.json atomically.
      - Aggregated stats in state.json reflect the new records.
      - A learning.recorded ChroniclerEvent has been emitted (fire-and-forget).
      - If the new overall acceptance rate crosses a phase threshold, phase_changed is True and a phase.transition ChroniclerEvent is emitted.

    Errors:
      - duplicate_record_id (DuplicateRecordError): One or more record_id values already exist in records.json.
          duplicate_ids: Comma-separated list of duplicate record_id values.
      - storage_write_failure (StorageWriteError): Atomic write to records.json or state.json fails (disk full, permissions).
          path: The file path that failed.
          reason: OS-level error description.
      - invalid_record (ValidationError): One or more records fail Pydantic validation.
          details: Pydantic validation error details.
      - concurrent_write_detected (ConcurrentWriteError): Another writer is detected (lock file present or state.json modified since last read).
          detail: Description of the conflict.

    Side effects: Appends records to .exemplar/learner/records.json, Updates .exemplar/learner/state.json with new aggregated stats, Emits learning.recorded ChroniclerEvent (fire-and-forget), May emit phase.transition ChroniclerEvent if phase advances (fire-and-forget)
    Idempotent: no
    """
    ...

async def record_human_decisions(
    decisions: list,           # length(min=1,max=1000)
    base_weight: float = 1.0,  # range(min=0.1,max=1.0)
) -> RecordDecisionResult:
    """
    Convenience method that maps a list of HumanDecisionInput objects into LearningRecords (generating record_id and timestamp) and delegates to record_decision. PACT key: pact:learner:record_human_decisions.

    Preconditions:
      - All decisions must pass HumanDecisionInput validation.
      - The .exemplar/learner/ directory must be writable.

    Postconditions:
      - Each HumanDecisionInput is converted to a LearningRecord with a new UUID4 record_id.
      - record_decision is called with the converted records.
      - All postconditions of record_decision apply.

    Errors:
      - invalid_decision_input (ValidationError): One or more HumanDecisionInput objects fail Pydantic validation.
          details: Pydantic validation error details.
      - storage_write_failure (StorageWriteError): Delegated to record_decision.
          path: The file path that failed.
          reason: OS-level error description.

    Side effects: none
    Idempotent: no
    """
    ...

async def get_trust_adjustments(
    base_weight: float = 1.0,  # range(min=0.1,max=1.0)
    min_observations: int = 10, # range(min=1,max=10000)
) -> list:
    """
    Computes and returns trust score adjustments for all reviewer+rule+stage combinations that meet the minimum observation threshold. Weight formula: base_weight * (accepted_count / total_count) clamped to [0.1, 1.0], rounded to 4 decimal places. Cold-start protection: combinations with total_count < min_observations are excluded. PACT key: pact:learner:get_trust_adjustments.

    Preconditions:
      - LearnerState must be loadable from .exemplar/learner/state.json.

    Postconditions:
      - Returned list contains only TrustScore entries where observation_count >= min_observations.
      - Every weight in the returned TrustScore entries is in [0.1, 1.0] and rounded to 4 decimal places.
      - The list is deterministically ordered by (reviewer_id, rule_id, review_stage).

    Errors:
      - state_not_found (StateNotFoundError): state.json does not exist (no decisions have been recorded yet).
          path: .exemplar/learner/state.json
      - state_corruption (StateCorruptionError): state.json exists but fails Pydantic validation.
          path: .exemplar/learner/state.json
          details: Validation error details.

    Side effects: none
    Idempotent: yes
    """
    ...

async def check_phase_progression(
    config: dict,
) -> LearnerPhase:
    """
    Evaluates whether the current learner phase should advance based on ApprenticeConfig thresholds and overall acceptance rate. Phase transitions are monotonic (shadow→canary→primary, no regression). Emits a phase.transition ChroniclerEvent on transition. Returns the (possibly new) LearnerPhase. PACT key: pact:learner:check_phase_progression.

    Preconditions:
      - LearnerState must be loadable from .exemplar/learner/state.json.
      - config must contain shadow_to_canary_threshold and canary_to_primary_threshold as floats in [0.0, 1.0].
      - config must contain min_observations_for_phase as int >= 1.

    Postconditions:
      - If phase changes, state.json is updated atomically with the new phase and a PhaseTransition entry.
      - If phase changes, a phase.transition ChroniclerEvent is emitted (fire-and-forget).
      - Returned LearnerPhase is >= the phase before the call (monotonic).

    Errors:
      - state_not_found (StateNotFoundError): state.json does not exist.
          path: .exemplar/learner/state.json
      - invalid_config (ConfigurationError): Required threshold keys are missing or out of range in the config dict.
          details: Description of what is missing or invalid.
      - storage_write_failure (StorageWriteError): Atomic write to state.json fails during phase transition.
          path: .exemplar/learner/state.json
          reason: OS-level error description.

    Side effects: none
    Idempotent: yes
    """
    ...

async def detect_patterns(
    min_observations: int = 10, # range(min=1,max=10000)
    anomaly_threshold: float = 0.5, # range(min=0.0,max=1.0)
) -> list:
    """
    Scans aggregated ReviewerRuleStats for recurring anomalies (high false-positive rates, category biases, file pattern biases) and returns a list of StigmergySignal objects. Emits pattern.detected ChroniclerEvent for each signal. PACT key: pact:learner:detect_patterns.

    Preconditions:
      - LearnerState must be loadable from .exemplar/learner/state.json.

    Postconditions:
      - Returned signals only reference reviewer+rule combinations with total_count >= min_observations.
      - Each signal has a unique signal_id (UUID4).
      - pattern.detected ChroniclerEvent emitted for each signal (fire-and-forget).

    Errors:
      - state_not_found (StateNotFoundError): state.json does not exist.
          path: .exemplar/learner/state.json
      - state_corruption (StateCorruptionError): state.json fails validation.
          path: .exemplar/learner/state.json
          details: Validation error details.

    Side effects: none
    Idempotent: yes
    """
    ...

async def get_current_phase() -> LearnerPhase:
    """
    Returns the current LearnerPhase from persisted state. Read-only, no side effects beyond file read. PACT key: pact:learner:get_current_phase.

    Preconditions:
      - LearnerState must be loadable from .exemplar/learner/state.json, OR if state.json does not exist, returns LearnerPhase.shadow as the default.

    Postconditions:
      - Returns a valid LearnerPhase value.

    Errors:
      - state_corruption (StateCorruptionError): state.json exists but fails validation.
          path: .exemplar/learner/state.json
          details: Validation error details.

    Side effects: none
    Idempotent: yes
    """
    ...

async def should_apply_adjustments() -> bool:
    """
    Returns True if the current phase is canary or primary (i.e., trust adjustments should be applied to reviewer weights). Returns False in shadow phase. PACT key: pact:learner:should_apply_adjustments.

    Postconditions:
      - Returns True if and only if get_current_phase() returns canary or primary.
      - Returns False if state.json does not exist (defaults to shadow).

    Errors:
      - state_corruption (StateCorruptionError): state.json exists but fails validation.
          path: .exemplar/learner/state.json
          details: Validation error details.

    Side effects: none
    Idempotent: yes
    """
    ...

async def get_stats(
    min_observations: int = 10, # range(min=1,max=10000)
) -> LearnerStatsReport:
    """
    Returns a LearnerStatsReport summarizing current state for CLI display and debugging. Includes phase, total records, overall acceptance rate, per-reviewer stats, and number of active trust adjustments. PACT key: pact:learner:get_stats.

    Preconditions:
      - LearnerState must be loadable from .exemplar/learner/state.json.

    Postconditions:
      - Returned report reflects the current persisted state.
      - active_trust_adjustments counts only entries with total_count >= min_observations.

    Errors:
      - state_not_found (StateNotFoundError): state.json does not exist.
          path: .exemplar/learner/state.json
      - state_corruption (StateCorruptionError): state.json fails validation.
          path: .exemplar/learner/state.json
          details: Validation error details.

    Side effects: none
    Idempotent: yes
    """
    ...

async def initialize_state(
    storage_dir: str = .exemplar/learner, # length(min=1,max=4096)
) -> bool:
    """
    Creates the .exemplar/learner/ directory and initializes empty state.json and records.json if they do not already exist. Safe to call multiple times (idempotent). PACT key: pact:learner:initialize_state.

    Preconditions:
      - Parent directory of storage_dir must exist or be creatable.

    Postconditions:
      - storage_dir exists as a directory.
      - state.json exists with a valid empty LearnerState (phase=shadow, no stats, schema_version=1).
      - records.json exists with an empty JSON array.
      - Returns True if files were created, False if they already existed.

    Errors:
      - permission_denied (StorageWriteError): Cannot create directory or files due to OS permissions.
          path: The path that could not be created.
          reason: OS-level error description.
      - existing_state_corruption (StateCorruptionError): Files exist but are not valid JSON. Does NOT overwrite — returns error.
          path: The corrupt file path.
          details: Parse or validation error details.

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['LearnerPhase', 'HumanDecision', 'PatternKind', 'PactKey', 'HumanDecisionInput', 'LearningRecord', 'ReviewerRuleStats', 'ReviewerStats', 'PhaseTransition', 'PhaseState', 'LearnerState', 'TrustScore', 'StigmergySignal', 'LearnerStatsReport', 'RecordDecisionResult', 'Severity', 'ReviewStage', 'record_decision', 'DuplicateRecordError', 'StorageWriteError', 'ValidationError', 'ConcurrentWriteError', 'record_human_decisions', 'get_trust_adjustments', 'StateNotFoundError', 'StateCorruptionError', 'check_phase_progression', 'ConfigurationError', 'detect_patterns', 'get_current_phase', 'should_apply_adjustments', 'get_stats', 'initialize_state']
