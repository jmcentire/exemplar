"""Apprentice Learning Module — public API re-exports."""

from learner.learner import (
    # Enums
    LearnerPhase,
    HumanDecision,
    PatternKind,
    Severity,
    ReviewStage,
    # Validated primitives
    ReviewerId,
    RuleId,
    TrustWeight,
    AcceptanceRate,
    MinObservations,
    FilePath,
    PactKey,
    # Data models
    HumanDecisionInput,
    LearningRecord,
    ReviewerRuleStats,
    ReviewerStats,
    PhaseTransition,
    PhaseState,
    LearnerState,
    TrustScore,
    StigmergySignal,
    LearnerStatsReport,
    RecordDecisionResult,
    # Errors
    DuplicateRecordError,
    StorageWriteError,
    ValidationError,
    ConcurrentWriteError,
    StateNotFoundError,
    StateCorruptionError,
    ConfigurationError,
    # Class wrapper
    Learner,
    # Functions
    record_decision,
    record_human_decisions,
    get_trust_adjustments,
    check_phase_progression,
    detect_patterns,
    get_current_phase,
    should_apply_adjustments,
    get_stats,
    initialize_state,
)
