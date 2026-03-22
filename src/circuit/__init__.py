"""Circuit component — Baton-style stage routing with circuit breakers."""
from circuit.circuit import (
    # Enums
    ReviewStage,
    Severity,
    Confidence,
    ReviewDecision,
    ClassificationLabel,
    FindingCategory,
    ChroniclerEventType,
    # Validated primitives
    PACTKey,
    StageTimeoutMs,
    # Domain data models
    DiffHunk,
    ReviewRequest,
    Finding,
    Assessment,
    # Circuit structural types
    ParallelGroup,
    CircuitConfig,
    ExecutionStep,
    ExecutionPlan,
    ChroniclerEvent,
    # Protocols
    ChroniclerEmitter,
    ClockProvider,
    ReviewerProtocol,
    # Errors
    CircuitConfigError,
    # PACT key constants
    PACT_CIRCUIT_INIT,
    PACT_CIRCUIT_RUN,
    PACT_CIRCUIT_RESOLVE_PLAN,
    PACT_CIRCUIT_INVOKE_REVIEWER,
    PACT_CIRCUIT_GET_TIMEOUT,
    PACT_CIRCUIT_GET_PLAN,
    # Main class
    BatonCircuitRouter,
)
