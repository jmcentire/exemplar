# === Baton Circuit Router (circuit) v1 ===
#  Dependencies: schemas, reviewers.base
# Async circuit routing engine. Takes classified DiffHunks and routes them through configured review stages per CircuitConfig. Supports parallel execution of independent stages via asyncio.gather, sequential execution where ordering matters. Implements circuit-breaker pattern: a failing/timing-out reviewer produces a degraded Assessment (recorded as partial result) rather than crashing the pipeline. Emits Chronicler events at stage boundaries (stage.started, stage.complete). Returns ordered list of Assessments from all stages. Configurable timeout per stage. Deterministic output ordering matches CircuitConfig.stages list regardless of parallel execution timing.

# Module invariants:
#   - BatonCircuitRouter never propagates exceptions from reviewer invocations — all failures are absorbed into degraded Assessments with is_partial=True
#   - BatonCircuitRouter never propagates exceptions from ChroniclerEmitter.emit — all emission failures are caught and logged (fire-and-forget)
#   - The returned list of Assessments from run() always has exactly len(config.stages) elements, one per configured stage, in config.stages order
#   - No reviewer invocation exceeds its configured timeout — asyncio.wait_for enforces cancellation
#   - The ExecutionPlan is immutable after construction and determines all routing behavior
#   - Every stage in config.stages has a registered reviewer (enforced at construction time via CircuitConfigError)
#   - Every stage in every ParallelGroup is a member of config.stages (enforced at construction time)
#   - No ReviewStage appears in more than one ParallelGroup (enforced at construction time)
#   - PACT key constants are module-level: PACT_CIRCUIT_INIT, PACT_CIRCUIT_RUN, PACT_CIRCUIT_RESOLVE_PLAN, PACT_CIRCUIT_INVOKE_REVIEWER, PACT_CIRCUIT_GET_TIMEOUT, PACT_CIRCUIT_GET_PLAN
#   - All Pydantic models used by circuit are frozen=True (immutable after construction)
#   - Chronicler events include the PACT key of the emitting method for Sentinel attribution
#   - ClockProvider injection enables fully deterministic testing — no real time dependencies when clock is provided

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

StageTimeoutMs = primitive  # Timeout in milliseconds for a single reviewer stage invocation. Must be a positive integer between 100ms and 300000ms (5 minutes).

class ParallelGroup:
    """A group of ReviewStage values that may execute concurrently via asyncio.gather. All stages in a group must be present in CircuitConfig.stages. Frozen Pydantic model."""
    stages: list[ReviewStage]                # required, length(len(stages) >= 2), Stages in this parallel group. Must contain at least 2 stages (a single stage needs no parallelism). All must be members of CircuitConfig.stages.

class CircuitConfig:
    """Configuration for Baton circuit routing: stage ordering, parallelism, and timeouts."""
    stages: list[ReviewStage]                # required, Ordered list of review stages to execute.
    parallel_stages: list[list[ReviewStage]] # required, Groups of stages that can run in parallel. Each inner list runs concurrently.
    stage_timeout_ms: int                    # required, range(value > 0), Default timeout per stage in milliseconds.
    block_threshold: int                     # required, Minimum number of critical/high findings to trigger a block decision.
    warn_threshold: int                      # required, Minimum number of medium findings to trigger a warn decision.

class ExecutionStep:
    """A single step in the resolved execution plan. Either a single sequential stage or a parallel group. Internal type built at construction time."""
    stages: list[ReviewStage]                # required, length(len(stages) >= 1), One or more stages to execute in this step. If len > 1, stages execute concurrently via asyncio.gather.
    is_parallel: bool                        # required, True if this step executes its stages concurrently.

class ExecutionPlan:
    """The resolved execution plan: an ordered list of ExecutionSteps derived from CircuitConfig at construction time. Frozen Pydantic model."""
    steps: list[ExecutionStep]               # required, length(len(steps) >= 1), Ordered execution steps. Steps execute sequentially; stages within a parallel step execute concurrently.
    stage_order: list[ReviewStage]           # required, Canonical ordering of all stages, matching CircuitConfig.stages. Used to sort final Assessment list deterministically.

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

class ChroniclerEmitter:
    """Protocol (runtime_checkable) for Chronicler event emission. Implementations must provide an async emit method. Defined in circuit.py for decoupling from chronicle module."""
    emit: Callable[[ChroniclerEvent], Awaitable[None]] # required, Async method to emit a ChroniclerEvent. Implementations should be fire-and-forget safe.

class ClockProvider:
    """Protocol (runtime_checkable) for injectable time and ID generation. Allows deterministic testing by replacing real clocks with fixed values."""
    now_utc: Callable[[], str]               # required, Returns current UTC timestamp as ISO 8601 string ending in Z.
    monotonic_ms: Callable[[], int]          # required, Returns monotonic clock value in milliseconds for duration measurement.

class CircuitConfigError:
    """Exception raised at BatonCircuitRouter construction time when CircuitConfig validation fails. Subclass of Exception."""
    message: str                             # required, Human-readable description of the configuration error.
    missing_reviewers: list[ReviewStage] = [] # optional, Stages in config that have no registered reviewer. Empty if the error is not about missing reviewers.
    invalid_parallel_stages: list[ReviewStage] = [] # optional, Parallel group stages not found in config.stages. Empty if the error is not about parallel subset violation.

class ReviewRequest:
    """The output of intake: a complete review request containing parsed and classified hunks."""
    id: str                                  # required, Unique review request identifier.
    source: str                              # required, Source identifier (e.g., file path, PR URL, stdin).
    hunks: list[DiffHunk]                    # required, Parsed and classified diff hunks.
    file_paths: list[str]                    # required, Deduplicated list of all file paths in the diff.
    created_at: str                          # required, ISO-8601 timestamp of when the request was created.
    metadata: dict[str, str]                 # required, Arbitrary key-value metadata (PR number, branch, author, etc.).

class DiffHunk:
    """A single parsed hunk from a unified diff, with metadata and classification labels."""
    id: str                                  # required, Unique identifier for this hunk (deterministic from content).
    file_path: str                           # required, Relative file path the hunk belongs to.
    start_line_old: int                      # required, Starting line number in the old file.
    count_old: int                           # required, Number of lines in the old file span.
    start_line_new: int                      # required, Starting line number in the new file.
    count_new: int                           # required, Number of lines in the new file span.
    context_before: list[str]                # required, Context lines before the change.
    added_lines: list[str]                   # required, Lines added in this hunk.
    removed_lines: list[str]                 # required, Lines removed in this hunk.
    context_after: list[str]                 # required, Context lines after the change.
    raw_header: str                          # required, Original @@ header line from the diff.
    classifications: list[ClassificationLabel] # required, Ledger classification labels applied to this hunk.
    language: Optional[str] = null           # optional, Detected programming language of the file, if known.

class Severity(Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class FindingCategory(Enum):
    """Category of a review finding. Imported from schemas."""
    SECURITY = "SECURITY"
    CORRECTNESS = "CORRECTNESS"
    STYLE = "STYLE"
    ARCHITECTURE = "ARCHITECTURE"

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

PACTKey = primitive  # A PACT attribution key string. Module-level constants following the pattern 'exemplar.module.Class.method'.

class Confidence(Enum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"

class ReviewDecision(Enum):
    """Final decision on a pull request review: block merging, warn, or pass."""
    block = "block"
    warn = "warn"
    pass = "pass"

class ClassificationLabel(Enum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"

class ReviewerProtocol:
    """Auto-stubbed type — referenced but not defined in contract 'circuit'"""
    pass

def __init__(
    config: CircuitConfig,
    reviewers: dict[ReviewStage, ReviewerProtocol],
    chronicler: ChroniclerEmitter = None,
    clock: ClockProvider = None,
) -> None:
    """
    Construct a BatonCircuitRouter. Validates that every stage in config.stages has a corresponding entry in the reviewers dict, that all parallel_stages entries are subsets of config.stages, and that no stage appears in more than one parallel group. Resolves the execution plan from config topology at construction time. Raises CircuitConfigError on validation failure.

    Preconditions:
      - config is a valid CircuitConfig instance (passes Pydantic validation)
      - reviewers dict is not empty
      - All ReviewerProtocol values satisfy the runtime_checkable protocol

    Postconditions:
      - self._execution_plan is a resolved ExecutionPlan covering all stages in config.stages exactly once
      - self._config, self._reviewers, self._chronicler, self._clock are stored immutably
      - No I/O has been performed (construction is synchronous and pure aside from validation)

    Errors:
      - missing_reviewers (CircuitConfigError): One or more stages in config.stages have no corresponding key in the reviewers dict
          missing_reviewers: list of ReviewStage values without registered reviewers
      - invalid_parallel_subset (CircuitConfigError): A ParallelGroup in config.parallel_stages contains stages not present in config.stages
          invalid_parallel_stages: list of ReviewStage values not in config.stages
      - duplicate_parallel_membership (CircuitConfigError): A ReviewStage appears in more than one ParallelGroup
          message: description of duplicate stage membership
      - empty_reviewers (CircuitConfigError): The reviewers dict is empty
          message: reviewers dict must not be empty

    Side effects: none
    Idempotent: yes
    """
    ...

async def run(
    request: ReviewRequest,
) -> list[Assessment]:
    """
    Execute the full review circuit for a given ReviewRequest. Iterates through the resolved ExecutionPlan: for each step, invokes reviewer(s) — concurrently for parallel steps, sequentially otherwise. Each reviewer invocation is wrapped in asyncio.wait_for with the configured stage timeout. On timeout or exception, a degraded Assessment (is_partial=True) is produced instead of propagating the error. Emits Chronicler events (stage.started, stage.complete) at each stage boundary via fire-and-forget. Returns assessments sorted in the canonical order defined by CircuitConfig.stages. PACT key: exemplar.circuit.BatonCircuitRouter.run

    Preconditions:
      - request is a valid ReviewRequest with at least one DiffHunk
      - BatonCircuitRouter was successfully constructed (no CircuitConfigError)

    Postconditions:
      - Returned list has exactly len(config.stages) Assessments, one per configured stage
      - Assessments are ordered by their position in CircuitConfig.stages
      - Every Assessment has a valid ReviewStage matching a configured stage
      - No exceptions are propagated from reviewer invocations — all failures produce is_partial=True assessments
      - If Chronicler is configured, stage.started and stage.complete events were emitted (fire-and-forget) for each stage
      - Each Assessment.duration_ms reflects the actual wall-clock time of that reviewer invocation

    Errors:
      - invalid_request (ValueError): request is None or fails ReviewRequest validation
          message: ReviewRequest must be non-None and valid
      - empty_hunks (ValueError): request.hunks is an empty list
          message: ReviewRequest must contain at least one DiffHunk

    Side effects: Invokes ReviewerProtocol.review() for each configured stage, Emits ChroniclerEvent via ChroniclerEmitter.emit() at stage boundaries (fire-and-forget), Uses asyncio.wait_for for timeout enforcement per stage
    Idempotent: no
    """
    ...

def resolve_execution_plan(
    config: CircuitConfig,
) -> ExecutionPlan:
    """
    Resolve the CircuitConfig into an ordered ExecutionPlan. Groups stages from parallel_stages into concurrent ExecutionSteps and remaining stages into sequential steps, preserving the order defined in config.stages. Called once at construction time. PACT key: exemplar.circuit.BatonCircuitRouter.resolve_execution_plan

    Preconditions:
      - config has passed all CircuitConfig validation (no duplicates, valid parallel groups)
      - This is called after reviewer registry validation succeeds

    Postconditions:
      - Every stage in config.stages appears in exactly one ExecutionStep
      - ExecutionPlan.stage_order matches config.stages exactly
      - Parallel groups are preserved as multi-stage ExecutionSteps with is_parallel=True
      - Sequential stages appear as single-stage ExecutionSteps with is_parallel=False
      - Step ordering respects the position of the earliest stage in each group within config.stages

    Side effects: none
    Idempotent: yes
    """
    ...

async def invoke_reviewer(
    stage: ReviewStage,
    request: ReviewRequest,
    timeout_ms: StageTimeoutMs,
) -> Assessment:
    """
    Invoke a single reviewer with circuit-breaker protection. Wraps the reviewer's async review call in asyncio.wait_for with the configured stage timeout. On TimeoutError or any Exception, returns a degraded Assessment with is_partial=True and the error message. Emits stage.started before invocation and stage.complete after (success or degraded). PACT key: exemplar.circuit.BatonCircuitRouter.invoke_reviewer

    Preconditions:
      - stage has a registered reviewer in self._reviewers
      - request is a valid ReviewRequest
      - timeout_ms is a valid StageTimeoutMs (100-300000)

    Postconditions:
      - Returns exactly one Assessment for the given stage
      - Assessment.stage == stage
      - If reviewer completed successfully within timeout: Assessment.is_partial == False and Assessment.findings contains reviewer output
      - If reviewer timed out or threw: Assessment.is_partial == True and Assessment.error_message describes the failure
      - Assessment.duration_ms reflects actual invocation wall-clock time
      - Chronicler events emitted (fire-and-forget) regardless of success/failure
      - No exception is ever propagated from this method

    Side effects: Invokes ReviewerProtocol.review() with asyncio.wait_for timeout, Emits ChroniclerEvent stage.started and stage.complete via fire-and-forget
    Idempotent: no
    """
    ...

def get_stage_timeout(
    stage: ReviewStage,
) -> StageTimeoutMs:
    """
    Resolve the effective timeout for a given stage. Returns the stage-specific override from config.stage_timeouts if present, otherwise config.default_timeout_ms. PACT key: exemplar.circuit.BatonCircuitRouter.get_stage_timeout

    Preconditions:
      - stage is a member of self._config.stages

    Postconditions:
      - Returns config.stage_timeouts[stage] if stage is in stage_timeouts, else config.default_timeout_ms
      - Returned value satisfies StageTimeoutMs validation (100-300000)

    Side effects: none
    Idempotent: yes
    """
    ...

def get_execution_plan() -> ExecutionPlan:
    """
    Returns the resolved ExecutionPlan for inspection and testing. Read-only accessor. PACT key: exemplar.circuit.BatonCircuitRouter.get_execution_plan

    Preconditions:
      - BatonCircuitRouter was successfully constructed

    Postconditions:
      - Returns the immutable ExecutionPlan resolved at construction time
      - Returned plan is a frozen Pydantic model — caller cannot mutate it

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ReviewStage', 'ParallelGroup', 'CircuitConfig', 'ExecutionStep', 'ExecutionPlan', 'ChroniclerEventType', 'ChroniclerEvent', 'ChroniclerEmitter', 'ClockProvider', 'CircuitConfigError', 'ReviewRequest', 'DiffHunk', 'Severity', 'FindingCategory', 'Finding', 'Assessment', 'Confidence', 'ReviewDecision', 'ClassificationLabel', 'ReviewerProtocol', 'run', 'resolve_execution_plan', 'invoke_reviewer', 'get_stage_timeout', 'get_execution_plan']
