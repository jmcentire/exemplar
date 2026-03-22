# === Root (root) v1 ===
#  Dependencies: assessor, circuit, cli, config, governance, intake, learner, mcp_server, reporter, reviewers, schemas
# Lightweight orchestrator implementing PipelineProtocol that wires together all Exemplar sub-components into an end-to-end governed code review pipeline. Root accepts ExemplarConfig, injects protocol-typed dependencies (ClockProvider, IdGenerator, ChroniclerEmitter, SealChainStoreProtocol), and orchestrates the async pipeline: intake.run_intake → circuit.run → assessor.merge_assessments → reporter.format_report + seal_report. Root contains zero business logic — only wiring, sequencing, error handling at stage boundaries, and Chronicler event emission with PACT key attribution. Supports async context manager for resource lifecycle (opening/closing seal chain store, chronicler log). All data flowing through the pipeline uses frozen Pydantic v2 models from schemas. Root itself is NOT a frozen model — it holds mutable runtime references to component instances.

# Module invariants:
#   - Root contains zero business logic — only wiring, sequencing, error handling at stage boundaries, and Chronicler event emission. All domain logic lives in sub-components.
#   - Root is NOT a frozen Pydantic model — it holds mutable runtime state (component references, _is_open flag). All data flowing through the pipeline uses frozen schemas models.
#   - All Chronicler event emissions from Root are fire-and-forget: emitter failures are caught, logged, and never propagate to the pipeline caller.
#   - PACT key constants (exemplar.root.*) are embedded in every ChroniclerEvent payload emitted by Root and in every ExemplarError raised by Root.
#   - Pipeline stage error classification is deterministic: intake failures with zero hunks are fatal; reviewer timeouts produce partial assessments (recoverable via circuit); seal/chronicler failures are ignorable (fire-and-forget).
#   - Root.__init__ never performs file I/O. All file I/O initialization happens in __aenter__.
#   - Root.__aexit__ never suppresses exceptions — it always returns False from the async context manager.
#   - The injected ClockProvider is used for all timestamps in Root-emitted ChroniclerEvents and PipelineResult, enabling deterministic testing.
#   - The injected id_generator is used for all event_id and report_id generation in Root, enabling deterministic testing.
#   - create_root is the canonical entry point — CLI main() and MCP create_server() should both use it to obtain a Root instance.
#   - Exit code mapping is deterministic and fixed: pass→0, warn→1, block→2, error→3.
#   - Learner trust adjustment retrieval is fire-and-forget: if learner state is unavailable, default trust weights from ExemplarConfig are used without error.
#   - Root holds exactly one BatonCircuitRouter instance, constructed once in __init__, reused across all run_pipeline calls.
#   - If seal_report fails, the pipeline still returns a valid PipelineResult with an unsealed ReviewReport — sealing is never fatal.

class PipelineStage(Enum):
    """Named stages of the Root orchestration pipeline, used for error boundary identification and Chronicler event context. StrEnum in implementation."""
    intake = "intake"
    circuit = "circuit"
    assess = "assess"
    format = "format"
    seal = "seal"

class ErrorSeverity(Enum):
    """Classification of pipeline errors by recoverability. Fatal errors abort the pipeline; recoverable errors produce partial results; ignorable errors are logged and suppressed."""
    fatal = "fatal"
    recoverable = "recoverable"
    ignorable = "ignorable"

class ExemplarError:
    """Base exception for all Root-level pipeline errors. Carries the failing stage, a human-readable message, optional cause exception context, and PACT key for attribution. Subclass of Exception in implementation."""
    stage: PipelineStage                     # required, The pipeline stage where the error occurred.
    message: str                             # required, length(len(value) >= 1), Human-readable error description.
    pact_key: str                            # required, regex(^exemplar\.root\.[a-z_]+$), PACT attribution key of the method that produced this error.
    cause: str = None                        # optional, String representation of the underlying exception that triggered this error, if any.
    error_severity: ErrorSeverity            # required, Whether this error is fatal, recoverable, or ignorable.
    context: dict = {}                       # optional, Arbitrary key-value context for debugging (e.g., review_request_id, stage config).

class PipelineStageError:
    """Error specific to a pipeline stage failure, wrapping the underlying component error with stage context. Subclass of ExemplarError in implementation."""
    stage: PipelineStage                     # required, The pipeline stage where the error occurred.
    message: str                             # required, Human-readable error description.
    pact_key: str                            # required, PACT attribution key.
    cause: str = None                        # optional, String repr of underlying exception.
    error_severity: ErrorSeverity            # required, Recoverability classification.
    context: dict = {}                       # optional, Debugging context.
    component_id: str                        # required, The component_id of the sub-component that failed (e.g., 'intake', 'circuit', 'assessor', 'reporter').

class PactKeyConstants:
    """Module-level PACT key constants for all Root public methods. Used in Chronicler event payloads and ExemplarError attribution. All values are class-level str constants in implementation."""
    ROOT_INIT: str                           # required, PACT key for Root.__init__. Value: 'exemplar.root.__init__'
    ROOT_RUN_PIPELINE: str                   # required, PACT key for Root.run_pipeline. Value: 'exemplar.root.run_pipeline'
    ROOT_AENTER: str                         # required, PACT key for Root.__aenter__. Value: 'exemplar.root.__aenter__'
    ROOT_AEXIT: str                          # required, PACT key for Root.__aexit__. Value: 'exemplar.root.__aexit__'
    ROOT_CREATE: str                         # required, PACT key for create_root factory. Value: 'exemplar.root.create_root'
    ROOT_BUILD_PIPELINE_RESULT: str          # required, PACT key for _build_pipeline_result. Value: 'exemplar.root.build_pipeline_result'

class RootConfig:
    """Frozen Pydantic model extracting the Root-relevant subset of ExemplarConfig. Constructed by Root.__init__ from the full ExemplarConfig. Carries paths for chronicle log, seal chain, kindex store, and stigmergy store, plus the full sub-configs needed to construct components."""
    chronicle_log_path: str                  # required, length(len(value) >= 1), File path for Chronicler JSON-lines log output.
    seal_chain_path: str                     # required, length(len(value) >= 1), File path for Tessera seal chain state.
    kindex_store_path: str                   # required, length(len(value) >= 1), File path for Kindex persistent store.
    stigmergy_store_path: str                # required, length(len(value) >= 1), File path for Stigmergy pattern store.

class PipelineEvent:
    """A Chronicler event accumulated during pipeline execution. Lightweight wrapper to track events emitted at stage boundaries before they are included in PipelineResult."""
    event_type: str                          # required, Well-known Chronicler event type string.
    stage: str = None                        # optional, Pipeline stage name, if applicable.
    message: str                             # required, Human-readable event description.
    payload: dict = {}                       # optional, Arbitrary structured data for the event.

class ExitCodeMapping:
    """Static mapping from ReviewDecision to integer exit codes. pass→0, warn→1, block→2. Used by Root to populate PipelineResult.exit_code."""
    pass_code: int                           # required, Exit code for pass decision. Value: 0.
    warn_code: int                           # required, Exit code for warn decision. Value: 1.
    block_code: int                          # required, Exit code for block decision. Value: 2.
    error_code: int                          # required, Exit code for error condition. Value: 3.

def __init__(
    config: any,
    clock: any = None,
    chronicler: any = None,
    chain_store: any = None,
    id_generator: any = None,
) -> None:
    """
    Construct a Root orchestrator instance. Validates and slices ExemplarConfig into sub-configs for each component. Instantiates governance primitives (ChronicleEmitter, TesseraSealer, LedgerClassifier, KindexStore, StigmergyTracker). Constructs BatonCircuitRouter with reviewer instances from get_all_reviewers(). Stores injected protocol-typed dependencies (ClockProvider, ChroniclerEmitter, SealChainStoreProtocol). Does NOT open file handles or perform I/O — that happens in __aenter__. PACT key: exemplar.root.__init__.

    Preconditions:
      - config is a valid ExemplarConfig that passes all Pydantic validators
      - If clock is provided, it satisfies ClockProvider protocol (now_utc() -> str, monotonic_ms() -> int)
      - If chronicler is provided, it satisfies ChroniclerEmitter protocol (async emit(event) -> None)
      - If chain_store is provided, it satisfies SealChainStoreProtocol (async get_previous_hash() -> str|None, async append_seal(seal) -> None)

    Postconditions:
      - self._config holds the original ExemplarConfig reference
      - self._root_config is a RootConfig extracted from the ExemplarConfig
      - self._circuit_router is a fully constructed BatonCircuitRouter with all enabled reviewers registered
      - self._clock, self._chronicler, self._chain_store, self._id_generator are stored (injected or default-constructed)
      - self._is_open is False (no resources opened until __aenter__)
      - No file I/O has been performed

    Errors:
      - invalid_config (ExemplarError): config is not a valid ExemplarConfig or fails internal extraction
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.__init__
      - circuit_config_error (ExemplarError): CircuitConfig is invalid or reviewers cannot be registered (e.g., no enabled reviewers for a configured stage)
          stage: circuit
          error_severity: fatal
          pact_key: exemplar.root.__init__
          cause: CircuitConfigError details
      - invalid_clock_protocol (TypeError): Provided clock does not satisfy ClockProvider protocol
          detail: clock must implement ClockProvider protocol (now_utc, monotonic_ms)
      - invalid_chronicler_protocol (TypeError): Provided chronicler does not satisfy ChroniclerEmitter protocol
          detail: chronicler must implement ChroniclerEmitter protocol (async emit)

    Side effects: none
    Idempotent: no
    """
    ...

async def __aenter__() -> any:
    """
    Async context manager entry. Opens file-based resources: ensures chronicle log directory exists, initializes seal chain store file if absent, initializes learner state directory. Returns self for use in 'async with' blocks. PACT key: exemplar.root.__aenter__.

    Preconditions:
      - Root was successfully constructed via __init__
      - self._is_open is False (not already entered)

    Postconditions:
      - self._is_open is True
      - Chronicle log directory exists on filesystem
      - Seal chain store file is initialized (empty chain if new)
      - Learner state directory is initialized via learner.initialize_state()
      - Returned value is self

    Errors:
      - already_open (ExemplarError): self._is_open is True (double entry into context manager)
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.__aenter__
          message: Root context manager is already open
      - filesystem_permission_error (ExemplarError): Cannot create chronicle log directory, seal chain file, or learner state directory due to permissions
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.__aenter__
          cause: PermissionError details
      - learner_init_failure (ExemplarError): learner.initialize_state() fails (corrupt existing state)
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.__aenter__
          cause: StateCorruptionError details

    Side effects: none
    Idempotent: no
    """
    ...

async def __aexit__(
    exc_type: any = None,
    exc_val: any = None,
    exc_tb: any = None,
) -> bool:
    """
    Async context manager exit. Performs cleanup: flushes any buffered chronicle events, closes file handles. Suppresses no exceptions (re-raises all). PACT key: exemplar.root.__aexit__.

    Preconditions:
      - self._is_open is True

    Postconditions:
      - self._is_open is False
      - All file handles have been closed or flushed
      - Return value is False (exceptions are not suppressed)

    Errors:
      - cleanup_failure (ExemplarError): File handle flush or close raises an I/O error during cleanup
          stage: seal
          error_severity: ignorable
          pact_key: exemplar.root.__aexit__
          message: Cleanup failure during context exit — logged and suppressed

    Side effects: none
    Idempotent: no
    """
    ...

async def run_pipeline(
    diff_source: str,          # length(len(value) >= 1)
    output_format: str,        # custom(value in ('json', 'md', 'github'))
    metadata: dict = {},
) -> any:
    """
    Execute the full end-to-end review pipeline. Orchestrates: (1) emit review.started Chronicler event, (2) intake.run_intake to parse and classify diff, (3) circuit.run to route hunks through reviewer stages, (4) assessor.merge_assessments to combine assessments with trust-weighted scoring, (5) reporter.format_report to render output, (6) reporter.seal_report to apply Tessera seal, (7) emit review.complete Chronicler event. Error boundaries: intake/circuit failures with zero usable results are fatal (raise PipelineStageError); reviewer timeouts produce partial Assessments (recoverable); chronicler/seal failures are fire-and-forget (ignorable). Accumulates all Chronicler events emitted during the pipeline for inclusion in PipelineResult. Maps final ReviewDecision to exit_code (pass→0, warn→1, block→2). PACT key: exemplar.root.run_pipeline.

    Preconditions:
      - self._is_open is True (Root context manager has been entered)
      - diff_source is a non-empty string containing unified diff text
      - output_format is a valid OutputFormat variant string

    Postconditions:
      - Returned PipelineResult.review_request contains parsed and classified DiffHunks
      - Returned PipelineResult.assessments contains one Assessment per configured review stage
      - Returned PipelineResult.report is a merged ReviewReport with TesseraSeal attached (if sealing succeeded)
      - Returned PipelineResult.formatted_output contains the report rendered in the requested format
      - Returned PipelineResult.output_format matches the requested output_format
      - Returned PipelineResult.exit_code is 0 (pass), 1 (warn), or 2 (block)
      - Returned PipelineResult.events contains all Chronicler events emitted during pipeline execution
      - A review.started ChroniclerEvent was emitted at pipeline start (fire-and-forget)
      - A review.complete ChroniclerEvent was emitted at pipeline end (fire-and-forget)
      - All findings in the report are sorted deterministically per assessor contract

    Errors:
      - not_open (ExemplarError): self._is_open is False — run_pipeline called outside async context manager
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.run_pipeline
          message: Root context manager must be entered before running pipeline
      - empty_diff (ExemplarError): diff_source is empty string
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.run_pipeline
          message: diff_source must not be empty
      - intake_failure (PipelineStageError): intake.run_intake returns zero hunks and one or more fatal errors (completely unparseable diff)
          stage: intake
          error_severity: fatal
          component_id: intake
          pact_key: exemplar.root.run_pipeline
      - circuit_failure (PipelineStageError): circuit.run raises an unexpected error (not a reviewer timeout, which is handled internally)
          stage: circuit
          error_severity: fatal
          component_id: circuit
          pact_key: exemplar.root.run_pipeline
      - assessor_failure (PipelineStageError): assessor.merge_assessments raises ValueError (invalid input data)
          stage: assess
          error_severity: fatal
          component_id: assessor
          pact_key: exemplar.root.run_pipeline
      - reporter_format_failure (PipelineStageError): reporter.format_report raises ReporterRenderError or ReporterFormatError
          stage: format
          error_severity: fatal
          component_id: reporter
          pact_key: exemplar.root.run_pipeline
      - seal_failure (ExemplarError): reporter.seal_report raises ReporterSealError or ReporterChainStoreError — fire-and-forget, report is returned unsealed
          stage: seal
          error_severity: ignorable
          pact_key: exemplar.root.run_pipeline
          message: Seal failed; report returned unsealed
      - invalid_output_format (ExemplarError): output_format is not one of 'json', 'md', 'github'
          stage: format
          error_severity: fatal
          pact_key: exemplar.root.run_pipeline
          message: Unsupported output format

    Side effects: none
    Idempotent: no
    """
    ...

async def _run_intake_stage(
    diff_text: str,
    metadata: dict = {},
    accumulated_events: list,
) -> any:
    """
    Internal method: executes the intake stage of the pipeline. Creates a string-based DiffSource from the raw diff text, invokes intake.run_intake with the LedgerConfig and ChroniclerEmitter, and returns the IntakeResult. Emits stage.started and stage.complete Chronicler events. PACT key: exemplar.root.run_pipeline (attributed to parent).

    Preconditions:
      - diff_text is a non-empty string
      - accumulated_events is an initialized (possibly empty) list

    Postconditions:
      - Returned IntakeResult.review_request.hunks has zero or more classified DiffHunks
      - stage.started and stage.complete events have been appended to accumulated_events
      - ChroniclerEmitter emission failures are caught and logged (fire-and-forget)

    Errors:
      - intake_read_failure (PipelineStageError): DiffSource.read() raises an IOError
          stage: intake
          component_id: intake
          error_severity: fatal
      - intake_parse_failure (PipelineStageError): parse_diff returns zero hunks with errors
          stage: intake
          component_id: intake
          error_severity: fatal

    Side effects: none
    Idempotent: no
    """
    ...

async def _run_circuit_stage(
    review_request: any,
    accumulated_events: list,
) -> list:
    """
    Internal method: executes the circuit stage. Invokes BatonCircuitRouter.run() with the ReviewRequest from intake. Returns the list of Assessments (one per configured stage). Reviewer timeouts and failures produce partial Assessments (handled by circuit internally). Emits stage boundary events. PACT key: exemplar.root.run_pipeline (attributed to parent).

    Preconditions:
      - review_request.hunks is non-empty
      - BatonCircuitRouter was successfully constructed in __init__

    Postconditions:
      - Returned list has exactly len(config.stages) Assessments
      - Assessments are ordered by their position in CircuitConfig.stages
      - Partial assessments (is_partial=True) are included for timed-out/failed reviewers

    Errors:
      - circuit_run_failure (PipelineStageError): BatonCircuitRouter.run() raises ValueError (invalid request)
          stage: circuit
          component_id: circuit
          error_severity: fatal

    Side effects: none
    Idempotent: no
    """
    ...

async def _run_assess_stage(
    assessments: list,
    review_request_id: str,    # length(1 <= len(value) <= 256)
    accumulated_events: list,
) -> any:
    """
    Internal method: executes the assessment merge stage. Retrieves trust adjustments from learner (if phase is canary or primary), resolves trust scores, invokes assessor.merge_assessments. Returns the merged ReviewReport. Emits stage boundary events. PACT key: exemplar.root.run_pipeline (attributed to parent).

    Preconditions:
      - assessments is a non-empty list of valid Assessment objects
      - All assessments have review_request_id matching review_request_id parameter

    Postconditions:
      - Returned ReviewReport.review_request_id matches the input review_request_id
      - Returned ReviewReport.findings are sorted deterministically
      - Returned ReviewReport.decision is one of block, warn, pass
      - Trust adjustments from learner are applied if learner phase is canary or primary

    Errors:
      - assessor_merge_failure (PipelineStageError): assessor.merge_assessments raises ValueError
          stage: assess
          component_id: assessor
          error_severity: fatal
      - learner_trust_failure (ExemplarError): learner.get_trust_adjustments() fails — fire-and-forget, default trust weights used
          stage: assess
          error_severity: ignorable
          message: Learner trust adjustment failed; using default weights

    Side effects: none
    Idempotent: no
    """
    ...

async def _run_format_and_seal_stage(
    report: any,
    output_format: str,
    accumulated_events: list,
) -> dict:
    """
    Internal method: executes the format and seal stages. Invokes reporter.format_report to render the ReviewReport, then reporter.seal_report to apply Tessera seal. Seal failure is fire-and-forget (report is returned unsealed). Emits stage boundary and report.sealed events. PACT key: exemplar.root.run_pipeline (attributed to parent).

    Preconditions:
      - report is a valid ReviewReport instance
      - output_format is one of 'json', 'md', 'github'

    Postconditions:
      - Returned dict has keys 'sealed_report' (ReviewReport, possibly with seal) and 'formatted_output' (FormattedReport)
      - If sealing succeeded, sealed_report.seal is a valid TesseraSeal
      - If sealing failed, sealed_report.seal is None and a warning is logged
      - formatted_output.content is a non-empty string in the requested format

    Errors:
      - format_failure (PipelineStageError): reporter.format_report raises ReporterRenderError
          stage: format
          component_id: reporter
          error_severity: fatal
      - seal_failure (ExemplarError): reporter.seal_report raises any error — fire-and-forget
          stage: seal
          error_severity: ignorable
          message: Sealing failed; returning unsealed report

    Side effects: none
    Idempotent: no
    """
    ...

def _build_pipeline_result(
    review_request: any,
    assessments: list,
    report: any,
    events: list,
    formatted_output: str,
    output_format: str,
) -> any:
    """
    Internal pure helper: assembles a PipelineResult from the outputs of all pipeline stages. Maps ReviewDecision to exit_code (pass→0, warn→1, block→2). Pure function except for clock injection for timestamp. PACT key: exemplar.root.build_pipeline_result.

    Preconditions:
      - All inputs are valid and non-None
      - report.decision is a valid ReviewDecision

    Postconditions:
      - Returned PipelineResult.exit_code is 0 for pass, 1 for warn, 2 for block
      - Returned PipelineResult.review_request is the input review_request
      - Returned PipelineResult.assessments is the input assessments list
      - Returned PipelineResult.report is the input report
      - Returned PipelineResult.events is the input events list
      - Returned PipelineResult.formatted_output is the input formatted_output string
      - Returned PipelineResult.output_format matches the input output_format

    Errors:
      - unknown_decision (ExemplarError): report.decision is not a recognized ReviewDecision variant
          stage: format
          error_severity: fatal
          pact_key: exemplar.root.build_pipeline_result
          message: Unknown ReviewDecision in report

    Side effects: none
    Idempotent: yes
    """
    ...

async def _emit_event(
    event_type: str,
    review_request_id: str,
    message: str,
    pact_key: str,
    stage: str = None,
    payload: dict = {},
    accumulated_events: list = None,
) -> None:
    """
    Internal fire-and-forget helper: constructs a ChroniclerEvent and emits it via the injected ChroniclerEmitter. Catches all exceptions from the emitter — failures are logged via stdlib logging but never propagate. Uses the injected clock for timestamp and id_generator for event_id. PACT key is passed as a payload field.

    Postconditions:
      - If emitter succeeds, event was durably emitted to chronicle log
      - If emitter fails, failure is logged via stdlib logging — no exception propagates
      - If accumulated_events is provided, event is appended to it regardless of emitter success/failure
      - Event payload contains 'pact_key' field with the provided PACT key

    Side effects: none
    Idempotent: no
    """
    ...

def create_root(
    config_path: str = None,
    clock: any = None,
    chronicler: any = None,
    chain_store: any = None,
    id_generator: any = None,
) -> any:
    """
    Factory function that creates a fully configured Root instance. Loads ExemplarConfig via config.load_config (using optional explicit path), constructs Root with all defaults, and returns it. This is the primary entry point for both CLI and MCP server. PACT key: exemplar.root.create_root.

    Preconditions:
      - If config_path is provided and non-empty, it points to a readable YAML file

    Postconditions:
      - Returned object is a fully constructed Root instance
      - Root._is_open is False (caller must use async with to open)
      - Config was loaded and validated successfully

    Errors:
      - config_file_not_found (ExemplarError): Explicit config_path does not exist on filesystem
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.create_root
          cause: ConfigFileNotFoundError
      - config_parse_error (ExemplarError): Config file has invalid YAML syntax
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.create_root
          cause: ConfigParseError
      - config_validation_error (ExemplarError): Config file content fails Pydantic validation
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.create_root
          cause: ConfigValidationError
      - root_construction_failure (ExemplarError): Root.__init__ raises ExemplarError (e.g., invalid circuit config)
          stage: intake
          error_severity: fatal
          pact_key: exemplar.root.create_root

    Side effects: none
    Idempotent: yes
    """
    ...

def map_decision_to_exit_code(
    decision: str,             # custom(value in ('pass', 'warn', 'block'))
) -> int:
    """
    Pure mapping function from ReviewDecision string to integer exit code. pass→0, warn→1, block→2. Used by _build_pipeline_result. PACT key: exemplar.root.build_pipeline_result.

    Preconditions:
      - decision is a valid ReviewDecision variant string

    Postconditions:
      - Returns 0 for 'pass', 1 for 'warn', 2 for 'block'
      - Return value is always in {0, 1, 2}

    Errors:
      - invalid_decision (ExemplarError): decision is not 'pass', 'warn', or 'block'
          stage: format
          error_severity: fatal
          pact_key: exemplar.root.build_pipeline_result
          message: Unknown ReviewDecision

    Side effects: none
    Idempotent: yes
    """
    ...

def get_config() -> any:
    """
    Read-only accessor returning the ExemplarConfig used by this Root instance. Useful for CLI/MCP introspection and debugging. PACT key: exemplar.root.get_config.

    Preconditions:
      - Root was successfully constructed

    Postconditions:
      - Returned value is the ExemplarConfig passed to __init__ (or loaded by create_root)
      - Returned config is a frozen Pydantic model — caller cannot mutate it

    Side effects: none
    Idempotent: yes
    """
    ...

def get_circuit_router() -> any:
    """
    Read-only accessor returning the BatonCircuitRouter instance constructed by Root. Useful for CLI/MCP introspection and testing. PACT key: exemplar.root.get_circuit_router.

    Preconditions:
      - Root was successfully constructed

    Postconditions:
      - Returned value is the BatonCircuitRouter instance
      - Router's execution plan is accessible via get_execution_plan()

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['PipelineStage', 'ErrorSeverity', 'ExemplarError', 'PipelineStageError', 'PactKeyConstants', 'RootConfig', 'PipelineEvent', 'ExitCodeMapping', 'run_pipeline', '_run_intake_stage', '_run_circuit_stage', '_run_assess_stage', '_run_format_and_seal_stage', '_build_pipeline_result', '_emit_event', 'create_root', 'map_decision_to_exit_code', 'get_config', 'get_circuit_router']
