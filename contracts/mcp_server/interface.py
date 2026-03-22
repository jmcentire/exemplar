# === MCP Server (mcp_server) v1 ===
#  Dependencies: intake, assessor, reporter, chronicle, schemas, config, learner
# MCP tool server over stdio transport exposing three tools: exemplar_review (accepts diff text or file path, config overrides, format preference; returns formatted ReviewReport), exemplar_trust (returns current trust scores as structured data), exemplar_history (accepts query parameters, returns matching past reviews from Kindex). Uses same core pipeline as CLI via injected PipelineProtocol. Implements MCP protocol message handling (JSON-RPC over stdio). Tool schemas generated from frozen Pydantic v2 models. Async request handling. All logging to stderr; stdout reserved exclusively for JSON-RPC protocol traffic.

# Module invariants:
#   - stdout is exclusively reserved for JSON-RPC protocol traffic; no logging or diagnostic output may be written to stdout
#   - All logging output is written to stderr via Python logging module
#   - Tool handlers never raise unhandled exceptions; all errors are caught and returned as McpToolResult with isError=True
#   - All tool input models are frozen Pydantic v2 models (frozen=True)
#   - All public functions carry a PACT key for Sentinel attribution
#   - Chronicler event emission is fire-and-forget: unreachable Chronicler does not block or fail tool responses
#   - Tool JSON schemas are generated from Pydantic model_json_schema() and are deterministic
#   - JSON serialization in tool responses is deterministic (sorted keys) for testability
#   - The MCP server holds no mutable state between requests; all state is in the injected pipeline
#   - ReviewToolInput requires at least one of diff_text or file_path to be non-None (model-level validator)

class OutputFormat(Enum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"

class ReviewToolInput:
    """Frozen Pydantic v2 input model for the exemplar_review tool. At least one of diff_text or file_path must be provided. Generates MCP-compatible JSON Schema via model_json_schema()."""
    diff_text: optional[str] = None          # optional, length(min=1, max=1048576), Raw unified diff text to review. Mutually sufficient with file_path; at least one must be provided.
    file_path: optional[str] = None          # optional, length(min=1, max=4096), Path to a diff file on disk. Mutually sufficient with diff_text; at least one must be provided.
    config_overrides: optional[dict] = None  # optional, Optional key-value config overrides applied on top of the base ExemplarConfig for this review invocation. Keys and values are strings.
    format: OutputFormat = json              # optional, Desired output format for the review report.

class TrustToolInput:
    """Frozen Pydantic v2 input model for the exemplar_trust tool. No required fields; returns all current trust scores."""
    reviewer_id: optional[str] = None        # optional, regex(^[a-zA-Z0-9_\-\.]{1,128}$), Optional filter to retrieve trust score for a specific reviewer. If None, returns all scores.

class HistoryToolInput:
    """Frozen Pydantic v2 input model for the exemplar_history tool. All fields optional; returns matching past reviews from Kindex."""
    tags: optional[list[str]] = None         # optional, Filter reviews by tags. Returns entries matching any of the provided tags.
    kind: optional[str] = None               # optional, regex(^[a-zA-Z0-9_\-]{1,64}$), Filter reviews by kind/category (e.g. 'security', 'correctness').
    date_from: optional[str] = None          # optional, regex(^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$), ISO 8601 date string for the start of the query range (inclusive).
    date_to: optional[str] = None            # optional, regex(^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$), ISO 8601 date string for the end of the query range (inclusive).
    limit: int = 50                          # optional, range(min=1, max=500), Maximum number of results to return.
    offset: int = 0                          # optional, range(min=0, max=100000), Pagination offset for result set.

class ToolError:
    """Frozen Pydantic v2 model for structured MCP tool error responses. Serialized with isError=True in the MCP content block."""
    error_type: str                          # required, custom(value in ('validation_error', 'pipeline_error', 'io_error', 'internal_error')), Classification of the error: 'validation_error', 'pipeline_error', 'io_error', 'internal_error'.
    message: str                             # required, length(min=1, max=4096), Human-readable error summary.
    field_errors: optional[list[FieldError]] = None # optional, Field-level validation error details, present when error_type is 'validation_error'.
    pact_key: str                            # required, PACT attribution key identifying the tool handler that produced this error.

class FieldError:
    """Per-field validation error detail within a ToolError."""
    field: str                               # required, Dotted path to the invalid field (e.g. 'config_overrides.severity_threshold').
    message: str                             # required, Description of the validation failure.
    input_value: optional[str] = None        # optional, String representation of the rejected value, if safe to include.

class McpContentBlock:
    """A single MCP tool result content block. The MCP SDK uses this shape for tool responses."""
    type: str                                # required, custom(value == 'text'), Content block type, always 'text' for this server's responses.
    text: str                                # required, Serialized JSON payload (ReviewReport, list[TrustScore], list[KindexEntry], or ToolError).

class McpToolResult:
    """MCP tool call result shape returned from tool handlers."""
    content: list[McpContentBlock]           # required, One or more content blocks containing the tool output.
    isError: bool = false                    # optional, True if this result represents an error condition.

class PipelineProtocol:
    """Runtime-checkable Protocol defining the core pipeline interface that the MCP server depends on. Allows dependency injection and test mocking of the pipeline layer. Implementation must provide run_review, get_trust_scores, and query_history async methods."""
    run_review: str                          # required, Async callable: (diff_text: str, config: ExemplarConfig) -> ReviewReport
    get_trust_scores: str                    # required, Async callable: (reviewer_id: Optional[str]) -> list[TrustScore]
    query_history: str                       # required, Async callable: (tags, kind, date_from, date_to, limit, offset) -> list[KindexEntry]

class ServerConfig:
    """Configuration subset relevant to the MCP server: server name, version metadata, and optional feature flags."""
    server_name: str = exemplar              # optional, regex(^[a-zA-Z0-9_\-]{1,64}$), MCP server name reported in initialization.
    server_version: str = 0.1.0              # optional, regex(^\d+\.\d+\.\d+(-[a-zA-Z0-9\.]+)?$), Semantic version string for the MCP server.
    enable_chronicler: bool = true           # optional, Whether to emit Chronicler events from tool handlers. Fire-and-forget when enabled.
    max_diff_size_bytes: int = 1048576       # optional, range(min=1024, max=10485760), Maximum allowed diff size in bytes (1MB default).

class optional:
    """Auto-stubbed type — referenced but not defined in contract 'mcp_server'"""
    pass

def create_server(
    pipeline: PipelineProtocol,
    config: ServerConfig = ServerConfig(),
) -> any:
    """
    Factory function that creates and configures an mcp.Server instance with all three tools registered (exemplar_review, exemplar_trust, exemplar_history). The pipeline and config are injected, allowing tests to call tool handlers directly without stdio transport. PACT key: mcp_server.create_server.

    Preconditions:
      - pipeline satisfies PipelineProtocol (runtime_checkable)
      - config is a valid ServerConfig instance

    Postconditions:
      - Returned mcp.Server has exactly 3 tools registered: exemplar_review, exemplar_trust, exemplar_history
      - Each tool's JSON schema matches the corresponding ToolInput model's model_json_schema()
      - Server is not yet running (no transport bound)

    Errors:
      - invalid_pipeline (TypeError): pipeline does not satisfy PipelineProtocol at runtime
          message: pipeline must implement PipelineProtocol (run_review, get_trust_scores, query_history)
      - invalid_config (ValidationError): config fails ServerConfig validation
          message: ServerConfig validation failed

    Side effects: none
    Idempotent: yes
    """
    ...

async def run_server(
    server: any,
) -> None:
    """
    Async entry point that binds the mcp.Server to stdio transport and runs the JSON-RPC message loop until the transport closes. Called from CLI or __main__. Blocks until stdin EOF or shutdown signal. PACT key: mcp_server.run_server.

    Preconditions:
      - server was created via create_server() with a valid pipeline
      - stdin and stdout are available file descriptors
      - stdout is not being written to by any other component (reserved for JSON-RPC)

    Postconditions:
      - Server has cleanly shut down and released stdio handles
      - No orphaned async tasks remain

    Errors:
      - stdio_unavailable (OSError): stdin or stdout is closed or unavailable
          message: stdio transport requires open stdin and stdout
      - transport_error (RuntimeError): Unrecoverable error in the MCP stdio transport layer
          message: MCP transport failed unexpectedly

    Side effects: Reads from stdin (JSON-RPC requests), Writes to stdout (JSON-RPC responses), Writes to stderr (logging)
    Idempotent: no
    """
    ...

async def handle_review(
    input: ReviewToolInput,
) -> McpToolResult:
    """
    Tool handler for exemplar_review. Validates ReviewToolInput, reads diff from text or file, applies config overrides, runs the review pipeline, formats the report, and returns an McpToolResult. Emits chronicler events (review.started, review.complete) around pipeline execution. Never raises unhandled exceptions. PACT key: mcp_server.handle_review.

    Preconditions:
      - At least one of input.diff_text or input.file_path is not None
      - If input.file_path is provided, the file exists and is readable
      - Pipeline has been injected via create_server()

    Postconditions:
      - Result contains exactly one McpContentBlock of type 'text'
      - If isError is false, content.text is valid JSON deserializable to ReviewReport
      - If isError is true, content.text is valid JSON deserializable to ToolError
      - Chronicler review.started event was emitted (fire-and-forget) before pipeline invocation
      - Chronicler review.complete event was emitted (fire-and-forget) after pipeline invocation

    Errors:
      - validation_error (ToolError): ReviewToolInput fails Pydantic validation (e.g. neither diff_text nor file_path provided)
          error_type: validation_error
          message: Input validation failed
      - file_not_found (ToolError): file_path is provided but the file does not exist or is not readable
          error_type: io_error
          message: Diff file not found or not readable
      - diff_too_large (ToolError): Diff content exceeds max_diff_size_bytes from ServerConfig
          error_type: validation_error
          message: Diff exceeds maximum allowed size
      - pipeline_failure (ToolError): Core review pipeline raises an exception during execution
          error_type: pipeline_error
          message: Review pipeline failed
      - internal_error (ToolError): Unexpected exception in handler logic (catch-all)
          error_type: internal_error
          message: Unexpected internal error

    Side effects: none
    Idempotent: no
    """
    ...

async def handle_trust(
    input: TrustToolInput,
) -> McpToolResult:
    """
    Tool handler for exemplar_trust. Validates TrustToolInput, retrieves current trust scores via the pipeline, and returns them as structured JSON in an McpToolResult. Never raises unhandled exceptions. PACT key: mcp_server.handle_trust.

    Preconditions:
      - Pipeline has been injected via create_server()

    Postconditions:
      - Result contains exactly one McpContentBlock of type 'text'
      - If isError is false, content.text is valid JSON deserializable to list of TrustScore objects
      - If isError is true, content.text is valid JSON deserializable to ToolError

    Errors:
      - validation_error (ToolError): TrustToolInput fails Pydantic validation
          error_type: validation_error
          message: Input validation failed
      - pipeline_failure (ToolError): Trust score retrieval raises an exception in the pipeline
          error_type: pipeline_error
          message: Trust score retrieval failed
      - internal_error (ToolError): Unexpected exception in handler logic (catch-all)
          error_type: internal_error
          message: Unexpected internal error

    Side effects: none
    Idempotent: yes
    """
    ...

async def handle_history(
    input: HistoryToolInput,
) -> McpToolResult:
    """
    Tool handler for exemplar_history. Validates HistoryToolInput, queries Kindex for matching past reviews via the pipeline, and returns them as structured JSON in an McpToolResult. Never raises unhandled exceptions. PACT key: mcp_server.handle_history.

    Preconditions:
      - Pipeline has been injected via create_server()
      - If date_from and date_to are both provided, date_from <= date_to

    Postconditions:
      - Result contains exactly one McpContentBlock of type 'text'
      - If isError is false, content.text is valid JSON deserializable to list of KindexEntry objects
      - If isError is true, content.text is valid JSON deserializable to ToolError
      - Returned list length <= input.limit

    Errors:
      - validation_error (ToolError): HistoryToolInput fails Pydantic validation (e.g. invalid date format, limit out of range)
          error_type: validation_error
          message: Input validation failed
      - invalid_date_range (ToolError): date_from is after date_to
          error_type: validation_error
          message: date_from must not be after date_to
      - pipeline_failure (ToolError): Kindex query raises an exception in the pipeline
          error_type: pipeline_error
          message: History query failed
      - internal_error (ToolError): Unexpected exception in handler logic (catch-all)
          error_type: internal_error
          message: Unexpected internal error

    Side effects: none
    Idempotent: yes
    """
    ...

def build_tool_error(
    error_type: str,           # custom(value in ('validation_error', 'pipeline_error', 'io_error', 'internal_error'))
    message: str,              # length(min=1, max=4096)
    pact_key: str,
    field_errors: optional[list[FieldError]] = None,
) -> McpToolResult:
    """
    Pure helper that constructs a ToolError and wraps it in an McpToolResult with isError=True. Used by all tool handlers for consistent error response formatting. PACT key: mcp_server.build_tool_error.

    Postconditions:
      - Returned McpToolResult.isError is True
      - Returned content has exactly one McpContentBlock of type 'text'
      - content.text is valid JSON deserializable to ToolError

    Side effects: none
    Idempotent: yes
    """
    ...

def build_success_result(
    data: any,
) -> McpToolResult:
    """
    Pure helper that serializes a Pydantic model (or list of models) to deterministic JSON and wraps it in an McpToolResult with isError=False. PACT key: mcp_server.build_success_result.

    Preconditions:
      - data is a Pydantic BaseModel instance or a list of Pydantic BaseModel instances

    Postconditions:
      - Returned McpToolResult.isError is False
      - Returned content has exactly one McpContentBlock of type 'text'
      - content.text is deterministic JSON (sorted keys, no extra whitespace beyond standard compact form)

    Errors:
      - serialization_error (TypeError): data cannot be serialized to JSON (not a valid Pydantic model)
          message: Data must be a Pydantic BaseModel or list of BaseModel instances

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['OutputFormat', 'ReviewToolInput', 'TrustToolInput', 'HistoryToolInput', 'ToolError', 'FieldError', 'McpContentBlock', 'McpToolResult', 'PipelineProtocol', 'ServerConfig', 'optional', 'create_server', 'ValidationError', 'run_server', 'handle_review', 'handle_trust', 'handle_history', 'build_tool_error', 'build_success_result']
