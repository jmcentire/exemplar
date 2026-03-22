# === Diff Intake & Classification (intake) v1 ===
#  Dependencies: schemas, config, chronicle
# Async module that parses unified diff text into DiffHunk records. Extracts file paths, changed line numbers, context lines, and hunk metadata. Applies Ledger field classification rules to flag hunks containing potential secrets, PII, or internal API references. Output: list of classified DiffHunks ready for circuit routing. Handles malformed diffs gracefully with partial-success semantics and clear error messages. Supports reading from file path or stdin via a DiffSource protocol abstraction. Two-phase architecture: pure parse phase (deterministic string processing) followed by classify phase (pre-compiled Ledger regex rules applied to added_lines only). All public functions carry PACT keys for Sentinel attribution. Chronicler events emitted at stage boundaries via fire-and-forget EventEmitter protocol.

# Module invariants:
#   - All DiffHunk instances are frozen Pydantic models (immutable after creation)
#   - All IntakeError instances are frozen Pydantic models (immutable after creation)
#   - All IntakeResult instances are frozen Pydantic models (immutable after creation)
#   - Hunk IDs are deterministic: identical (file_path, raw_header, added_lines) always produce identical HunkId
#   - Classification is applied exclusively to added_lines — removed_lines and context_lines are never scanned for classification
#   - parse_diff is a pure function: no side effects, deterministic output for identical input
#   - classify_hunks is a pure function: no side effects, deterministic output for identical input and config
#   - EventEmitter failures never block or abort intake processing (fire-and-forget pattern)
#   - PACT keys are embedded in all public function signatures for Sentinel attribution
#   - EXTENSION_LANGUAGE_MAP is a module-level constant dict and never mutated at runtime
#   - Partial success is the default: malformed sections produce IntakeErrors while valid sections produce DiffHunks
#   - Regex patterns from LedgerConfig are pre-compiled once per classify_hunks call and reused across all hunks
#   - All timestamps use ISO 8601 UTC format

class DiffSourceKind(Enum):
    """Discriminator for the origin of diff text input."""
    file = "file"
    stdin = "stdin"

class ClassificationLabel(Enum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"

class LineRange:
    """A contiguous range of line numbers within a single file side (old or new). Frozen Pydantic model."""
    start: int                               # required, range(>=1), First line number in the range (1-based).
    count: int                               # required, range(>=0), Number of lines in the range.

class HunkMetadata:
    """Parsed header metadata from a single unified diff hunk (the @@ line). Frozen Pydantic model."""
    old_range: LineRange                     # required, Line range in the original (pre-change) file.
    new_range: LineRange                     # required, Line range in the modified (post-change) file.
    section_header: str = None               # optional, Optional function/class name from the @@ header trailing text.

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

HunkId = primitive  # Deterministic hunk identifier: 'hunk-' prefix followed by 12 lowercase hex characters derived from SHA-256 hash of (file_path + raw_header + added_lines content).

FilePath = primitive  # A validated filesystem path string. Must be non-empty when required and contain only valid path characters.

ReviewRequestId = primitive  # Non-empty string identifier for a review request, used to correlate assessments, reports, and Chronicler events.

class IntakeError:
    """Frozen Pydantic model capturing a parse or classification error with location context. Not an exception — a data record for partial-success reporting."""
    line_number: int = None                  # optional, 1-based line number in the raw diff where the error was detected. None if not locatable.
    message: str                             # required, length(>=1), Human-readable description of what went wrong.
    raw_content: str = None                  # optional, The raw text fragment that triggered the error, for diagnostics. None if not applicable.
    phase: IntakePhase                       # required, Which intake phase produced this error.

class IntakePhase(Enum):
    """Discriminator for which phase of intake processing produced an error or event."""
    read = "read"
    parse = "parse"
    classify = "classify"
    orchestrate = "orchestrate"

class IntakeResult:
    """Frozen Pydantic model wrapping the complete output of run_intake. Supports partial success: some hunks may parse successfully while others produce errors."""
    review_request: ReviewRequest            # required, The assembled ReviewRequest with classified hunks, ready for circuit routing.
    errors: list                             # required, Errors encountered during parsing or classification. Non-empty does not mean total failure.
    warnings: list                           # required, Non-fatal warnings (e.g., unknown file extensions, very large hunks truncated).
    hunk_count: int                          # required, range(>=0), Total number of successfully parsed and classified hunks.
    classified_hunk_count: int               # required, range(>=0), Number of hunks that received at least one non-NONE classification.

class ReviewRequest:
    """The output of intake: a complete review request containing parsed and classified hunks."""
    id: str                                  # required, Unique review request identifier.
    source: str                              # required, Source identifier (e.g., file path, PR URL, stdin).
    hunks: list[DiffHunk]                    # required, Parsed and classified diff hunks.
    file_paths: list[str]                    # required, Deduplicated list of all file paths in the diff.
    created_at: str                          # required, ISO-8601 timestamp of when the request was created.
    metadata: dict[str, str]                 # required, Arbitrary key-value metadata (PR number, branch, author, etc.).

class DiffSource:
    """runtime_checkable Protocol with a single async read() -> str method. Concrete implementations: FileDiffSource (reads from Path) and StdinDiffSource (reads from sys.stdin). This type represents the Protocol interface; implementations are not separate contract types."""
    kind: DiffSourceKind                     # required, Discriminator indicating file or stdin source.

class EventEmitter:
    """runtime_checkable Protocol for Chronicler event emission. Single method: async emit(event: ChroniclerEvent) -> None. Used in fire-and-forget pattern — emission failures must not block intake processing."""
    pass

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

class LedgerConfig:
    """Configuration for Ledger field classification: rules for detecting secrets, PII, and internal APIs."""
    rules: list[LedgerFieldRule]             # required, Ordered list of classification rules. First match wins per label category.
    default_label: ClassificationLabel       # required, Default label when no rule matches.

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

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

class LedgerFieldRule:
    """A single Ledger classification rule: a regex pattern mapped to a classification label."""
    pattern: str                             # required, Regex pattern to match against diff hunk content.
    label: ClassificationLabel               # required, Classification label to apply when pattern matches.
    description: str = None                  # optional, Human-readable description of what this rule detects.

async def parse_diff(
    raw: str,
) -> tuple[list[DiffHunk], list[IntakeError]]:
    """
    Pure parsing of unified diff text into DiffHunk records. Deterministic: same input always produces identical output. No classification is applied (classifications field will be empty list). Handles malformed input gracefully by returning partial results alongside IntakeError records. Language detection is applied via EXTENSION_LANGUAGE_MAP during file path extraction. Hunk IDs are generated deterministically via SHA-256. This is the first phase of the two-phase intake architecture.

    Preconditions:
      - raw is a str (may be empty)
      - No external state is read or mutated

    Postconditions:
      - Every returned DiffHunk has a deterministic id derived from SHA-256(file_path + raw_header + added_lines)
      - DiffHunk.classifications is always an empty list (classification happens in classify_hunks)
      - DiffHunk.classification_evidence is always an empty list
      - If raw is empty string, returns ([], []) with no errors
      - Every DiffHunk.file_path is non-empty and uses forward slashes
      - Every DiffHunk.language is populated from EXTENSION_LANGUAGE_MAP or 'unknown'
      - Line numbers in HunkMetadata are consistent with actual line counts
      - Each IntakeError has phase='parse' and a non-empty message
      - The union of successfully parsed hunks and errors accounts for all hunk-like sections in the input

    Errors:
      - empty_input (none): raw is an empty string
          behavior: Returns ([], []) — no hunks, no errors. Not considered an error.
      - no_diff_headers (IntakeError): raw contains text but no recognizable '---'/'+++' or 'diff --git' headers
          phase: parse
          message: No diff headers found in input. Expected unified diff format.
      - malformed_hunk_header (IntakeError): A @@ line cannot be parsed as a valid hunk range
          phase: parse
          message: Malformed hunk header: could not extract line ranges.
      - truncated_hunk (IntakeError): Diff ends mid-hunk without another header or EOF marker
          phase: parse
          message: Hunk appears truncated — fewer lines than header declares.
      - binary_file_marker (IntakeError): Diff contains 'Binary files ... differ' marker
          phase: parse
          message: Binary file diff detected; cannot parse as text hunk.
      - invalid_utf8 (IntakeError): Input contains byte sequences that are not valid UTF-8 after decoding
          phase: parse
          message: Input contains invalid character sequences.

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_hunks(
    hunks: list,
    config: LedgerConfig,
) -> list[DiffHunk]:
    """
    Applies Ledger field classification rules to a list of DiffHunks. For each hunk, scans only the added_lines against pre-compiled regex patterns from LedgerConfig to detect secrets, PII, and internal API references. Returns new frozen DiffHunk instances with classifications and classification_evidence populated. Sync function because it is CPU-bound regex matching with no I/O. This is the second phase of the two-phase intake architecture.

    Preconditions:
      - All input hunks have empty classifications lists (fresh from parse_diff)
      - config.secret_patterns, config.pii_patterns, config.internal_api_patterns are valid regex strings
      - Regex patterns in config have been validated at config load time

    Postconditions:
      - Output list has same length as input hunks list
      - Output hunks have same id, file_path, metadata, raw_header, context_lines, added_lines, removed_lines as input
      - Each output hunk's classifications contains zero or more ClassificationLabel values (no duplicates per hunk)
      - classification_evidence has same length as classifications for each hunk
      - Classification is based solely on added_lines content — removed_lines and context_lines are not scanned
      - A hunk with no pattern matches has classifications=[] and classification_evidence=[]
      - Order of output hunks matches order of input hunks

    Errors:
      - invalid_regex_pattern (ValueError): A pattern in LedgerConfig fails to compile as a valid regex
          message: Ledger config contains invalid regex pattern: <pattern>
      - empty_hunks_list (none): hunks is an empty list
          behavior: Returns empty list. Not considered an error.

    Side effects: none
    Idempotent: yes
    """
    ...

async def run_intake(
    source: DiffSource,
    config: LedgerConfig,
    emit: EventEmitter = None,
) -> IntakeResult:
    """
    Top-level async orchestrator for the intake module. Reads diff text from a DiffSource, invokes parse_diff, then classify_hunks, assembles a ReviewRequest with a UUID4-based id, and returns an IntakeResult. Emits three Chronicler events via the optional EventEmitter: 'review.intake.started' before reading, 'review.intake.parsed' after parse phase, 'review.intake.classified' after classification. Event emission uses fire-and-forget pattern — emission failures are caught and logged as warnings, never blocking intake processing. PACT key embedded for Sentinel attribution.

    Preconditions:
      - source conforms to DiffSource protocol (has async read() -> str method)
      - config is a valid LedgerConfig with compilable regex patterns
      - If emit is provided, it conforms to EventEmitter protocol

    Postconditions:
      - IntakeResult.review_request.id starts with 'req-' and contains a UUID4 hex string
      - IntakeResult.review_request.hunks contains only fully classified DiffHunks
      - IntakeResult.hunk_count == len(IntakeResult.review_request.hunks)
      - IntakeResult.classified_hunk_count <= IntakeResult.hunk_count
      - IntakeResult.errors collects all IntakeErrors from both parse and classify phases plus any read errors
      - IntakeResult.review_request.source_kind matches source.kind
      - IntakeResult.review_request.created_at is a valid ISO 8601 UTC timestamp
      - If emit is provided, exactly 3 Chronicler events were attempted (started, parsed, classified)
      - Emission failures appear as warnings in IntakeResult.warnings, not as errors

    Errors:
      - source_read_failure (IntakeError): source.read() raises an IOError, FileNotFoundError, or PermissionError
          phase: read
          message: Failed to read diff from source: <detail>
      - source_read_timeout (IntakeError): source.read() does not complete within a reasonable time (e.g., stdin with no input and no EOF)
          phase: read
          message: Timed out reading from source.
      - totally_unparseable (none): parse_diff returns zero hunks and one or more errors
          behavior: Returns IntakeResult with empty hunks list and all errors. Not raised as exception.
      - emitter_failure (none): EventEmitter.emit() raises any exception
          behavior: Exception is caught, logged as warning in IntakeResult.warnings, intake continues.
      - config_regex_failure (IntakeError): classify_hunks raises ValueError due to invalid regex in config
          phase: classify
          message: Classification failed: invalid regex pattern in Ledger config.

    Side effects: Reads from file system or stdin via DiffSource, Emits up to 3 Chronicler events via EventEmitter (fire-and-forget), Generates UUID4 for ReviewRequest ID (non-deterministic)
    Idempotent: no
    """
    ...

def generate_hunk_id(
    file_path: str,
    raw_header: str,
    added_lines: list,
) -> HunkId:
    """
    Internal helper that generates a deterministic hunk identifier by computing SHA-256 over the concatenation of file_path, raw_header, and joined added_lines, then truncating to 12 hex characters and prefixing with 'hunk-'. Exposed in contract for testability and specification clarity.

    Preconditions:
      - file_path is a non-empty string
      - raw_header is a non-empty string

    Postconditions:
      - Result starts with 'hunk-'
      - Result after prefix is exactly 12 lowercase hexadecimal characters
      - Same inputs always produce same output (deterministic)
      - Different inputs produce different outputs with overwhelming probability (SHA-256 collision resistance)

    Errors:
      - empty_file_path (ValueError): file_path is empty string
          message: file_path must not be empty for hunk ID generation.

    Side effects: none
    Idempotent: yes
    """
    ...

def generate_request_id() -> ReviewRequestId:
    """
    Internal helper that generates a ReviewRequest identifier by creating a UUID4 and prefixing it with 'req-'. Non-deterministic due to UUID4 randomness.

    Postconditions:
      - Result starts with 'req-'
      - Result after prefix is a valid 32-character hexadecimal UUID4 string (no hyphens)
      - Each call returns a unique value with overwhelming probability

    Side effects: none
    Idempotent: no
    """
    ...

def detect_language(
    file_path: str,
) -> str:
    """
    Internal helper that maps a file path's extension to a programming language name using the module-level EXTENSION_LANGUAGE_MAP constant. Returns 'unknown' for unrecognized extensions or files without extensions.

    Preconditions:
      - file_path is a non-empty string

    Postconditions:
      - Result is a lowercase language name string from EXTENSION_LANGUAGE_MAP or 'unknown'
      - Matching is case-insensitive on the file extension
      - Dotfiles without a secondary extension return 'unknown'

    Errors:
      - empty_path (ValueError): file_path is empty string
          message: file_path must not be empty for language detection.

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['DiffSourceKind', 'ClassificationLabel', 'LineRange', 'HunkMetadata', 'DiffHunk', 'IntakeError', 'IntakePhase', 'IntakeResult', 'ReviewRequest', 'DiffSource', 'EventEmitter', 'ChroniclerEvent', 'LedgerConfig', 'ReviewStage', 'ChroniclerEventType', 'LedgerFieldRule', 'parse_diff', 'none', 'classify_hunks', 'run_intake', 'generate_hunk_id', 'generate_request_id', 'detect_language']
