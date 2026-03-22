# === Report Formatter & Sealer (reporter) v1 ===
#  Dependencies: schemas, chronicle
# Formats ReviewReport into three output formats: JSON (validates against schema), Markdown (human-readable with severity badges), GitHub-compatible PR comment (collapsible sections per stage). Deterministic output: injectable timestamps, sorted keys, canonical serialization. Applies Tessera seal to final report (hash-chain proof over content). Includes verify function that confirms seal integrity and detects post-seal modification. Emits report.sealed Chronicler event via injectable callback. Module constant PACT_COMPONENT = 'reporter' for Sentinel attribution.

# Module invariants:
#   - PACT_COMPONENT module constant is always 'reporter' and is included in all ChroniclerEvent payloads and FormattedReport.metadata
#   - canonicalize is the single source of truth for content hashing: both seal_report and verify_seal use canonicalize to compute content_hash
#   - Seal content_hash is always SHA-256 of canonicalize(report_with_seal_set_to_None)
#   - Seal chain_hash is always SHA-256 of (content_hash + '|' + (previous_hash or 'GENESIS'))
#   - All hash values are lowercase hex-encoded 64-character strings
#   - All ReviewReport instances are frozen (immutable): seal_report returns a new instance via model_copy, never mutates the input
#   - FormattedReport instances are frozen (immutable)
#   - SealVerificationResult instances are frozen (immutable)
#   - verify_seal never raises exceptions: all error states are captured in the return value
#   - Injectable timestamps: all functions that produce timestamps accept an optional timestamp parameter; if None, use datetime.utcnow().isoformat() + 'Z'
#   - GitHub format output never exceeds 65000 characters (truncation with notice is applied)
#   - JSON format output from format_report uses 2-space indent (readable), while canonicalize uses compact separators (for hashing)
#   - ChroniclerCallback errors are always caught and suppressed (fire-and-forget pattern)
#   - Determinism: identical inputs with identical injectable timestamps produce byte-identical outputs across all format_report and canonicalize calls
#   - Severity badge mapping is fixed: 🔴=critical, 🟠=high, 🟡=medium, 🔵=low, ⚪=info

class OutputFormat(Enum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"

class SealVerificationStatus(Enum):
    """Outcome status of a seal verification check. StrEnum in implementation."""
    valid = "valid"
    invalid_content_hash = "invalid_content_hash"
    invalid_chain_hash = "invalid_chain_hash"
    missing_seal = "missing_seal"
    verification_error = "verification_error"

class FormattedReport:
    """Component-local frozen Pydantic model containing the rendered report string, seal status, and metadata. Immutable (frozen=True)."""
    content: str                             # required, The fully rendered report string in the requested output format.
    output_format: OutputFormat              # required, Which format was used to render the report.
    report_id: ReportId                      # required, Unique identifier of the source ReviewReport.
    is_sealed: bool                          # required, Whether the source ReviewReport had a valid TesseraSeal attached at render time.
    character_count: int                     # required, range(value >= 0), Length of the content string in characters.
    truncated: bool                          # required, True if content was truncated (only applicable to github format at 65000 char limit).
    rendered_at: Iso8601Timestamp            # required, ISO 8601 UTC timestamp of when the report was rendered.
    metadata: dict                           # required, Additional metadata including pact_component attribution key and any format-specific info.

class SealVerificationResult:
    """Frozen Pydantic model containing the full result of a seal integrity verification. Immutable (frozen=True)."""
    status: SealVerificationStatus           # required, Overall verification outcome.
    valid: bool                              # required, Convenience boolean: True iff status == 'valid'.
    content_hash_match: bool                 # required, Whether the recomputed content_hash matches the seal's content_hash.
    chain_hash_match: bool                   # required, Whether the recomputed chain_hash matches the seal's chain_hash.
    expected_content_hash: Sha256Hex         # required, The content_hash stored in the seal. Empty string if seal is missing.
    actual_content_hash: Sha256Hex           # required, The content_hash recomputed from the report content. Empty string if computation failed.
    expected_chain_hash: Sha256Hex           # required, The chain_hash stored in the seal. Empty string if seal is missing.
    actual_chain_hash: Sha256Hex             # required, The chain_hash recomputed from content_hash and previous_hash. Empty string if computation failed.
    error: str                               # required, Human-readable error message if verification failed. Empty string on success.

ReportId = primitive  # Opaque unique identifier for a ReviewReport. Non-empty string.

Iso8601Timestamp = primitive  # ISO 8601 UTC timestamp string ending in 'Z'. Used for deterministic injectable timestamps.

Sha256Hex = primitive  # A SHA-256 hash value represented as a 64-character lowercase hexadecimal string. May be empty string when hash is unavailable (e.g. missing seal).

SealerId = primitive  # Identifier of the entity (component or operator) applying the Tessera seal. Non-empty string.

ChroniclerCallback = primitive  # Injectable callback type: Callable[[ChroniclerEvent], None] | None. When provided, called fire-and-forget (wrapped in try/except) after sealing to emit report.sealed events. None means no event emission.

class SealChainStoreProtocol:
    """Protocol (runtime_checkable) abstracting seal chain persistence. Implementations read/write seal chain data (e.g. JSON lines file). Keeps file I/O out of the formatter for pure-logic testing per SOPs."""
    get_previous_hash: str                   # required, Async method signature: async def get_previous_hash() -> str | None. Returns the most recent chain_hash from the seal chain store, or None if the chain is empty (GENESIS case).
    append_seal: str                         # required, Async method signature: async def append_seal(seal: TesseraSeal) -> None. Appends a completed seal record to the chain store.

GitHubTruncationNotice = primitive  # Constant string appended when GitHub format output exceeds 65000 characters. Value: '\n\n---\n⚠️ *Report truncated. Full report available in JSON format.*'

GithubCharLimit = primitive  # Maximum character count for GitHub PR comment format. Constant value: 65000.

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

class TrustScore:
    """Arbiter trust weight for a reviewer agent, used in weighted assessment merging."""
    reviewer_id: str                         # required, Identifier of the reviewer this score applies to.
    stage: ReviewStage                       # required, Stage the reviewer operates in.
    weight: float                            # required, range(0.0 <= value <= 1.0), Trust weight in range [0.0, 1.0].
    accepted_count: int                      # required, Number of findings from this reviewer that humans accepted.
    dismissed_count: int                     # required, Number of findings from this reviewer that humans dismissed.
    updated_at: str                          # required, ISO-8601 timestamp of last trust score update.

class TesseraSeal:
    """A hash-chain tamper-proof seal over serialized content, verifiable independently."""
    content_hash: str                        # required, SHA-256 hash of the canonical JSON content that was sealed.
    previous_hash: Optional[str] = null      # optional, Hash of the previous seal in the chain (null for first seal).
    chain_hash: str                          # required, SHA-256 hash of (content_hash + previous_hash), forming the chain link.
    sealed_at: str                           # required, ISO-8601 timestamp of when the seal was created.
    sealer_id: str                           # required, Identifier of the entity that created this seal.

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

def canonicalize(
    report: ReviewReport,
) -> bytes:
    """
    Pure function: produces the canonical byte representation of a ReviewReport for hashing. Creates a seal-excluded copy of the report (seal=None), calls model_dump(mode='json'), then serializes with json.dumps(sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf-8'). This is the single source of truth for content hashing — both seal_report and verify_seal must use this function. No side effects.

    Preconditions:
      - report is a valid ReviewReport instance (Pydantic-validated)
      - report has a non-empty report_id

    Postconditions:
      - Return value is valid UTF-8 encoded JSON bytes
      - Return value is deterministic: same report content always produces identical bytes
      - Seal field is excluded from canonical representation (set to None before dump)
      - JSON keys are sorted lexicographically at all nesting levels
      - No whitespace padding in output (compact separators (',', ':'))
      - Calling canonicalize twice on the same report yields byte-identical output

    Errors:
      - serialization_failure (ReporterSerializationError): The report contains data that cannot be serialized to JSON via model_dump(mode='json')
          report_id: The report_id of the failing report
          detail: Description of the serialization failure

    Side effects: none
    Idempotent: yes
    """
    ...

async def seal_report(
    report: ReviewReport,
    chain_store: SealChainStoreProtocol,
    sealer_id: SealerId,
    timestamp: Iso8601Timestamp = None,
    chronicler_callback: ChroniclerCallback = None,
) -> ReviewReport:
    """
    Applies a Tessera seal to a ReviewReport. Computes content_hash as SHA-256 of canonicalize(report), retrieves previous_hash from the SealChainStoreProtocol (or uses the explicit previous_hash override), computes chain_hash as SHA-256 of (content_hash + '|' + (previous_hash or 'GENESIS')). Returns a new ReviewReport (via model_copy) with the TesseraSeal attached. Appends the seal to the chain store. Emits report.sealed ChroniclerEvent via the injectable callback if provided (fire-and-forget). Timestamp is injectable for deterministic testing.

    Preconditions:
      - report is a valid ReviewReport instance
      - report.seal is None (report is not already sealed)
      - sealer_id is a non-empty string
      - chain_store conforms to SealChainStoreProtocol

    Postconditions:
      - Returned ReviewReport is a new instance (original is not mutated, frozen model)
      - Returned report.seal is a valid TesseraSeal with non-empty content_hash, chain_hash, sealed_at, and sealer_id
      - content_hash == SHA-256(canonicalize(original_report))
      - chain_hash == SHA-256(content_hash + '|' + (previous_hash or 'GENESIS'))
      - Seal has been appended to chain_store via append_seal
      - All fields of the returned report except seal are identical to the input report
      - If chronicler_callback was provided, report.sealed event was attempted (failure does not affect return value)

    Errors:
      - already_sealed (ReporterSealError): report.seal is not None — the report already has a seal attached
          report_id: The report_id
          detail: Report is already sealed
      - chain_store_read_failure (ReporterChainStoreError): chain_store.get_previous_hash() raises an exception (e.g. file not found, permission denied)
          report_id: The report_id
          operation: get_previous_hash
          detail: Underlying error message
      - chain_store_write_failure (ReporterChainStoreError): chain_store.append_seal() raises an exception (e.g. disk full, permission denied)
          report_id: The report_id
          operation: append_seal
          detail: Underlying error message
      - canonicalization_failure (ReporterSerializationError): canonicalize(report) raises ReporterSerializationError
          report_id: The report_id
          detail: Canonicalization failed

    Side effects: Appends seal record to SealChainStoreProtocol (file I/O via chain store), Optionally emits report.sealed ChroniclerEvent via callback (fire-and-forget)
    Idempotent: no
    """
    ...

def verify_seal(
    report: ReviewReport,
) -> SealVerificationResult:
    """
    Pure verification function: recomputes content_hash from the report via canonicalize(), recomputes chain_hash from content_hash and the seal's previous_hash, and compares both against the values stored in the seal. Returns a SealVerificationResult with match booleans and expected/actual hash values. Does not perform any I/O or mutate state. Does not access the chain store — verification is self-contained using only the report and its embedded seal.

    Preconditions:
      - report is a valid ReviewReport instance

    Postconditions:
      - If report.seal is None, returns SealVerificationResult with status='missing_seal', valid=False
      - If content_hash matches and chain_hash matches, returns status='valid', valid=True
      - If content_hash does not match, returns status='invalid_content_hash', valid=False
      - If content_hash matches but chain_hash does not match, returns status='invalid_chain_hash', valid=False
      - expected_content_hash and expected_chain_hash are taken from the seal
      - actual_content_hash and actual_chain_hash are freshly recomputed
      - Function never raises exceptions — all errors are captured in the error field with status='verification_error'

    Errors:
      - missing_seal (SealVerificationResult): report.seal is None — no seal is attached to verify
          status: missing_seal
          valid: False
          error: Report has no seal attached
      - canonicalization_failure_during_verify (SealVerificationResult): canonicalize(report) fails during hash recomputation
          status: verification_error
          valid: False
          error: Failed to canonicalize report for verification

    Side effects: none
    Idempotent: yes
    """
    ...

def format_report(
    report: ReviewReport,
    output_format: OutputFormat,
    timestamp: Iso8601Timestamp = None,
) -> FormattedReport:
    """
    Renders a ReviewReport into the specified OutputFormat. For JSON: canonical serialization with 2-space indent for readability (distinct from the compact canonical form used for hashing). For Markdown: severity emoji badges (🔴 critical, 🟠 high, 🟡 medium, 🔵 low, ⚪ info), findings grouped by ReviewStage, summary stats table. For GitHub: collapsible <details> sections per stage, truncation at 65000 characters with truncation notice appended. Timestamp is injectable for deterministic output. Returns a FormattedReport frozen model.

    Preconditions:
      - report is a valid ReviewReport instance
      - output_format is a valid OutputFormat variant

    Postconditions:
      - Returned FormattedReport.content is a non-empty string in the requested format
      - Returned FormattedReport.output_format matches the requested output_format
      - Returned FormattedReport.report_id matches report.report_id
      - Returned FormattedReport.is_sealed reflects whether report.seal is not None
      - Returned FormattedReport.character_count == len(FormattedReport.content)
      - For github format: if character_count > 65000, content is truncated and truncated=True
      - For json and markdown formats: truncated is always False
      - Returned FormattedReport.metadata contains key 'pact_component' with value 'reporter'
      - Output is deterministic: same inputs with same timestamp produce identical output
      - For json format: output is valid JSON parseable by json.loads()
      - For markdown format: output contains severity emoji badges for each finding
      - For github format: output contains <details> sections for each stage with findings

    Errors:
      - unsupported_format (ReporterFormatError): output_format is not one of the supported OutputFormat variants
          output_format: The unsupported format string
          supported_formats: json, markdown, github
      - rendering_failure (ReporterRenderError): An unexpected error occurs during rendering (e.g. malformed report data that passes validation but causes template errors)
          report_id: The report_id
          output_format: The requested format
          detail: Description of the rendering failure

    Side effects: none
    Idempotent: yes
    """
    ...

def render_json(
    report: ReviewReport,
) -> str:
    """
    Internal renderer: serializes the ReviewReport to a human-readable JSON string with 2-space indentation, sorted keys, and ensure_ascii=False. This is the readable format (distinct from the compact canonical form used by canonicalize for hashing). Includes the seal in the output if present.

    Preconditions:
      - report is a valid ReviewReport instance

    Postconditions:
      - Output is valid JSON parseable by json.loads()
      - Output uses 2-space indentation
      - JSON keys are sorted lexicographically at all nesting levels
      - Output includes seal data if report.seal is not None

    Errors:
      - json_serialization_failure (ReporterSerializationError): Report data cannot be serialized to JSON
          report_id: The report_id
          detail: JSON serialization failed

    Side effects: none
    Idempotent: yes
    """
    ...

def render_markdown(
    report: ReviewReport,
    timestamp: Iso8601Timestamp,
) -> str:
    """
    Internal renderer: produces a Markdown string with severity emoji badges (🔴 critical, 🟠 high, 🟡 medium, 🔵 low, ⚪ info), findings grouped by ReviewStage, a summary statistics table with counts per severity, and seal status section if sealed. Deterministic ordering: stages sorted by enum order, findings within stage sorted by severity descending then by file path ascending.

    Preconditions:
      - report is a valid ReviewReport instance

    Postconditions:
      - Output contains a top-level heading with report_id
      - Each finding has its severity emoji badge prefixed
      - Findings are grouped under stage-level headings
      - A summary table lists finding counts per severity level
      - If report.seal is not None, a seal status section is included

    Errors:
      - markdown_rendering_failure (ReporterRenderError): Unexpected error during Markdown template rendering
          report_id: The report_id
          detail: Markdown rendering failed

    Side effects: none
    Idempotent: yes
    """
    ...

def render_github(
    report: ReviewReport,
    timestamp: Iso8601Timestamp,
) -> str:
    """
    Internal renderer: produces a GitHub-compatible PR comment with collapsible <details> sections per ReviewStage, severity emoji badges, finding details, and a summary header. Truncates to 65000 characters if the output exceeds the GitHub comment size limit, appending a truncation notice. Deterministic ordering: same as render_markdown.

    Preconditions:
      - report is a valid ReviewReport instance

    Postconditions:
      - Output contains <details> and <summary> tags for each stage with findings
      - Each finding has its severity emoji badge
      - If len(output) > 65000, output is truncated to 65000 chars and truncation notice is appended
      - If report has no findings for a stage, that stage section is omitted
      - Output is valid GitHub-flavored Markdown

    Errors:
      - github_rendering_failure (ReporterRenderError): Unexpected error during GitHub format rendering
          report_id: The report_id
          detail: GitHub rendering failed

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['OutputFormat', 'SealVerificationStatus', 'FormattedReport', 'SealVerificationResult', 'SealChainStoreProtocol', 'ReviewReport', 'Confidence', 'ReviewDecision', 'Finding', 'Assessment', 'TrustScore', 'TesseraSeal', 'Severity', 'ReviewStage', 'canonicalize', 'ReporterSerializationError', 'seal_report', 'ReporterSealError', 'ReporterChainStoreError', 'verify_seal', 'format_report', 'ReporterFormatError', 'ReporterRenderError', 'render_json', 'render_markdown', 'render_github']
