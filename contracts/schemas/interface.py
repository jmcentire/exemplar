# === Data Models & Schemas (schemas) v1 ===
# Frozen Pydantic v2 models and StrEnums forming the shared data contract for the entire Exemplar system. Provides: _ExemplarBase (shared frozen base with canonical_bytes()/canonical_hash() for deterministic hashing), 9 enums (Severity, Confidence, ReviewStage, ReviewDecision, ClassificationLabel, ChroniclerEventType, LearnerPhase, StigmergyVerb, CliExitCode), and 16 domain models in dependency order (ClassificationLabel → DiffHunk → ReviewRequest → Finding → Assessment → TrustScore → TesseraSeal → ReviewReport → ReviewerCredential → PolicyToken → ChroniclerEvent → StigmergySignal → LearningRecord → KindexEntry → PipelineResult). All models use frozen=True and extra='forbid'. Shallow-freeze semantics with list[]/dict[] fields. IsoTimestamp annotated type for ISO 8601 validation. JSON round-trip guarantee: M.model_validate_json(instance.model_dump_json()) == instance. PACT_KEY ClassVar on base model for Sentinel attribution. No ABC per SOP — concrete Pydantic base only. Module-level ordering functions for enums with comparison semantics. __all__ export control for clean imports.

# Module invariants:
#   - All models inherit from _ExemplarBase which sets frozen=True and extra='forbid' via ConfigDict
#   - No model uses ABC or abstract methods — only concrete Pydantic BaseModel per SOP
#   - All models satisfy JSON round-trip: M.model_validate_json(instance.model_dump_json()) == instance
#   - canonical_bytes() output is deterministic: same field values always produce identical bytes regardless of insertion order
#   - canonical_hash() returns SHA-256 hex digest of canonical_bytes()
#   - Models are defined in dependency order so no ForwardRef annotations are needed
#   - All list[] and dict[] fields use shallow-freeze semantics — the container is not deeply frozen
#   - IsoTimestamp fields accept only valid ISO 8601 strings and store them as str
#   - PACT_KEY ClassVar is present on _ExemplarBase and inherited by all models
#   - StrEnum is used for all text-valued enums; IntEnum only for CliExitCode
#   - Every public type is listed in __all__

str = primitive

int = primitive

float = primitive

bool = primitive

bytes = primitive

None = primitive

dict = primitive

list = primitive

any = primitive

IsoTimestamp = primitive  # Annotated str type validated against ISO 8601 format. Stored as plain str but guaranteed to parse as a valid ISO 8601 datetime string. Uses AfterValidator to reject non-conforming values at model construction time.

class Severity(Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class Confidence(Enum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

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

class LearnerPhase(Enum):
    """Apprentice learning phase progression stage."""
    shadow = "shadow"
    canary = "canary"
    primary = "primary"

class StigmergyVerb(Enum):
    """Stigmergy signal verb for inter-agent coordination. StrEnum."""
    deposit = "deposit"
    reinforce = "reinforce"
    decay = "decay"
    query = "query"

class CliExitCode(Enum):
    """CLI process exit codes mapping to review outcomes."""
    0 = "0"
    1 = "1"
    2 = "2"
    3 = "3"

class _ExemplarBase:
    """Shared frozen Pydantic v2 base model. ConfigDict(frozen=True, extra='forbid'). Provides canonical_bytes() and canonical_hash() methods. Contains PACT_KEY: ClassVar[str] = 'exemplar.schemas' for Sentinel attribution. All domain models inherit from this."""
    pass

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

class ReviewRequest:
    """The output of intake: a complete review request containing parsed and classified hunks."""
    id: str                                  # required, Unique review request identifier.
    source: str                              # required, Source identifier (e.g., file path, PR URL, stdin).
    hunks: list[DiffHunk]                    # required, Parsed and classified diff hunks.
    file_paths: list[str]                    # required, Deduplicated list of all file paths in the diff.
    created_at: str                          # required, ISO-8601 timestamp of when the request was created.
    metadata: dict[str, str]                 # required, Arbitrary key-value metadata (PR number, branch, author, etc.).

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

class ReviewerCredential:
    """Signet identity credential for a reviewer agent, used for authentication and attribution."""
    reviewer_id: str                         # required, Unique identifier for this reviewer agent.
    display_name: str                        # required, Human-readable name of the reviewer.
    stage: ReviewStage                       # required, Primary stage this reviewer operates in.
    public_key_hex: str                      # required, Hex-encoded public key for signature verification.
    created_at: str                          # required, ISO-8601 timestamp of credential creation.
    is_active: bool                          # required, Whether this credential is currently active.

class PolicyToken:
    """Agent-Safe policy token defining what a reviewer agent is permitted to access and do."""
    token_id: str                            # required, Unique token identifier.
    reviewer_id: str                         # required, Reviewer agent this token is issued to.
    allowed_file_patterns: list[str]         # required, Glob patterns for files the reviewer may inspect.
    denied_file_patterns: list[str]          # required, Glob patterns for files the reviewer must NOT inspect.
    allowed_classifications: list[ClassificationLabel] # required, Classification labels the reviewer is permitted to see.
    max_severity: Severity                   # required, Maximum severity level the reviewer is allowed to emit.
    issued_at: str                           # required, ISO-8601 timestamp of token issuance.
    expires_at: Optional[str] = null         # optional, ISO-8601 expiry timestamp, null if non-expiring.

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

class KindexEntry:
    """A Kindex knowledge store entry representing a past review or codebase context artifact."""
    key: str                                 # required, Unique key for retrieval (e.g., review request ID or context topic).
    kind: str                                # required, Entry kind: 'review', 'context', 'pattern'.
    summary: str                             # required, Human-readable summary for search and display.
    data: dict[str, str]                     # required, Structured data payload of the entry.
    tags: list[str]                          # required, Tags for query filtering.
    created_at: str                          # required, ISO-8601 timestamp of entry creation.
    updated_at: str                          # required, ISO-8601 timestamp of last update.

class PipelineResult:
    """End-to-end pipeline result returned by the core pipeline, used by both CLI and MCP server."""
    review_request: ReviewRequest            # required, The parsed review request.
    assessments: list[Assessment]            # required, All individual stage assessments.
    report: ReviewReport                     # required, The final merged and sealed report.
    events: list[ChroniclerEvent]            # required, All Chronicler events emitted during the pipeline.
    formatted_output: str                    # required, The report formatted in the requested output format.
    output_format: OutputFormat              # required, The format used for formatted_output.
    exit_code: int                           # required, Numeric exit code: 0=pass, 1=warn, 2=block, 3=error.

class OutputFormat(Enum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"

def severity_rank(
    severity: Severity,
) -> int:
    """
    Returns an integer rank for a Severity enum value. Higher rank = more severe. critical=4, high=3, medium=2, low=1, info=0. Pure function, no side effects. Used for sorting and comparison of severity levels across the system.

    Preconditions:
      - severity must be a valid Severity enum member

    Postconditions:
      - returned value is in range [0, 4]
      - critical > high > medium > low > info

    Errors:
      - invalid_severity (ValueError): severity is not a valid Severity enum member
          detail: Unknown severity value

    Side effects: none
    Idempotent: yes
    """
    ...

def confidence_rank(
    confidence: Confidence,
) -> int:
    """
    Returns an integer rank for a Confidence enum value. Higher rank = more confident. high=2, medium=1, low=0. Pure function, no side effects.

    Preconditions:
      - confidence must be a valid Confidence enum member

    Postconditions:
      - returned value is in range [0, 2]
      - high > medium > low

    Errors:
      - invalid_confidence (ValueError): confidence is not a valid Confidence enum member
          detail: Unknown confidence value

    Side effects: none
    Idempotent: yes
    """
    ...

def learner_phase_rank(
    phase: LearnerPhase,
) -> int:
    """
    Returns an integer rank for a LearnerPhase enum value. Higher rank = more advanced phase. observe=0, suggest=1, act=2, reflect=3. Pure function, no side effects.

    Preconditions:
      - phase must be a valid LearnerPhase enum member

    Postconditions:
      - returned value is in range [0, 3]
      - reflect > act > suggest > observe

    Errors:
      - invalid_phase (ValueError): phase is not a valid LearnerPhase enum member
          detail: Unknown learner phase value

    Side effects: none
    Idempotent: yes
    """
    ...

def canonical_bytes(
    self: _ExemplarBase,
) -> bytes:
    """
    Instance method on _ExemplarBase. Returns deterministic JSON bytes of the model instance suitable for SHA-256 hashing. Uses model_dump(mode='json') serialized with sort_keys=True and compact separators (',', ':'). The output is stable across Python dict insertion order and is used by TesseraSeal for hash-chain proofs. PACT_KEY attribution: docstring references _ExemplarBase.PACT_KEY for Sentinel tracing.

    Preconditions:
      - self is a valid _ExemplarBase subclass instance that passes Pydantic validation

    Postconditions:
      - output is valid UTF-8 encoded JSON
      - output is deterministic: identical field values always produce identical bytes
      - json.loads(output) produces a dict equivalent to self.model_dump(mode='json')
      - calling canonical_bytes() twice on the same instance returns identical bytes

    Side effects: none
    Idempotent: yes
    """
    ...

def canonical_hash(
    self: _ExemplarBase,
) -> str:
    """
    Instance method on _ExemplarBase. Returns the hex SHA-256 digest of canonical_bytes(). Used by TesseraSeal.content_hash and TesseraSeal.seal_hash for hash-chain integrity verification. PACT_KEY attribution: docstring references _ExemplarBase.PACT_KEY for Sentinel tracing.

    Preconditions:
      - self is a valid _ExemplarBase subclass instance that passes Pydantic validation

    Postconditions:
      - output is a 64-character lowercase hexadecimal string
      - output == hashlib.sha256(self.canonical_bytes()).hexdigest()
      - output is deterministic for identical field values

    Side effects: none
    Idempotent: yes
    """
    ...

def validate_iso_timestamp(
    value: str,
) -> str:
    """
    Validator function for the IsoTimestamp annotated type. Accepts a string, validates it conforms to ISO 8601 datetime format (using datetime.fromisoformat()), and returns the original string unchanged. Used as an AfterValidator in the Annotated type definition.

    Preconditions:
      - value is a non-empty string

    Postconditions:
      - datetime.fromisoformat(value) does not raise ValueError
      - returned value is identical to input value (no transformation)

    Errors:
      - invalid_iso_format (ValueError): value cannot be parsed by datetime.fromisoformat()
          detail: Timestamp must be valid ISO 8601 format
      - empty_string (ValueError): value is an empty string
          detail: Timestamp must not be empty

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['Severity', 'Confidence', 'ReviewStage', 'ReviewDecision', 'ClassificationLabel', 'ChroniclerEventType', 'LearnerPhase', 'StigmergyVerb', 'CliExitCode', '_ExemplarBase', 'DiffHunk', 'ReviewRequest', 'Finding', 'Assessment', 'TrustScore', 'TesseraSeal', 'ReviewReport', 'ReviewerCredential', 'PolicyToken', 'ChroniclerEvent', 'StigmergySignal', 'LearningRecord', 'KindexEntry', 'PipelineResult', 'OutputFormat', 'severity_rank', 'confidence_rank', 'learner_phase_rank', 'canonical_bytes', 'canonical_hash', 'validate_iso_timestamp']
