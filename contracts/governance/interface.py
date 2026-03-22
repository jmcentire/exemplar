# === Governance Primitives (governance) v1 ===
# Inline implementations of governance stack patterns used across modules. Includes: TesseraSealer (SHA-256 hash-chain seal creation and verification over canonical JSON), ChronicleEmitter (emit structured events to JSON-lines log file, queryable), AgentSafeEnforcer (filter hunks by PolicyToken scope, log violations), SignetManager (create/verify reviewer credentials), ArbiterScorer (weighted trust score calculation and conflict resolution), LedgerClassifier (classify diff content against field rules for secrets/PII/internal APIs), StigmergyTracker (record and query recurring pattern signals to JSON storage), KindexStore (persistent JSON-file key-value store for review history and codebase context). Each is a focused class with a clean Protocol-based interface, fire-and-forget for optional integrations. Sync methods for pure computation, async for file I/O. Canonical JSON via json.dumps(data, sort_keys=True, separators=(',',':')) for deterministic hashing. Atomic file writes (write-to-temp + os.replace) for JSON stores. PACT keys as class-level constants included in ChroniclerEvent payloads.

# Module invariants:
#   - All TesseraSeal instances produced by a single TesseraSealer form a valid hash chain: each seal's previous_hash equals the prior seal's chain_hash, and sequence_numbers are monotonically increasing from 0.
#   - Canonical JSON serialization is always json.dumps(data, sort_keys=True, separators=(',',':')) — no other serialization format is used for hashing.
#   - All governance types are Pydantic v2 frozen=True models — no in-place mutation. Functions return new instances.
#   - Fire-and-forget methods (emit, record_signal, kindex_put) never raise exceptions to callers. They return bool and log failures via stdlib logging.
#   - Verification methods (verify_seal, verify_credential) raise domain-specific exceptions (SealVerificationError, CredentialError) on failure — they do NOT return False silently.
#   - All async methods perform file I/O only. No network calls, no GPU, no API keys required.
#   - Atomic file writes use write-to-temp + os.replace pattern to prevent partial writes and corruption.
#   - PACT keys are class-level str constants on each concrete implementation and are included in all ChroniclerEvent payloads emitted by that class.
#   - PolicyToken expiration is checked against UTC now at call time. Clock skew tolerance is not provided — callers must ensure clocks are synchronized.
#   - LedgerClassifier pre-compiles all regex patterns in __init__. Invalid patterns cause GovernanceError at construction time, not at classify() call time.
#   - KindexStore TTL expiration is checked at read time (get, query_by_tags). Expired entries remain in storage until overwritten or compacted externally.
#   - All UUID4 identifiers are generated as 32-character lowercase hex strings (no hyphens).
#   - SignetManager secret key is injected at construction time and never logged or serialized.

class GovernanceError:
    """Base exception for all governance primitive errors. Contains a human-readable message and optional context dict."""
    message: str                             # required, Human-readable error description.
    context: dict = {}                       # optional, Optional structured context for debugging.

class SealVerificationError:
    """Raised when a TesseraSeal fails verification against provided content. Subtype of GovernanceError."""
    message: str                             # required, Describes the verification failure.
    seal_id: str                             # required, The seal_id that failed verification.
    expected_hash: str = None                # optional, Expected content hash if available.
    actual_hash: str = None                  # optional, Actual computed content hash.

class PolicyViolationError:
    """Raised when a PolicyToken scope check fails or a hunk violates policy. Subtype of GovernanceError."""
    message: str                             # required, Describes the policy violation.
    token_id: str                            # required, The PolicyToken id that was violated.
    violated_scopes: list[str] = []          # optional, List of scope strings that were violated.

class CredentialError:
    """Raised when a ReviewerCredential fails verification. Subtype of GovernanceError."""
    message: str                             # required, Describes the credential failure.
    credential_id: str                       # required, The credential_id that failed.
    reason: CredentialErrorReason            # required, Categorized reason for failure.

class CredentialErrorReason(Enum):
    """Categorized reasons for credential verification failure."""
    EXPIRED = "EXPIRED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNKNOWN_REVIEWER = "UNKNOWN_REVIEWER"
    STAGE_MISMATCH = "STAGE_MISMATCH"
    MALFORMED = "MALFORMED"

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

class Confidence(Enum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"

class TesseraSeal:
    """A hash-chain tamper-proof seal over serialized content, verifiable independently."""
    content_hash: str                        # required, SHA-256 hash of the canonical JSON content that was sealed.
    previous_hash: Optional[str] = null      # optional, Hash of the previous seal in the chain (null for first seal).
    chain_hash: str                          # required, SHA-256 hash of (content_hash + previous_hash), forming the chain link.
    sealed_at: str                           # required, ISO-8601 timestamp of when the seal was created.
    sealer_id: str                           # required, Identifier of the entity that created this seal.

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

class ReviewerCredential:
    """Signet identity credential for a reviewer agent, used for authentication and attribution."""
    reviewer_id: str                         # required, Unique identifier for this reviewer agent.
    display_name: str                        # required, Human-readable name of the reviewer.
    stage: ReviewStage                       # required, Primary stage this reviewer operates in.
    public_key_hex: str                      # required, Hex-encoded public key for signature verification.
    created_at: str                          # required, ISO-8601 timestamp of credential creation.
    is_active: bool                          # required, Whether this credential is currently active.

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

class FindingSeverity(Enum):
    """Severity levels for review findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class TrustScore:
    """Arbiter trust weight for a reviewer agent, used in weighted assessment merging."""
    reviewer_id: str                         # required, Identifier of the reviewer this score applies to.
    stage: ReviewStage                       # required, Stage the reviewer operates in.
    weight: float                            # required, range(0.0 <= value <= 1.0), Trust weight in range [0.0, 1.0].
    accepted_count: int                      # required, Number of findings from this reviewer that humans accepted.
    dismissed_count: int                     # required, Number of findings from this reviewer that humans dismissed.
    updated_at: str                          # required, ISO-8601 timestamp of last trust score update.

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

class LearningOutcome(Enum):
    """Categories of learning outcomes for trust score updates."""
    CORRECT_ACCEPT = "CORRECT_ACCEPT"
    CORRECT_REJECT = "CORRECT_REJECT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    PARTIAL_MATCH = "PARTIAL_MATCH"

class LedgerFieldRule:
    """A single Ledger classification rule: a regex pattern mapped to a classification label."""
    pattern: str                             # required, Regex pattern to match against diff hunk content.
    label: ClassificationLabel               # required, Classification label to apply when pattern matches.
    description: str = None                  # optional, Human-readable description of what this rule detects.

class LedgerConfig:
    """Configuration for Ledger field classification: rules for detecting secrets, PII, and internal APIs."""
    rules: list[LedgerFieldRule]             # required, Ordered list of classification rules. First match wins per label category.
    default_label: ClassificationLabel       # required, Default label when no rule matches.

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

class KindexEntry:
    """A Kindex knowledge store entry representing a past review or codebase context artifact."""
    key: str                                 # required, Unique key for retrieval (e.g., review request ID or context topic).
    kind: str                                # required, Entry kind: 'review', 'context', 'pattern'.
    summary: str                             # required, Human-readable summary for search and display.
    data: dict[str, str]                     # required, Structured data payload of the entry.
    tags: list[str]                          # required, Tags for query filtering.
    created_at: str                          # required, ISO-8601 timestamp of entry creation.
    updated_at: str                          # required, ISO-8601 timestamp of last update.

class CircuitConfig:
    """Configuration for Baton circuit routing: stage ordering, parallelism, and timeouts."""
    stages: list[ReviewStage]                # required, Ordered list of review stages to execute.
    parallel_stages: list[list[ReviewStage]] # required, Groups of stages that can run in parallel. Each inner list runs concurrently.
    stage_timeout_ms: int                    # required, range(value > 0), Default timeout per stage in milliseconds.
    block_threshold: int                     # required, Minimum number of critical/high findings to trigger a block decision.
    warn_threshold: int                      # required, Minimum number of medium findings to trigger a warn decision.

class FilterResult:
    """Result of hunk filtering by AgentSafeEnforcer, including allowed hunks and violation details."""
    allowed_hunks: list[DiffHunk]            # required, Hunks that passed policy filtering.
    denied_hunk_ids: list[str]               # required, Hunk IDs that were filtered out due to policy violations.
    violations: list[str]                    # required, Human-readable descriptions of each policy violation.

class Severity(Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

def seal(
    content: str,              # length(1 <= len <= 10485760)
    sealer_id: str,            # length(1 <= len <= 256)
) -> TesseraSeal:
    """
    Create a SHA-256 hash-chain seal over canonical JSON content. The seal chains to the previous seal in the sealer's chain (or genesis if first). Content is serialized via json.dumps(data, sort_keys=True, separators=(',',':')) for deterministic hashing. The chain_hash is SHA-256(content_hash + previous_hash + sealer_id + timestamp_iso). The sealer maintains internal chain state (previous_hash, sequence_number) which advances with each seal.

    Preconditions:
      - content must be valid JSON
      - sealer_id must be non-empty

    Postconditions:
      - Returned seal.content_hash == SHA-256 of canonical JSON re-serialization of content
      - Returned seal.chain_hash == SHA-256(content_hash + previous_hash + sealer_id + timestamp_iso)
      - Returned seal.sequence_number == previous sequence_number + 1 (or 0 for genesis)
      - Returned seal.previous_hash == chain_hash of the last seal produced by this sealer (or 64 zeros for genesis)
      - Internal chain state is advanced: previous_hash and sequence_number are updated

    Errors:
      - invalid_json (GovernanceError): content is not valid JSON
          message: Content must be valid JSON for canonical serialization.
      - empty_sealer_id (GovernanceError): sealer_id is empty or whitespace-only
          message: sealer_id must not be empty.

    Side effects: none
    Idempotent: no
    """
    ...

def verify_seal(
    seal: TesseraSeal,
    content: str,              # length(1 <= len <= 10485760)
) -> bool:
    """
    Verify that a TesseraSeal is valid for the given content. Checks: (1) content_hash matches SHA-256 of canonical JSON re-serialization of content, (2) chain_hash matches SHA-256(content_hash + previous_hash + sealer_id + timestamp_iso). Raises SealVerificationError on any mismatch. Does NOT verify chain continuity (previous_hash linkage) — that requires the full chain.

    Preconditions:
      - content must be valid JSON

    Postconditions:
      - Returns True only if both content_hash and chain_hash verifications pass

    Errors:
      - content_hash_mismatch (SealVerificationError): SHA-256 of canonical content does not match seal.content_hash
          message: Content hash does not match seal.
          seal_id: seal.seal_id
      - chain_hash_mismatch (SealVerificationError): Computed chain_hash does not match seal.chain_hash
          message: Chain hash does not match seal.
          seal_id: seal.seal_id
      - invalid_content_json (GovernanceError): content is not valid JSON
          message: Content must be valid JSON for canonical verification.

    Side effects: none
    Idempotent: yes
    """
    ...

async def emit(
    event: ChroniclerEvent,
) -> bool:
    """
    Emit a structured ChroniclerEvent to the JSON-lines log file. Appends one JSON line per event. Fire-and-forget: catches all exceptions internally, logs via stdlib logging, returns False on failure. Uses atomic write (append mode with flush).

    Preconditions:
      - event.payload must be JSON-serializable

    Postconditions:
      - On True return: event is durably appended to the JSON-lines log file
      - On False return: failure is logged via stdlib logging, no event persisted

    Errors:
      - file_write_failure (GovernanceError): Unable to write to the chronicle log file (permissions, disk full, etc.)
          message: Failed to write chronicle event to log file.
      - serialization_failure (GovernanceError): Event payload contains non-JSON-serializable data
          message: Event payload is not JSON-serializable.

    Side effects: Appends JSON line to chronicle log file
    Idempotent: no
    """
    ...

async def query_events(
    review_request_id: str,    # length(1 <= len <= 256)
    event_type: ChroniclerEventType = None,
) -> list[ChroniclerEvent]:
    """
    Query chronicle events from the JSON-lines log file, filtered by review_request_id and optionally by event_type. Reads the entire log file and filters in memory. Returns empty list if the log file does not exist.

    Postconditions:
      - Returned events all have review_request_id matching the input
      - If event_type is provided, returned events all have matching event_type
      - Events are returned in chronological order (file order)

    Errors:
      - file_read_failure (GovernanceError): Unable to read the chronicle log file (permissions, corrupt)
          message: Failed to read chronicle log file.
      - corrupt_line (GovernanceError): A line in the log file is not valid JSON — skipped with warning
          message: Corrupt line encountered in chronicle log.

    Side effects: none
    Idempotent: yes
    """
    ...

def filter_hunks(
    hunks: list[DiffHunk],
    token: PolicyToken,
) -> FilterResult:
    """
    Filter a list of DiffHunks by PolicyToken scope. Checks each hunk against: (1) allowed_file_patterns (glob matching), (2) max_classification (hunk classification_labels must not exceed token's max), (3) allowed_stages (caller must verify stage separately). Returns a FilterResult with allowed hunks, denied hunk IDs, and violation descriptions. Does NOT raise on violation — violations are informational. Logs all violations via ChronicleEmitter if available.

    Preconditions:
      - token must not be expired (expires_iso in the future)

    Postconditions:
      - len(allowed_hunks) + len(denied_hunk_ids) == len(hunks)
      - All allowed_hunks have file_path matching at least one allowed_file_pattern (or patterns list is empty)
      - No allowed_hunk has a classification_label exceeding token.max_classification
      - Each denied hunk_id appears in denied_hunk_ids exactly once
      - Each violation has a corresponding human-readable description in violations list

    Errors:
      - expired_token (PolicyViolationError): token.expires_iso is in the past
          message: PolicyToken has expired.
          token_id: token.token_id
      - invalid_glob_pattern (GovernanceError): A pattern in token.allowed_file_patterns is not a valid glob
          message: Invalid glob pattern in PolicyToken.

    Side effects: none
    Idempotent: yes
    """
    ...

def check_token(
    token: PolicyToken,
) -> bool:
    """
    Check whether a PolicyToken is valid: not expired, has at least one allowed stage, and has a non-empty reviewer_id. Returns True if valid. Raises PolicyViolationError if the token is expired.

    Postconditions:
      - Returns True only if token is not expired, has >=1 allowed_stages, and reviewer_id is non-empty

    Errors:
      - expired_token (PolicyViolationError): token.expires_iso is in the past
          message: PolicyToken has expired.
          token_id: token.token_id

    Side effects: none
    Idempotent: yes
    """
    ...

def create_credential(
    reviewer_id: str,          # length(1 <= len <= 256)
    display_name: str,         # length(1 <= len <= 512)
    stage: ReviewStage,
) -> ReviewerCredential:
    """
    Create a ReviewerCredential for a reviewer scoped to a specific review stage. Generates a UUID4 credential_id, computes an HMAC-SHA256 signature over (credential_id + reviewer_id + stage) using the SignetManager's secret key, and sets expiration to configured TTL from now.

    Preconditions:
      - reviewer_id must be non-empty
      - display_name must be non-empty

    Postconditions:
      - Returned credential.reviewer_id == reviewer_id
      - Returned credential.stage == stage
      - Returned credential.signature_hash == HMAC-SHA256(secret, credential_id + reviewer_id + stage)
      - Returned credential.expires_iso is in the future

    Errors:
      - empty_reviewer_id (GovernanceError): reviewer_id is empty or whitespace-only
          message: reviewer_id must not be empty.
      - empty_display_name (GovernanceError): display_name is empty or whitespace-only
          message: display_name must not be empty.

    Side effects: none
    Idempotent: no
    """
    ...

def verify_credential(
    credential: ReviewerCredential,
) -> bool:
    """
    Verify a ReviewerCredential's HMAC signature and expiration. Raises CredentialError with a specific reason on failure. Checks: (1) credential is not expired, (2) signature_hash matches HMAC-SHA256(secret, credential_id + reviewer_id + stage), (3) credential_id is well-formed.

    Postconditions:
      - Returns True only if signature is valid and credential is not expired

    Errors:
      - expired (CredentialError): credential.expires_iso is in the past
          message: Credential has expired.
          credential_id: credential.credential_id
          reason: EXPIRED
      - invalid_signature (CredentialError): Computed HMAC does not match credential.signature_hash
          message: Credential signature is invalid.
          credential_id: credential.credential_id
          reason: INVALID_SIGNATURE
      - malformed (CredentialError): credential_id does not match expected UUID4 hex format
          message: Credential is malformed.
          credential_id: credential.credential_id
          reason: MALFORMED

    Side effects: none
    Idempotent: yes
    """
    ...

def score(
    assessments: list[Assessment],
    trust_scores: list[TrustScore],
    circuit_config: CircuitConfig,
) -> list:
    """
    Compute a weighted trust score and final ReviewDecision from multiple reviewer assessments. Each assessment is weighted by: (1) its stage's weight from circuit_config.stage_weights, (2) the reviewer's trust_score for that stage, (3) the assessment's own confidence. Assessments below circuit_config.min_confidence are excluded. If fewer than circuit_config.quorum assessments qualify, returns ABSTAIN. Conflict detection: if the ratio of disagreeing assessments exceeds circuit_config.conflict_threshold, escalates to BLOCK. Returns (decision, aggregate_confidence, reasoning_trace).

    Preconditions:
      - assessments must not be empty
      - trust_scores must contain an entry for every unique (reviewer_id, stage) pair in assessments

    Postconditions:
      - Return list has exactly 3 elements: [ReviewDecision, Confidence, list[str]]
      - If fewer than quorum assessments qualify, decision is ABSTAIN
      - If conflict ratio exceeds conflict_threshold, decision is BLOCK
      - reasoning_trace contains one entry per assessment explaining its weight contribution
      - Confidence.value is the weighted average of qualifying assessment confidences

    Errors:
      - missing_trust_score (GovernanceError): An assessment references a reviewer_id+stage pair with no corresponding TrustScore
          message: Missing trust score for reviewer+stage pair.
      - empty_assessments (GovernanceError): assessments list is empty
          message: Cannot score an empty assessments list.

    Side effects: none
    Idempotent: yes
    """
    ...

def update_trust(
    trust_score: TrustScore,
    record: LearningRecord,
) -> TrustScore:
    """
    Update a TrustScore based on a LearningRecord. Applies the learning record's delta to the trust score, clamped to [0.0, 1.0], increments review_count, and updates last_updated_iso. Returns a new TrustScore (frozen model, not mutated in-place).

    Preconditions:
      - record.reviewer_id must match trust_score.reviewer_id

    Postconditions:
      - Returned trust_score.score == clamp(old_score + record.delta, 0.0, 1.0)
      - Returned trust_score.review_count == old_review_count + 1
      - Returned trust_score.last_updated_iso is current UTC time
      - Returned trust_score.reviewer_id == input trust_score.reviewer_id
      - Returned trust_score.stage == input trust_score.stage

    Errors:
      - reviewer_mismatch (GovernanceError): record.reviewer_id does not match trust_score.reviewer_id
          message: LearningRecord reviewer_id does not match TrustScore reviewer_id.

    Side effects: none
    Idempotent: no
    """
    ...

def classify(
    hunk: DiffHunk,
    rules: list[LedgerFieldRule],
) -> list[ClassificationLabel]:
    """
    Classify a single DiffHunk by applying a list of LedgerFieldRules against its added_lines and removed_lines. Each line is tested against each rule's compiled regex pattern. Returns the union of all matching ClassificationLabels, deduplicated. If no rules match and fail_open is not applicable (single-hunk method), returns [UNKNOWN].

    Preconditions:
      - rules must not be empty
      - All rule patterns must be valid regex

    Postconditions:
      - Returned labels are deduplicated
      - If no rule matches, returns [UNKNOWN]
      - Lines exceeding internal max length are truncated before matching

    Errors:
      - invalid_regex (GovernanceError): A rule's pattern is not a valid regex
          message: Invalid regex pattern in LedgerFieldRule.
      - empty_rules (GovernanceError): rules list is empty
          message: Cannot classify with empty rules list.

    Side effects: none
    Idempotent: yes
    """
    ...

def classify_all(
    hunks: list[DiffHunk],
    config: LedgerConfig,
) -> list[DiffHunk]:
    """
    Classify all DiffHunks using a LedgerConfig. Applies LedgerConfig.rules to each hunk, sets classification_labels on each hunk, and returns the updated list. Uses LedgerConfig.fail_open to determine default label for unmatched hunks (SAFE if true, UNKNOWN if false). Returns new DiffHunk instances (frozen models, not mutated in-place).

    Preconditions:
      - config.rules must not be empty
      - All rule patterns must be valid regex

    Postconditions:
      - Returned list has same length as input hunks
      - Each returned hunk has classification_labels populated
      - Unmatched hunks get [SAFE] if config.fail_open else [UNKNOWN]
      - Returned hunks are new instances with all other fields preserved

    Errors:
      - invalid_regex (GovernanceError): A rule's pattern in config.rules is not a valid regex
          message: Invalid regex pattern in LedgerConfig rules.
      - empty_rules (GovernanceError): config.rules is empty
          message: Cannot classify with empty rules in LedgerConfig.

    Side effects: none
    Idempotent: yes
    """
    ...

async def record_signal(
    signal: StigmergySignal,
) -> bool:
    """
    Record a StigmergySignal to the JSON storage file. Fire-and-forget: catches all exceptions internally, logs via stdlib logging, returns False on failure. Uses atomic file write (read-modify-write with temp file + os.replace).

    Preconditions:
      - signal.metadata must be JSON-serializable

    Postconditions:
      - On True return: signal is durably persisted to the JSON storage file
      - On False return: failure is logged via stdlib logging

    Errors:
      - file_write_failure (GovernanceError): Unable to write to the stigmergy JSON file
          message: Failed to write stigmergy signal to storage.
      - serialization_failure (GovernanceError): Signal metadata is not JSON-serializable
          message: Signal metadata is not JSON-serializable.

    Side effects: Writes to stigmergy JSON storage file
    Idempotent: no
    """
    ...

async def query_signals(
    pattern_key: str,          # length(1 <= len <= 512)
) -> list[StigmergySignal]:
    """
    Query StigmergySignals from JSON storage by pattern_key. Returns all signals matching the given pattern_key in chronological order. Returns empty list if storage file does not exist.

    Postconditions:
      - All returned signals have pattern_key matching the input
      - Signals are in chronological order by timestamp_iso

    Errors:
      - file_read_failure (GovernanceError): Unable to read the stigmergy JSON file
          message: Failed to read stigmergy storage file.
      - corrupt_storage (GovernanceError): Storage file contains invalid JSON
          message: Stigmergy storage file is corrupt.

    Side effects: none
    Idempotent: yes
    """
    ...

async def kindex_get(
    key: str,                  # length(1 <= len <= 512)
) -> KindexEntry:
    """
    Retrieve a KindexEntry by key from the JSON-file key-value store. Returns None if the key does not exist or the store file does not exist. Entries with ttl_seconds > 0 that have expired (created_iso + ttl_seconds < now) are treated as non-existent.

    Postconditions:
      - If returned, entry.key == key
      - Expired entries are not returned (treated as None)

    Errors:
      - file_read_failure (GovernanceError): Unable to read the kindex JSON file
          message: Failed to read kindex storage file.
      - corrupt_storage (GovernanceError): Storage file contains invalid JSON
          message: Kindex storage file is corrupt.

    Side effects: none
    Idempotent: yes
    """
    ...

async def kindex_put(
    entry: KindexEntry,
) -> bool:
    """
    Store or update a KindexEntry in the JSON-file key-value store. If an entry with the same key exists, it is replaced. Fire-and-forget: catches all exceptions internally, logs via stdlib logging, returns False on failure. Uses atomic file write (read-modify-write with temp file + os.replace).

    Preconditions:
      - entry.value must be JSON-serializable

    Postconditions:
      - On True return: entry is durably persisted (upserted) in the JSON store
      - On False return: failure is logged via stdlib logging

    Errors:
      - file_write_failure (GovernanceError): Unable to write to the kindex JSON file
          message: Failed to write kindex entry to storage.
      - serialization_failure (GovernanceError): Entry value is not JSON-serializable
          message: Entry value is not JSON-serializable.

    Side effects: Writes to kindex JSON storage file
    Idempotent: yes
    """
    ...

async def kindex_query_by_tags(
    tags: list[str],
) -> list[KindexEntry]:
    """
    Query KindexEntries from the JSON store by tags. Returns all entries where the entry's tags set intersects with the query tags set. Expired entries (ttl_seconds > 0 and created_iso + ttl_seconds < now) are excluded. Returns empty list if storage file does not exist.

    Preconditions:
      - tags must not be empty

    Postconditions:
      - Each returned entry has at least one tag in common with the query tags
      - Expired entries are excluded

    Errors:
      - file_read_failure (GovernanceError): Unable to read the kindex JSON file
          message: Failed to read kindex storage file.
      - corrupt_storage (GovernanceError): Storage file contains invalid JSON
          message: Kindex storage file is corrupt.
      - empty_tags (GovernanceError): tags list is empty
          message: Cannot query with empty tags list.

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['GovernanceError', 'SealVerificationError', 'PolicyViolationError', 'CredentialError', 'CredentialErrorReason', 'ReviewStage', 'ChroniclerEventType', 'ReviewDecision', 'ClassificationLabel', 'Confidence', 'TesseraSeal', 'ChroniclerEvent', 'DiffHunk', 'PolicyToken', 'ReviewerCredential', 'Assessment', 'Finding', 'FindingSeverity', 'TrustScore', 'LearningRecord', 'LearningOutcome', 'LedgerFieldRule', 'LedgerConfig', 'StigmergySignal', 'KindexEntry', 'CircuitConfig', 'FilterResult', 'Severity', 'seal', 'verify_seal', 'emit', 'query_events', 'filter_hunks', 'check_token', 'create_credential', 'verify_credential', 'score', 'update_trust', 'classify', 'classify_all', 'record_signal', 'query_signals', 'kindex_get', 'kindex_put', 'kindex_query_by_tags']
