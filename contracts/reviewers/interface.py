# === Reviewer Implementations (reviewers) v1 ===
#  Dependencies: schemas, config
# ReviewerProtocol (runtime_checkable Protocol) and four independent implementations for multi-stage code review analysis. SecurityReviewer detects hardcoded secrets, SQL injection, path traversal, command injection, and insecure deserialization via compiled regex patterns. CorrectnessReviewer performs AST-based analysis for None dereference patterns, off-by-one errors in range/slice, unchecked return values, bare excepts, and mutable default arguments. StyleReviewer checks convention violations including naming, line length, import ordering, and docstring presence via text/regex analysis. ArchitectureReviewer detects coupling via import analysis, layer violation checks, and circular dependency hints. Each reviewer is scoped by Agent-Safe PolicyToken — receives only permitted hunks. Each produces typed findings with Severity and Confidence. Heuristic-quality, not production static analysis. Reviewers are pure analysis units — Chronicler event emission is handled by the caller (circuit.py).

# Module invariants:
#   - All reviewers implement the same ReviewerProtocol — no class inheritance, only structural conformance via @runtime_checkable Protocol
#   - Every reviewer filters hunks through filter_hunks_by_policy() before analysis — no hunk reaches analysis logic without policy check
#   - Each hunk is processed inside its own try/except — a failure analyzing one hunk never prevents analysis of remaining hunks
#   - All rule IDs follow namespaced format: SEC-xxx for security, COR-xxx for correctness, STY-xxx for style, ARC-xxx for architecture
#   - Rule catalogs are module-level frozen constants — they are never mutated at runtime
#   - Assessment.decision is derived deterministically from aggregate severity of findings — not manually set
#   - Assessment.confidence is the conservative minimum across all findings — not averaged
#   - Assessment objects returned are frozen (immutable Pydantic models with frozen=True)
#   - Reviewers never emit Chronicler events directly — they are pure analysis units
#   - PACT keys are embedded in all public method docstrings for Sentinel attribution
#   - review() is idempotent: given the same hunks, policy, and review_request_id, it produces the same Assessment

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

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

class ReviewDecision(Enum):
    """Final decision on a pull request review: block merging, warn, or pass."""
    block = "block"
    warn = "warn"
    pass = "pass"

RuleId = primitive  # Namespaced rule identifier string. Format: PREFIX-NNN where PREFIX is SEC|COR|STY|ARC and NNN is a zero-padded 3-digit number.

FilePath = primitive  # Relative file path within a repository. Unix-style forward slashes, no leading slash, no '..' traversal.

LineNumber = primitive  # 1-based line number within a source file.

ReviewRequestId = primitive  # UUID string identifying a unique review request. Used for deterministic assessment ID generation via uuid5.

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

class RulePattern:
    """Frozen dataclass representing a single compiled detection rule used by pattern-based reviewers (Security, Style)."""
    rule_id: RuleId                          # required, Namespaced rule identifier
    pattern: str                             # required, length(1..2000), Regex pattern string (compiled at module load time)
    severity: Severity                       # required, Default severity when this rule matches
    confidence: Confidence                   # required, Default confidence when this rule matches
    message_template: str                    # required, length(1..500), Human-readable message template. May contain {match} placeholder for the matched text.
    suggestion: str = None                   # optional, Remediation suggestion for this rule

class AstRule:
    """Frozen dataclass representing a single AST-based detection rule used by CorrectnessReviewer."""
    rule_id: RuleId                          # required, Namespaced rule identifier (COR-xxx)
    node_types: list                         # required, AST node type names this rule inspects (e.g., 'If', 'Compare', 'FunctionDef')
    severity: Severity                       # required, Default severity when this rule matches
    confidence: Confidence                   # required, Default confidence when this rule matches
    message_template: str                    # required, length(1..500), Human-readable message template

class ImportInfo:
    """Parsed import information extracted from a single import statement for architecture analysis."""
    module: str                              # required, The module being imported
    names: list                              # required, Specific names imported (empty for bare 'import X')
    file_path: FilePath                      # required, File containing this import statement
    line_number: LineNumber                  # required, Line number of the import statement

class HunkAnalysisError:
    """Structured record of an error encountered while analyzing a single hunk."""
    file_path: FilePath                      # required, File path of the hunk that caused the error
    start_line: LineNumber                   # required, Start line of the hunk
    error_type: str                          # required, Exception class name
    error_message: str                       # required, length(1..500), Human-readable error description

class FilteredHunksResult:
    """Result of filtering hunks by policy. Contains the permitted hunks and count of denied hunks."""
    permitted: list                          # required, Hunks that passed policy filtering
    denied_count: int                        # required, range(0..100000), Number of hunks denied by policy

class DecisionDerivation:
    """Intermediate result of deriving a ReviewDecision from aggregate finding severities."""
    decision: ReviewDecision                 # required, The derived decision
    min_confidence: Confidence               # required, Conservative minimum confidence across all findings. HIGH if no findings.
    has_critical: bool                       # required, Whether any CRITICAL severity finding exists
    has_high: bool                           # required, Whether any HIGH severity finding exists

class ClassificationLabel(Enum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"

def filter_hunks_by_policy(
    hunks: list,
    policy: PolicyToken,
    stage: ReviewStage,
) -> FilteredHunksResult:
    """
    Filters a list of DiffHunks according to PolicyToken scoping rules. Uses fnmatch glob matching with deny-wins semantics: if a hunk's file_path matches any denied_paths pattern, it is excluded regardless of allowed_paths. If allowed_paths is non-empty, only hunks matching at least one allowed pattern (and no denied pattern) pass through. Also checks that the reviewer's stage is in allowed_stages (or allowed_stages is empty). PACT-KEY: FILTER-HUNKS-POLICY-V1

    Preconditions:
      - hunks is a list (may be empty)
      - policy is a valid PolicyToken with well-formed glob patterns
      - stage is a valid ReviewStage enum member

    Postconditions:
      - result.permitted contains only hunks whose file_path matches allowed_paths (if non-empty) and does not match any denied_paths
      - result.denied_count == len(hunks) - len(result.permitted)
      - result.permitted preserves original ordering of hunks
      - If policy.allowed_stages is non-empty and stage not in policy.allowed_stages, result.permitted is empty and result.denied_count == len(hunks)

    Errors:
      - invalid_glob_pattern (ValueError): A glob pattern in policy.allowed_paths or policy.denied_paths causes fnmatch to raise
          detail: Description of the malformed pattern

    Side effects: none
    Idempotent: yes
    """
    ...

def derive_decision(
    findings: list,
) -> DecisionDerivation:
    """
    Derives a ReviewDecision and conservative minimum Confidence from a list of Findings using deterministic severity aggregation rules. BLOCK if any CRITICAL or HIGH finding, ADVISORY if any MEDIUM finding, PASS otherwise. Confidence is the minimum across all findings, or HIGH if no findings. PACT-KEY: DERIVE-DECISION-V1

    Preconditions:
      - findings is a list of valid Finding objects (may be empty)

    Postconditions:
      - If findings is empty, decision is PASS and min_confidence is HIGH
      - If any finding has severity CRITICAL or HIGH, decision is BLOCK
      - If no CRITICAL/HIGH but any MEDIUM, decision is ADVISORY
      - If all findings are LOW or INFO, decision is PASS
      - min_confidence is the minimum confidence across all findings using ordering LOW < MEDIUM < HIGH

    Side effects: none
    Idempotent: yes
    """
    ...

def build_assessment(
    reviewer_id: str,          # regex(^(security|correctness|style|architecture)$)
    stage: ReviewStage,
    findings: list,
    hunks_analyzed: int,
    hunks_skipped: int,
    errors: list,
    review_request_id: ReviewRequestId,
    start_ns: int,
) -> Assessment:
    """
    Constructs a frozen Assessment from the reviewer's analysis results. Generates a deterministic assessment_id via uuid5(NAMESPACE_DNS, f'{review_request_id}:{reviewer_id}'). Computes duration_ms from start_ns (monotonic_ns captured at review entry). Derives decision and confidence via derive_decision(). PACT-KEY: BUILD-ASSESSMENT-V1

    Preconditions:
      - start_ns was captured via time.monotonic_ns() at the beginning of the review call
      - review_request_id is a valid UUID string
      - hunks_analyzed >= 0
      - hunks_skipped >= 0

    Postconditions:
      - assessment_id is deterministic: uuid5(NAMESPACE_DNS, '{review_request_id}:{reviewer_id}')
      - duration_ms >= 0.0
      - decision and confidence are derived from findings via derive_decision()
      - Returned Assessment is a frozen Pydantic model

    Errors:
      - invalid_reviewer_id (ValueError): reviewer_id is not one of the four canonical reviewer names
          detail: Unrecognized reviewer_id

    Side effects: none
    Idempotent: yes
    """
    ...

async def SecurityReviewer.review(
    hunks: list,
    policy: PolicyToken,
    review_request_id: ReviewRequestId,
) -> Assessment:
    """
    Analyzes diff hunks for security vulnerabilities using compiled regex pattern matching against OWASP top patterns. Detects hardcoded secrets (API keys, passwords, tokens), SQL injection vectors, path traversal attempts, command injection, and insecure deserialization. Filters hunks by policy first, then iterates each permitted hunk with per-hunk try/except isolation. Rule IDs: SEC-001 (hardcoded secrets), SEC-002 (SQL injection), SEC-003 (path traversal), SEC-004 (command injection), SEC-005 (insecure deserialization), SEC-006 (weak cryptography), SEC-007 (debug/logging exposure). PACT-KEY: SEC-REVIEW-V1

    Preconditions:
      - hunks is a list of valid DiffHunk objects
      - policy is a valid PolicyToken
      - review_request_id is a valid UUID string

    Postconditions:
      - Assessment.reviewer_id == 'security'
      - Assessment.stage == ReviewStage.SECURITY
      - All findings have rule_ids matching SEC-xxx pattern
      - Assessment.hunks_analyzed + Assessment.hunks_skipped == len(hunks) - len(hunks that errored) + Assessment.hunks_skipped ... specifically: hunks_analyzed counts successfully processed hunks, hunks_skipped counts policy-filtered hunks
      - No exceptions propagate — per-hunk errors are captured in Assessment.errors

    Errors:
      - all_hunks_denied (None): PolicyToken denies all hunks or stage not permitted — not an error, returns Assessment with empty findings and PASS decision
          detail: Returns valid Assessment with zero findings

    Side effects: none
    Idempotent: yes
    """
    ...

async def CorrectnessReviewer.review(
    hunks: list,
    policy: PolicyToken,
    review_request_id: ReviewRequestId,
) -> Assessment:
    """
    Analyzes diff hunks for correctness issues using AST-based analysis with ast.parse and ast.NodeVisitor. Detects None dereference patterns (attribute access on potentially-None values), off-by-one errors in range/slice expressions, unchecked return values, bare except clauses, mutable default arguments, and logic errors. Falls back gracefully when ast.parse raises SyntaxError (non-Python files or invalid syntax). Rule IDs: COR-001 (None dereference), COR-002 (off-by-one), COR-003 (unchecked return), COR-004 (bare except), COR-005 (mutable default), COR-006 (unreachable code). PACT-KEY: COR-REVIEW-V1

    Preconditions:
      - hunks is a list of valid DiffHunk objects
      - policy is a valid PolicyToken
      - review_request_id is a valid UUID string

    Postconditions:
      - Assessment.reviewer_id == 'correctness'
      - Assessment.stage == ReviewStage.CORRECTNESS
      - All findings have rule_ids matching COR-xxx pattern
      - Hunks with non-Python file paths or unparseable content are gracefully skipped (SyntaxError fallback) and counted in hunks_analyzed with no findings
      - No exceptions propagate — per-hunk errors are captured in Assessment.errors

    Errors:
      - syntax_error_fallback (None): ast.parse raises SyntaxError for a hunk's content — this is expected for non-Python or partial code
          detail: Gracefully handled: hunk is skipped for AST analysis, may still be checked by text-based fallback patterns
      - all_hunks_denied (None): PolicyToken denies all hunks or stage not permitted
          detail: Returns valid Assessment with zero findings

    Side effects: none
    Idempotent: yes
    """
    ...

async def StyleReviewer.review(
    hunks: list,
    policy: PolicyToken,
    review_request_id: ReviewRequestId,
) -> Assessment:
    """
    Analyzes diff hunks for coding convention violations using text and regex analysis. Checks line length limits, naming convention adherence (PascalCase for classes, snake_case for functions/variables, UPPER_SNAKE_CASE for constants), import ordering (stdlib before third-party before local, alphabetical within groups), and docstring presence on public functions/classes. Rule IDs: STY-001 (line length), STY-002 (naming convention), STY-003 (import ordering), STY-004 (missing docstring), STY-005 (trailing whitespace), STY-006 (mixed indentation). PACT-KEY: STY-REVIEW-V1

    Preconditions:
      - hunks is a list of valid DiffHunk objects
      - policy is a valid PolicyToken
      - review_request_id is a valid UUID string

    Postconditions:
      - Assessment.reviewer_id == 'style'
      - Assessment.stage == ReviewStage.STYLE
      - All findings have rule_ids matching STY-xxx pattern
      - Style findings never have severity above MEDIUM — style issues are advisory only
      - No exceptions propagate — per-hunk errors are captured in Assessment.errors

    Errors:
      - all_hunks_denied (None): PolicyToken denies all hunks or stage not permitted
          detail: Returns valid Assessment with zero findings

    Side effects: none
    Idempotent: yes
    """
    ...

async def ArchitectureReviewer.review(
    hunks: list,
    policy: PolicyToken,
    review_request_id: ReviewRequestId,
) -> Assessment:
    """
    Analyzes diff hunks for architectural issues using import-line regex extraction and cross-hunk coupling analysis. Detects excessive coupling (too many imports from a single module), layer violations (e.g., a low-level module importing from a high-level one per configured layer hierarchy), circular dependency hints (A imports B and B imports A detected within the diff), and god-module indicators (files with excessive import counts). Rule IDs: ARC-001 (excessive coupling), ARC-002 (layer violation), ARC-003 (circular dependency hint), ARC-004 (god module), ARC-005 (forbidden import). PACT-KEY: ARC-REVIEW-V1

    Preconditions:
      - hunks is a list of valid DiffHunk objects
      - policy is a valid PolicyToken
      - review_request_id is a valid UUID string

    Postconditions:
      - Assessment.reviewer_id == 'architecture'
      - Assessment.stage == ReviewStage.ARCHITECTURE
      - All findings have rule_ids matching ARC-xxx pattern
      - Cross-hunk analysis considers all permitted hunks collectively (not hunk-by-hunk isolation) for import graph construction
      - No exceptions propagate — per-hunk errors are captured in Assessment.errors

    Errors:
      - all_hunks_denied (None): PolicyToken denies all hunks or stage not permitted
          detail: Returns valid Assessment with zero findings

    Side effects: none
    Idempotent: yes
    """
    ...

def get_all_reviewers() -> list:
    """
    Factory function that instantiates and returns all four canonical reviewer implementations. Each reviewer is constructed with its module-level frozen rule catalog. Returns a list ordered by recommended execution sequence: Security, Correctness, Style, Architecture. PACT-KEY: GET-ALL-REVIEWERS-V1

    Postconditions:
      - Returned list contains exactly 4 elements
      - Each element satisfies the ReviewerProtocol (runtime_checkable)
      - Order is: SecurityReviewer, CorrectnessReviewer, StyleReviewer, ArchitectureReviewer
      - Each reviewer's reviewer_id is unique

    Side effects: none
    Idempotent: yes
    """
    ...

def get_reviewer_by_stage(
    stage: ReviewStage,
) -> any:
    """
    Returns the canonical reviewer implementation for a given ReviewStage. PACT-KEY: GET-REVIEWER-BY-STAGE-V1

    Preconditions:
      - stage is a valid ReviewStage enum member

    Postconditions:
      - Returned object satisfies ReviewerProtocol
      - Returned reviewer's stage property matches the input stage

    Errors:
      - unknown_stage (ValueError): stage value is not a recognized ReviewStage member (should not occur with proper enum typing but guarded defensively)
          detail: Unrecognized ReviewStage value

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ReviewStage', 'Severity', 'Confidence', 'ReviewDecision', 'DiffHunk', 'PolicyToken', 'Finding', 'Assessment', 'RulePattern', 'AstRule', 'ImportInfo', 'HunkAnalysisError', 'FilteredHunksResult', 'DecisionDerivation', 'ClassificationLabel', 'filter_hunks_by_policy', 'derive_decision', 'build_assessment', 'get_all_reviewers', 'get_reviewer_by_stage']
