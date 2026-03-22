"""
ReviewerProtocol and four independent reviewer implementations for multi-stage code review.

SecurityReviewer, CorrectnessReviewer, StyleReviewer, ArchitectureReviewer — each scoped by
Agent-Safe PolicyToken, producing typed findings with Severity and Confidence.
Heuristic-quality, not production static analysis.
Reviewers are pure analysis units — Chronicler event emission is handled by the caller.
"""

from __future__ import annotations

import ast
import fnmatch
import re
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator


# ── Enums ──────────────────────────────────────────────


class ReviewStage(str, Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


class Severity(str, Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(str, Enum):
    """Confidence level of a reviewer finding or merged assessment."""
    high = "high"
    medium = "medium"
    low = "low"


class ReviewDecision(str, Enum):
    """Final decision on a pull request review: block merging, warn, or pass."""
    block = "block"
    warn = "warn"
    pass_ = "pass"


class ClassificationLabel(str, Enum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"


# ── Primitive validated types ──────────────────────────

_RULE_ID_RE = re.compile(r"^(SEC|COR|STY|ARC)-\d{3}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)


class RuleId(BaseModel):
    """Namespaced rule identifier string."""
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if not _RULE_ID_RE.match(v):
            raise ValueError(f"Invalid RuleId format: {v!r}. Expected PREFIX-NNN.")
        return v


class FilePath(BaseModel):
    """Relative file path within a repository."""
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if not v:
            raise ValueError("FilePath must not be empty")
        if len(v) > 500:
            raise ValueError(f"FilePath exceeds 500 chars ({len(v)})")
        if v.startswith("/"):
            raise ValueError("FilePath must be relative, not absolute")
        if ".." in v.split("/"):
            raise ValueError("FilePath must not contain '..' traversal")
        return v


class LineNumber(BaseModel):
    """1-based line number within a source file."""
    model_config = ConfigDict(frozen=True)
    value: int

    @field_validator("value")
    @classmethod
    def _validate(cls, v: int) -> int:
        if v < 1:
            raise ValueError(f"LineNumber must be >= 1, got {v}")
        if v > 1_000_000:
            raise ValueError(f"LineNumber must be <= 1000000, got {v}")
        return v


class ReviewRequestId(BaseModel):
    """UUID string identifying a unique review request."""
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if not _UUID_RE.match(v):
            raise ValueError(f"Invalid UUID format: {v!r}")
        return v


# ── Data models ────────────────────────────────────────


class DiffHunk(BaseModel):
    """A single parsed hunk from a unified diff."""
    model_config = ConfigDict(frozen=True)
    id: str
    file_path: str
    start_line_old: int
    count_old: int
    start_line_new: int
    count_new: int
    context_before: list[str]
    added_lines: list[str]
    removed_lines: list[str]
    context_after: list[str]
    raw_header: str
    classifications: list[ClassificationLabel]
    language: Optional[str] = None


class PolicyToken(BaseModel):
    """Agent-Safe policy token defining what a reviewer agent is permitted to access and do."""
    model_config = ConfigDict(frozen=True)
    token_id: str
    reviewer_id: str
    allowed_file_patterns: list[str]
    denied_file_patterns: list[str]
    allowed_classifications: list[ClassificationLabel]
    max_severity: Severity
    issued_at: str
    expires_at: Optional[str] = None


class Finding(BaseModel):
    """A single issue found by a reviewer in a specific hunk."""
    model_config = ConfigDict(frozen=True)
    id: str
    hunk_id: str
    file_path: str
    line_number: Optional[int] = None
    severity: Severity
    confidence: Confidence
    title: str
    description: str
    suggestion: Optional[str] = None
    rule_id: str
    stage: ReviewStage


class Assessment(BaseModel):
    """A single reviewer's complete assessment of the diff hunks it was given."""
    model_config = ConfigDict(frozen=True)
    id: str
    review_request_id: str
    stage: ReviewStage
    reviewer_id: str
    decision: ReviewDecision
    findings: list[Finding]
    confidence: Confidence
    is_partial: bool
    error_message: Optional[str] = None
    duration_ms: int
    created_at: str


# ── Rule data structures ──────────────────────────────


class RulePattern(BaseModel):
    """Frozen dataclass representing a single compiled detection rule."""
    model_config = ConfigDict(frozen=True)
    rule_id: RuleId
    pattern: str
    severity: Severity
    confidence: Confidence
    message_template: str
    suggestion: Optional[str] = None

    @field_validator("pattern")
    @classmethod
    def _validate_pattern(cls, v: str) -> str:
        if len(v) < 1:
            raise ValueError("pattern must not be empty")
        if len(v) > 2000:
            raise ValueError(f"pattern exceeds 2000 chars ({len(v)})")
        return v

    @field_validator("message_template")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        if len(v) < 1:
            raise ValueError("message_template must not be empty")
        if len(v) > 500:
            raise ValueError(f"message_template exceeds 500 chars ({len(v)})")
        return v


class AstRule(BaseModel):
    """Frozen dataclass representing a single AST-based detection rule."""
    model_config = ConfigDict(frozen=True)
    rule_id: RuleId
    node_types: list[str]
    severity: Severity
    confidence: Confidence
    message_template: str

    @field_validator("message_template")
    @classmethod
    def _validate_message(cls, v: str) -> str:
        if len(v) < 1:
            raise ValueError("message_template must not be empty")
        if len(v) > 500:
            raise ValueError(f"message_template exceeds 500 chars ({len(v)})")
        return v


class ImportInfo(BaseModel):
    """Parsed import information extracted from a single import statement."""
    model_config = ConfigDict(frozen=True)
    module: str
    names: list[str]
    file_path: str
    line_number: int


class HunkAnalysisError(BaseModel):
    """Structured record of an error encountered while analyzing a single hunk."""
    model_config = ConfigDict(frozen=True)
    file_path: FilePath
    start_line: LineNumber
    error_type: str
    error_message: str

    @field_validator("error_message")
    @classmethod
    def _validate_msg(cls, v: str) -> str:
        if len(v) > 500:
            raise ValueError(f"error_message exceeds 500 chars ({len(v)})")
        return v


class FilteredHunksResult(BaseModel):
    """Result of filtering hunks by policy."""
    model_config = ConfigDict(frozen=True)
    permitted: list[DiffHunk]
    denied_count: int

    @field_validator("denied_count")
    @classmethod
    def _validate_denied(cls, v: int) -> int:
        if v < 0 or v > 100_000:
            raise ValueError(f"denied_count must be 0..100000, got {v}")
        return v


class DecisionDerivation(BaseModel):
    """Intermediate result of deriving a ReviewDecision from aggregate finding severities."""
    model_config = ConfigDict(frozen=True)
    decision: ReviewDecision
    min_confidence: Confidence
    has_critical: bool
    has_high: bool


# ── Confidence ordering ────────────────────────────────

_CONFIDENCE_RANK = {
    Confidence.low: 0,
    Confidence.medium: 1,
    Confidence.high: 2,
}


# ── Core functions ─────────────────────────────────────


def filter_hunks_by_policy(
    hunks: list[DiffHunk],
    policy: PolicyToken,
    stage: ReviewStage,
) -> FilteredHunksResult:
    """
    Filters a list of DiffHunks according to PolicyToken scoping rules.
    PACT-KEY: FILTER-HUNKS-POLICY-V1
    """
    if not hunks:
        return FilteredHunksResult(permitted=[], denied_count=0)

    permitted: list[DiffHunk] = []
    denied = 0

    for hunk in hunks:
        fp = hunk.file_path
        # Deny-wins: check denied patterns first
        if any(fnmatch.fnmatch(fp, pat) for pat in policy.denied_file_patterns):
            denied += 1
            continue
        # If allowed patterns specified, hunk must match at least one
        if policy.allowed_file_patterns:
            if not any(fnmatch.fnmatch(fp, pat) for pat in policy.allowed_file_patterns):
                denied += 1
                continue
        permitted.append(hunk)

    return FilteredHunksResult(permitted=permitted, denied_count=denied)


def derive_decision(findings: list[Finding]) -> DecisionDerivation:
    """
    Derives a ReviewDecision and conservative minimum Confidence from findings.
    PACT-KEY: DERIVE-DECISION-V1
    """
    if not findings:
        return DecisionDerivation(
            decision=ReviewDecision.pass_,
            min_confidence=Confidence.high,
            has_critical=False,
            has_high=False,
        )

    has_critical = any(f.severity == Severity.critical for f in findings)
    has_high = any(f.severity == Severity.high for f in findings)
    has_medium = any(f.severity == Severity.medium for f in findings)

    if has_critical or has_high:
        decision = ReviewDecision.block
    elif has_medium:
        decision = ReviewDecision.warn
    else:
        decision = ReviewDecision.pass_

    min_confidence = min(
        (f.confidence for f in findings),
        key=lambda c: _CONFIDENCE_RANK[c],
    )

    return DecisionDerivation(
        decision=decision,
        min_confidence=min_confidence,
        has_critical=has_critical,
        has_high=has_high,
    )


def build_assessment(
    reviewer_id: str,
    stage: ReviewStage,
    findings: list[Finding],
    hunks_analyzed: int,
    hunks_skipped: int,
    errors: list,
    review_request_id: ReviewRequestId,
    start_ns: int,
) -> Assessment:
    """
    Constructs a frozen Assessment from the reviewer's analysis results.
    PACT-KEY: BUILD-ASSESSMENT-V1
    """
    valid_ids = {"security", "correctness", "style", "architecture"}
    if reviewer_id not in valid_ids:
        raise ValueError(f"Unrecognized reviewer_id: {reviewer_id!r}")

    # Accept both ReviewRequestId objects and plain strings
    if isinstance(review_request_id, str):
        rrid_str = review_request_id
    elif hasattr(review_request_id, "value"):
        rrid_str = review_request_id.value
    else:
        rrid_str = str(review_request_id)
    assessment_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{rrid_str}:{reviewer_id}"))

    duration_ns = time.monotonic_ns() - start_ns
    duration_ms = max(0, duration_ns // 1_000_000)

    derivation = derive_decision(findings)

    is_partial = len(errors) > 0
    error_message: Optional[str] = None
    if errors:
        error_message = "; ".join(
            str(e.error_message) if hasattr(e, "error_message") else str(e)
            for e in errors
        )

    return Assessment(
        id=assessment_id,
        review_request_id=rrid_str,
        stage=stage,
        reviewer_id=reviewer_id,
        decision=derivation.decision,
        findings=findings,
        confidence=derivation.min_confidence,
        is_partial=is_partial,
        error_message=error_message,
        duration_ms=duration_ms,
        created_at=datetime.now(timezone.utc).isoformat(),
    )


# ── ReviewerProtocol ──────────────────────────────────


@runtime_checkable
class ReviewerProtocol(Protocol):
    """Protocol for all reviewer implementations."""

    @property
    def reviewer_id(self) -> str: ...

    @property
    def stage(self) -> ReviewStage: ...

    async def review(
        self,
        hunks: list[DiffHunk],
        policy: PolicyToken,
        review_request_id: ReviewRequestId,
    ) -> Assessment: ...


# ══════════════════════════════════════════════════════
# Security Rule Catalog (module-level frozen constants)
# ══════════════════════════════════════════════════════

_SECURITY_PATTERNS: tuple[tuple[str, re.Pattern, Severity, Confidence, str, str | None], ...] = (
    (
        "SEC-001",
        re.compile(
            r"""(?:api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token|access[_-]?key)"""
            r"""\s*=\s*['"][^'"]{4,}['"]""",
            re.IGNORECASE,
        ),
        Severity.critical,
        Confidence.high,
        "Hardcoded secret detected: {match}",
        "Use environment variables or a secrets manager instead of hardcoding credentials.",
    ),
    (
        "SEC-002",
        re.compile(
            r"""(?:f['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*\{)|"""
            r"""(?:(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*['"]\s*\+\s*\w+)|"""
            r"""(?:\.execute\(\s*['"]\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*['"]\s*\+)""",
            re.IGNORECASE,
        ),
        Severity.high,
        Confidence.medium,
        "Potential SQL injection: {match}",
        "Use parameterized queries instead of string concatenation/interpolation.",
    ),
    (
        "SEC-003",
        re.compile(
            r"""(?:"""
            r"""(?:os\.path\.join|open)\s*\(.*(?:user_input|request\.|params\[|argv)|"""
            r"""(?:os\.path\.join|open)\s*\(.*\.\.[\\/]|"""
            r"""(?:user_input|request\.|params\[|argv).*[\\/]\.\."""
            r""")""",
            re.IGNORECASE,
        ),
        Severity.high,
        Confidence.medium,
        "Potential path traversal: {match}",
        "Validate and sanitize file paths. Use pathlib and resolve against a base directory.",
    ),
    (
        "SEC-004",
        re.compile(
            r"""(?:"""
            r"""(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(.*(?:\+|\.format|f['"])|"""
            r"""os\.system\s*\(\s*(?!['"])[\w.]+|"""
            r"""subprocess\.(?:call|run|Popen|check_output)\s*\(.*shell\s*=\s*True"""
            r""")""",
            re.IGNORECASE,
        ),
        Severity.critical,
        Confidence.medium,
        "Potential command injection: {match}",
        "Use subprocess with a list of arguments instead of shell=True or string concatenation.",
    ),
    (
        "SEC-005",
        re.compile(
            r"""(?:pickle\.loads?|yaml\.load\s*\((?!.*Loader)|marshal\.loads?|shelve\.open)\s*\(""",
            re.IGNORECASE,
        ),
        Severity.high,
        Confidence.high,
        "Insecure deserialization detected: {match}",
        "Use safe loaders (e.g., yaml.safe_load) or avoid deserializing untrusted data.",
    ),
    (
        "SEC-006",
        re.compile(
            r"""(?:hashlib\.(?:md5|sha1)\s*\(|DES\b|RC4\b|Blowfish\b)""",
            re.IGNORECASE,
        ),
        Severity.medium,
        Confidence.medium,
        "Weak cryptography detected: {match}",
        "Use strong cryptographic algorithms (e.g., SHA-256, AES-256).",
    ),
    (
        "SEC-007",
        re.compile(
            r"""(?:print\s*\(.*(?:password|secret|token|key)|logging\.debug\s*\(.*(?:password|secret|token|key))""",
            re.IGNORECASE,
        ),
        Severity.medium,
        Confidence.low,
        "Potential debug/logging exposure of sensitive data: {match}",
        "Remove sensitive data from logging and print statements.",
    ),
)


# ══════════════════════════════════════════════════════
# Correctness Rule Catalog
# ══════════════════════════════════════════════════════

_CORRECTNESS_TEXT_PATTERNS: tuple[tuple[str, re.Pattern, Severity, Confidence, str], ...] = (
    (
        "COR-004",
        re.compile(r"^\s*except\s*:\s*$"),
        Severity.medium,
        Confidence.high,
        "Bare except clause catches all exceptions including SystemExit and KeyboardInterrupt",
    ),
    (
        "COR-005",
        re.compile(r"def\s+\w+\s*\([^)]*(?:=\s*\[\]|=\s*\{\}|=\s*set\s*\(\s*\))"),
        Severity.medium,
        Confidence.high,
        "Mutable default argument — default is shared across calls",
    ),
)


# ══════════════════════════════════════════════════════
# Style Rule Catalog
# ══════════════════════════════════════════════════════

_MAX_LINE_LENGTH = 120

_STYLE_PATTERNS: tuple[tuple[str, re.Pattern, Severity, Confidence, str, str | None], ...] = (
    (
        "STY-001",
        re.compile(r".{" + str(_MAX_LINE_LENGTH + 1) + r",}"),
        Severity.low,
        Confidence.high,
        "Line exceeds {max_len} characters",
        f"Keep lines under {_MAX_LINE_LENGTH} characters.",
    ),
    (
        "STY-002",
        re.compile(r"^\s*def\s+([a-z]+[A-Z]\w*)\s*\("),
        Severity.low,
        Confidence.medium,
        "Naming convention violation: camelCase function name",
        "Use snake_case for function names (PEP 8).",
    ),
    (
        "STY-005",
        re.compile(r"[ \t]+$"),
        Severity.low,
        Confidence.high,
        "Trailing whitespace detected",
        "Remove trailing whitespace.",
    ),
    (
        "STY-006",
        re.compile(r"^(\t+ +| +\t+)"),
        Severity.low,
        Confidence.medium,
        "Mixed indentation (tabs and spaces) detected",
        "Use consistent indentation — prefer spaces.",
    ),
)


# ══════════════════════════════════════════════════════
# Architecture constants
# ══════════════════════════════════════════════════════

_IMPORT_RE = re.compile(r"^\s*(?:import\s+([\w.]+)|from\s+([\w.]+)\s+import\s+(.*))")
_GOD_MODULE_THRESHOLD = 15


# ══════════════════════════════════════════════════════
# Helper: create finding
# ══════════════════════════════════════════════════════


def _make_finding(
    *,
    hunk: DiffHunk,
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    title: str,
    description: str,
    stage: ReviewStage,
    line_number: int | None = None,
    suggestion: str | None = None,
) -> Finding:
    fid = str(uuid.uuid5(
        uuid.NAMESPACE_DNS,
        f"{hunk.id}:{rule_id}:{line_number or 0}:{description[:80]}",
    ))
    return Finding(
        id=fid,
        hunk_id=hunk.id,
        file_path=hunk.file_path,
        line_number=line_number,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        suggestion=suggestion,
        rule_id=rule_id,
        stage=stage,
    )


# ══════════════════════════════════════════════════════
# SecurityReviewer
# ══════════════════════════════════════════════════════


class SecurityReviewer:
    """Detects security vulnerabilities via compiled regex pattern matching. PACT-KEY: SEC-REVIEW-V1"""

    def __init__(self) -> None:
        self._reviewer_id = "security"
        self._stage = ReviewStage.security

    @property
    def reviewer_id(self) -> str:
        return self._reviewer_id

    @property
    def stage(self) -> ReviewStage:
        return self._stage

    async def review(
        self,
        hunks: list[DiffHunk],
        policy: PolicyToken,
        review_request_id: ReviewRequestId,
    ) -> Assessment:
        """Analyze hunks for security vulnerabilities. PACT-KEY: SEC-REVIEW-V1"""
        start_ns = time.monotonic_ns()
        findings: list[Finding] = []
        errors: list[HunkAnalysisError] = []

        filtered = filter_hunks_by_policy(hunks, policy, self._stage)
        hunks_skipped = filtered.denied_count

        for hunk in filtered.permitted:
            try:
                self._analyze_hunk(hunk, findings)
            except Exception as exc:
                try:
                    errors.append(HunkAnalysisError(
                        file_path=FilePath(value=hunk.file_path),
                        start_line=LineNumber(value=max(1, hunk.start_line_new)),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:500],
                    ))
                except Exception:
                    pass

        return build_assessment(
            reviewer_id=self._reviewer_id,
            stage=self._stage,
            findings=findings,
            hunks_analyzed=len(filtered.permitted) - len(errors),
            hunks_skipped=hunks_skipped,
            errors=errors,
            review_request_id=review_request_id,
            start_ns=start_ns,
        )

    def _analyze_hunk(self, hunk: DiffHunk, findings: list[Finding]) -> None:
        for line_idx, line in enumerate(hunk.added_lines):
            for rule_id, pattern, severity, confidence, msg_tpl, suggestion in _SECURITY_PATTERNS:
                m = pattern.search(line)
                if m:
                    matched_text = m.group(0)[:100]
                    findings.append(_make_finding(
                        hunk=hunk,
                        rule_id=rule_id,
                        severity=severity,
                        confidence=confidence,
                        title=msg_tpl.split(":")[0].strip() if ":" in msg_tpl else msg_tpl.replace("{match}", "").strip(),
                        description=msg_tpl.replace("{match}", matched_text),
                        stage=self._stage,
                        line_number=hunk.start_line_new + line_idx,
                        suggestion=suggestion,
                    ))


# ══════════════════════════════════════════════════════
# CorrectnessReviewer
# ══════════════════════════════════════════════════════


class CorrectnessReviewer:
    """Analyzes diff hunks for correctness issues. PACT-KEY: COR-REVIEW-V1"""

    def __init__(self) -> None:
        self._reviewer_id = "correctness"
        self._stage = ReviewStage.correctness

    @property
    def reviewer_id(self) -> str:
        return self._reviewer_id

    @property
    def stage(self) -> ReviewStage:
        return self._stage

    async def review(
        self,
        hunks: list[DiffHunk],
        policy: PolicyToken,
        review_request_id: ReviewRequestId,
    ) -> Assessment:
        """Analyze hunks for correctness issues. PACT-KEY: COR-REVIEW-V1"""
        start_ns = time.monotonic_ns()
        findings: list[Finding] = []
        errors: list[HunkAnalysisError] = []

        filtered = filter_hunks_by_policy(hunks, policy, self._stage)
        hunks_skipped = filtered.denied_count

        for hunk in filtered.permitted:
            try:
                self._analyze_hunk(hunk, findings)
            except Exception as exc:
                try:
                    errors.append(HunkAnalysisError(
                        file_path=FilePath(value=hunk.file_path),
                        start_line=LineNumber(value=max(1, hunk.start_line_new)),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:500],
                    ))
                except Exception:
                    pass

        return build_assessment(
            reviewer_id=self._reviewer_id,
            stage=self._stage,
            findings=findings,
            hunks_analyzed=len(filtered.permitted) - len(errors),
            hunks_skipped=hunks_skipped,
            errors=errors,
            review_request_id=review_request_id,
            start_ns=start_ns,
        )

    def _analyze_hunk(self, hunk: DiffHunk, findings: list[Finding]) -> None:
        code = "\n".join(hunk.added_lines)

        # Text-based checks always run
        for line_idx, line in enumerate(hunk.added_lines):
            for rule_id, pattern, severity, confidence, msg in _CORRECTNESS_TEXT_PATTERNS:
                if pattern.search(line):
                    findings.append(_make_finding(
                        hunk=hunk,
                        rule_id=rule_id,
                        severity=severity,
                        confidence=confidence,
                        title=msg.split("\u2014")[0].strip(),
                        description=msg,
                        stage=self._stage,
                        line_number=hunk.start_line_new + line_idx,
                    ))

        # AST-based checks — graceful fallback on SyntaxError
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return

        self._check_ast(tree, hunk, findings)

    def _check_ast(self, tree: ast.Module, hunk: DiffHunk, findings: list[Finding]) -> None:
        for node in ast.walk(tree):
            # COR-004: bare except (AST-based, complementing text check)
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                findings.append(_make_finding(
                    hunk=hunk,
                    rule_id="COR-004",
                    severity=Severity.medium,
                    confidence=Confidence.high,
                    title="Bare except clause",
                    description="Bare except clause catches all exceptions including SystemExit and KeyboardInterrupt",
                    stage=self._stage,
                    line_number=hunk.start_line_new + (node.lineno - 1),
                ))
            # COR-005: mutable default argument
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for default in node.args.defaults + node.args.kw_defaults:
                    if default is None:
                        continue
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                        findings.append(_make_finding(
                            hunk=hunk,
                            rule_id="COR-005",
                            severity=Severity.medium,
                            confidence=Confidence.high,
                            title="Mutable default argument",
                            description=f"Function '{node.name}' has a mutable default argument",
                            stage=self._stage,
                            line_number=hunk.start_line_new + (node.lineno - 1),
                        ))
            # COR-006: unreachable code after return/raise/break/continue
            if hasattr(node, "body") and isinstance(node.body, list):
                self._check_unreachable(node.body, hunk, findings)

    def _check_unreachable(self, stmts: list, hunk: DiffHunk, findings: list[Finding]) -> None:
        """Check for statements after return/raise/break/continue in a statement block."""
        _TERMINAL = (ast.Return, ast.Raise, ast.Break, ast.Continue)
        for i, stmt in enumerate(stmts):
            if isinstance(stmt, _TERMINAL) and i < len(stmts) - 1:
                next_stmt = stmts[i + 1]
                findings.append(_make_finding(
                    hunk=hunk,
                    rule_id="COR-006",
                    severity=Severity.medium,
                    confidence=Confidence.high,
                    title="Unreachable code",
                    description="Code after return/raise/break/continue is unreachable",
                    stage=self._stage,
                    line_number=hunk.start_line_new + (next_stmt.lineno - 1),
                ))
                break  # Only report the first unreachable statement per block


# ══════════════════════════════════════════════════════
# StyleReviewer
# ══════════════════════════════════════════════════════


class StyleReviewer:
    """Checks coding convention violations via text/regex analysis. PACT-KEY: STY-REVIEW-V1"""

    def __init__(self) -> None:
        self._reviewer_id = "style"
        self._stage = ReviewStage.style

    @property
    def reviewer_id(self) -> str:
        return self._reviewer_id

    @property
    def stage(self) -> ReviewStage:
        return self._stage

    async def review(
        self,
        hunks: list[DiffHunk],
        policy: PolicyToken,
        review_request_id: ReviewRequestId,
    ) -> Assessment:
        """Analyze hunks for style violations. PACT-KEY: STY-REVIEW-V1"""
        start_ns = time.monotonic_ns()
        findings: list[Finding] = []
        errors: list[HunkAnalysisError] = []

        filtered = filter_hunks_by_policy(hunks, policy, self._stage)
        hunks_skipped = filtered.denied_count

        for hunk in filtered.permitted:
            try:
                self._analyze_hunk(hunk, findings)
            except Exception as exc:
                try:
                    errors.append(HunkAnalysisError(
                        file_path=FilePath(value=hunk.file_path),
                        start_line=LineNumber(value=max(1, hunk.start_line_new)),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:500],
                    ))
                except Exception:
                    pass

        return build_assessment(
            reviewer_id=self._reviewer_id,
            stage=self._stage,
            findings=findings,
            hunks_analyzed=len(filtered.permitted) - len(errors),
            hunks_skipped=hunks_skipped,
            errors=errors,
            review_request_id=review_request_id,
            start_ns=start_ns,
        )

    def _analyze_hunk(self, hunk: DiffHunk, findings: list[Finding]) -> None:
        has_tab_indent = False
        has_space_indent = False
        first_tab_line_idx: int | None = None
        for line_idx, line in enumerate(hunk.added_lines):
            for rule_id, pattern, severity, confidence, msg, suggestion in _STYLE_PATTERNS:
                # Cap severity at medium for style findings
                capped = severity if severity not in (Severity.critical, Severity.high) else Severity.medium
                if pattern.search(line):
                    findings.append(_make_finding(
                        hunk=hunk,
                        rule_id=rule_id,
                        severity=capped,
                        confidence=confidence,
                        title=msg.replace("{max_len}", str(_MAX_LINE_LENGTH)),
                        description=msg.replace("{max_len}", str(_MAX_LINE_LENGTH)),
                        stage=self._stage,
                        line_number=hunk.start_line_new + line_idx,
                        suggestion=suggestion,
                    ))
            # Track indentation style across lines for cross-line mixed indent
            if line and line[0] == '\t':
                if not has_tab_indent:
                    first_tab_line_idx = line_idx
                has_tab_indent = True
            elif line and line[0] == ' ':
                has_space_indent = True

        # Cross-line mixed indentation: some lines use tabs, others use spaces
        if has_tab_indent and has_space_indent and first_tab_line_idx is not None:
            findings.append(_make_finding(
                hunk=hunk,
                rule_id="STY-006",
                severity=Severity.low,
                confidence=Confidence.medium,
                title="Mixed indentation (tabs and spaces) detected",
                description="Hunk mixes tab and space indentation across lines",
                stage=self._stage,
                line_number=hunk.start_line_new + first_tab_line_idx,
                suggestion="Use consistent indentation — prefer spaces.",
            ))


# ══════════════════════════════════════════════════════
# ArchitectureReviewer
# ══════════════════════════════════════════════════════


class ArchitectureReviewer:
    """Detects coupling via import analysis and cross-hunk patterns. PACT-KEY: ARC-REVIEW-V1"""

    def __init__(self) -> None:
        self._reviewer_id = "architecture"
        self._stage = ReviewStage.architecture

    @property
    def reviewer_id(self) -> str:
        return self._reviewer_id

    @property
    def stage(self) -> ReviewStage:
        return self._stage

    async def review(
        self,
        hunks: list[DiffHunk],
        policy: PolicyToken,
        review_request_id: ReviewRequestId,
    ) -> Assessment:
        """Analyze hunks for architectural issues. PACT-KEY: ARC-REVIEW-V1"""
        start_ns = time.monotonic_ns()
        findings: list[Finding] = []
        errors: list[HunkAnalysisError] = []

        filtered = filter_hunks_by_policy(hunks, policy, self._stage)
        hunks_skipped = filtered.denied_count

        # Collect imports across all permitted hunks for cross-hunk analysis
        file_imports: dict[str, list[ImportInfo]] = {}

        for hunk in filtered.permitted:
            try:
                imports = self._extract_imports(hunk)
                file_imports.setdefault(hunk.file_path, []).extend(imports)
            except Exception as exc:
                try:
                    errors.append(HunkAnalysisError(
                        file_path=FilePath(value=hunk.file_path),
                        start_line=LineNumber(value=max(1, hunk.start_line_new)),
                        error_type=type(exc).__name__,
                        error_message=str(exc)[:500],
                    ))
                except Exception:
                    pass

        # Cross-hunk analysis
        try:
            self._check_god_modules(file_imports, filtered.permitted, findings)
            self._check_circular_dependencies(file_imports, filtered.permitted, findings)
        except Exception:
            pass

        return build_assessment(
            reviewer_id=self._reviewer_id,
            stage=self._stage,
            findings=findings,
            hunks_analyzed=len(filtered.permitted) - len(errors),
            hunks_skipped=hunks_skipped,
            errors=errors,
            review_request_id=review_request_id,
            start_ns=start_ns,
        )

    def _extract_imports(self, hunk: DiffHunk) -> list[ImportInfo]:
        imports: list[ImportInfo] = []
        for line_idx, line in enumerate(hunk.added_lines):
            m = _IMPORT_RE.match(line)
            if m:
                if m.group(1):
                    imports.append(ImportInfo(
                        module=m.group(1),
                        names=[],
                        file_path=hunk.file_path,
                        line_number=hunk.start_line_new + line_idx,
                    ))
                elif m.group(2):
                    names = [n.strip().split(" as ")[0].strip() for n in m.group(3).split(",")]
                    imports.append(ImportInfo(
                        module=m.group(2),
                        names=names,
                        file_path=hunk.file_path,
                        line_number=hunk.start_line_new + line_idx,
                    ))
        return imports

    def _check_god_modules(
        self,
        file_imports: dict[str, list[ImportInfo]],
        hunks: list[DiffHunk],
        findings: list[Finding],
    ) -> None:
        for file_path, imports in file_imports.items():
            if len(imports) > _GOD_MODULE_THRESHOLD:
                hunk = next((h for h in hunks if h.file_path == file_path), None)
                if hunk:
                    findings.append(_make_finding(
                        hunk=hunk,
                        rule_id="ARC-004",
                        severity=Severity.medium,
                        confidence=Confidence.medium,
                        title="God module detected",
                        description=f"File '{file_path}' has {len(imports)} imports (threshold: {_GOD_MODULE_THRESHOLD})",
                        stage=self._stage,
                        line_number=hunk.start_line_new,
                    ))

    def _check_circular_dependencies(
        self,
        file_imports: dict[str, list[ImportInfo]],
        hunks: list[DiffHunk],
        findings: list[Finding],
    ) -> None:
        file_to_modules: dict[str, set[str]] = {}
        for file_path, imports in file_imports.items():
            file_to_modules[file_path] = {imp.module for imp in imports}

        files = list(file_to_modules.keys())
        for i, file_a in enumerate(files):
            for file_b in files[i + 1:]:
                modules_a = file_to_modules[file_a]
                modules_b = file_to_modules[file_b]
                a_imports_b = any(
                    file_b.replace("/", ".").replace(".py", "") in mod
                    or mod in file_b.replace("/", ".").replace(".py", "")
                    for mod in modules_a
                )
                b_imports_a = any(
                    file_a.replace("/", ".").replace(".py", "") in mod
                    or mod in file_a.replace("/", ".").replace(".py", "")
                    for mod in modules_b
                )
                if a_imports_b and b_imports_a:
                    hunk = next((h for h in hunks if h.file_path == file_a), hunks[0] if hunks else None)
                    if hunk:
                        findings.append(_make_finding(
                            hunk=hunk,
                            rule_id="ARC-003",
                            severity=Severity.high,
                            confidence=Confidence.low,
                            title="Circular dependency hint",
                            description=f"Potential circular dependency between '{file_a}' and '{file_b}'",
                            stage=self._stage,
                            line_number=hunk.start_line_new,
                        ))


# ══════════════════════════════════════════════════════
# Factory functions
# ══════════════════════════════════════════════════════


def get_all_reviewers() -> list:
    """
    Returns all four canonical reviewer implementations in recommended order.
    PACT-KEY: GET-ALL-REVIEWERS-V1
    """
    return [
        SecurityReviewer(),
        CorrectnessReviewer(),
        StyleReviewer(),
        ArchitectureReviewer(),
    ]


_STAGE_TO_REVIEWER: dict[ReviewStage, type] = {
    ReviewStage.security: SecurityReviewer,
    ReviewStage.correctness: CorrectnessReviewer,
    ReviewStage.style: StyleReviewer,
    ReviewStage.architecture: ArchitectureReviewer,
}


def get_reviewer_by_stage(stage: ReviewStage):
    """
    Returns the canonical reviewer implementation for a given ReviewStage.
    PACT-KEY: GET-REVIEWER-BY-STAGE-V1
    """
    cls = _STAGE_TO_REVIEWER.get(stage)
    if cls is None:
        raise ValueError(f"Unrecognized ReviewStage value: {stage!r}")
    return cls()


# ══════════════════════════════════════════════════════
# Emission wrapper (Pact Chronicler integration)
# ══════════════════════════════════════════════════════


class _ReviewerProxy:
    """Proxy that wraps a reviewer's review method with event emission."""

    def __init__(self, reviewer, event_handler):
        self._reviewer = reviewer
        self._handler = event_handler

    def review(self, *args, **kwargs):
        pact_key = f"PACT:reviewers:{type(self._reviewer).__name__}.review"
        if self._handler:
            self._handler({
                "event": "invoked",
                "pact_key": pact_key,
                "input_classification": [],
            })
        try:
            result = self._reviewer.review(*args, **kwargs)
            if self._handler:
                self._handler({"event": "completed", "pact_key": pact_key})
            return result
        except Exception as exc:
            if self._handler:
                self._handler({"event": "error", "pact_key": pact_key, "error": str(exc)})
            raise


class Reviewers:
    """Pact emission wrapper for the reviewers component.

    Wraps module-level functions and reviewer classes with Chronicler event
    emission. The underlying reviewers are pure analysis units; this class
    adds the event emission layer expected by the Pact framework.
    """

    def __init__(self, event_handler=None):
        self._handler = event_handler
        self.SecurityReviewer = _ReviewerProxy(SecurityReviewer(), self._handler)
        self.CorrectnessReviewer = _ReviewerProxy(CorrectnessReviewer(), self._handler)
        self.StyleReviewer = _ReviewerProxy(StyleReviewer(), self._handler)
        self.ArchitectureReviewer = _ReviewerProxy(ArchitectureReviewer(), self._handler)

    def _emit(self, pact_key: str, event_type: str, **extra):
        if self._handler:
            evt = {"event": event_type, "pact_key": pact_key, "input_classification": []}
            evt.update(extra)
            self._handler(evt)

    def filter_hunks_by_policy(self, *args, **kwargs):
        """PACT-KEY: FILTER-HUNKS-POLICY-V1"""
        pact_key = "PACT:reviewers:filter_hunks_by_policy"
        self._emit(pact_key, "invoked")
        try:
            result = filter_hunks_by_policy(*args, **kwargs)
            self._emit(pact_key, "completed")
            return result
        except Exception as exc:
            self._emit(pact_key, "error", error=str(exc))
            raise

    def derive_decision(self, *args, **kwargs):
        """PACT-KEY: DERIVE-DECISION-V1"""
        pact_key = "PACT:reviewers:derive_decision"
        self._emit(pact_key, "invoked")
        try:
            result = derive_decision(*args, **kwargs)
            self._emit(pact_key, "completed")
            return result
        except Exception as exc:
            self._emit(pact_key, "error", error=str(exc))
            raise

    def build_assessment(self, *args, **kwargs):
        """PACT-KEY: BUILD-ASSESSMENT-V1"""
        pact_key = "PACT:reviewers:build_assessment"
        self._emit(pact_key, "invoked")
        try:
            result = build_assessment(*args, **kwargs)
            self._emit(pact_key, "completed")
            return result
        except Exception as exc:
            self._emit(pact_key, "error", error=str(exc))
            raise

    def get_all_reviewers(self, *args, **kwargs):
        """PACT-KEY: GET-ALL-REVIEWERS-V1"""
        pact_key = "PACT:reviewers:get_all_reviewers"
        self._emit(pact_key, "invoked")
        try:
            result = get_all_reviewers(*args, **kwargs)
            self._emit(pact_key, "completed")
            return result
        except Exception as exc:
            self._emit(pact_key, "error", error=str(exc))
            raise

    def get_reviewer_by_stage(self, *args, **kwargs):
        """PACT-KEY: GET-REVIEWER-BY-STAGE-V1"""
        pact_key = "PACT:reviewers:get_reviewer_by_stage"
        self._emit(pact_key, "invoked")
        try:
            result = get_reviewer_by_stage(*args, **kwargs)
            self._emit(pact_key, "completed")
            return result
        except Exception as exc:
            self._emit(pact_key, "error", error=str(exc))
            raise
