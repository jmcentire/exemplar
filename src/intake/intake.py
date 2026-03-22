"""Diff Intake & Classification — parse unified diffs and apply Ledger field rules.

Two-phase architecture:
  1. parse_diff  — deterministic string processing into DiffHunk records
  2. classify_hunks — pre-compiled Ledger regex rules applied to added_lines only

All public types are frozen Pydantic models.  All public functions carry PACT
keys for Sentinel attribution.
"""
from __future__ import annotations

import enum
import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol, Tuple, runtime_checkable

from pydantic import BaseModel, Field, field_validator, model_validator

# ═══════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════


class DiffSourceKind(str, enum.Enum):
    """Discriminator for the origin of diff text input."""
    file = "file"
    stdin = "stdin"


class ClassificationLabel(str, enum.Enum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"


class IntakePhase(str, enum.Enum):
    """Which phase of intake processing produced an error or event."""
    read = "read"
    parse = "parse"
    classify = "classify"
    orchestrate = "orchestrate"


class ReviewStage(str, enum.Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


class ChroniclerEventType(str, enum.Enum):
    """Well-known Chronicler event types."""
    review_started = "review.started"
    stage_started = "stage.started"
    stage_complete = "stage.complete"
    assessment_merged = "assessment.merged"
    report_sealed = "report.sealed"
    review_complete = "review.complete"
    policy_violation = "policy.violation"
    pattern_detected = "pattern.detected"
    learning_recorded = "learning.recorded"
    # Intake-specific sub-types used in run_intake:
    intake_started = "review.intake.started"
    intake_parsed = "review.intake.parsed"
    intake_classified = "review.intake.classified"


# ═══════════════════════════════════════════════════════════════════════
# Value objects / structs  (frozen Pydantic models)
# ═══════════════════════════════════════════════════════════════════════


class LineRange(BaseModel):
    """A contiguous range of line numbers within a single file side."""
    model_config = {"frozen": True}

    start: int
    count: int

    @field_validator("start")
    @classmethod
    def _start_ge_1(cls, v: int) -> int:
        if v < 1:
            raise ValueError("Line numbers are 1-based; start must be >= 1.")
        return v

    @field_validator("count")
    @classmethod
    def _count_ge_0(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Line count must be non-negative.")
        return v


class HunkMetadata(BaseModel):
    """Parsed header metadata from a single unified diff hunk."""
    model_config = {"frozen": True}

    old_range: LineRange
    new_range: LineRange
    section_header: str = ""


class IntakeError(BaseModel):
    """A parse or classification error with location context."""
    model_config = {"frozen": True}

    line_number: Optional[int] = None
    message: str
    raw_content: Optional[str] = None
    phase: IntakePhase

    @field_validator("message")
    @classmethod
    def _message_nonempty(cls, v: str) -> str:
        if not v:
            raise ValueError("Error message must not be empty.")
        return v


class DiffHunk(BaseModel):
    """A single parsed hunk from a unified diff."""
    model_config = {"frozen": True}

    id: str
    file_path: str
    start_line_old: int
    count_old: int
    start_line_new: int
    count_new: int
    context_before: List[str] = Field(default_factory=list)
    added_lines: List[str] = Field(default_factory=list)
    removed_lines: List[str] = Field(default_factory=list)
    context_after: List[str] = Field(default_factory=list)
    raw_header: str = ""
    metadata: Optional[HunkMetadata] = None
    classifications: List[ClassificationLabel] = Field(default_factory=list)
    language: Optional[str] = None


class ReviewRequest(BaseModel):
    """Output of intake: a complete review request with classified hunks."""
    model_config = {"frozen": True}

    id: str
    source: str
    hunks: List[DiffHunk] = Field(default_factory=list)
    file_paths: List[str] = Field(default_factory=list)
    created_at: str = ""
    metadata: Dict[str, str] = Field(default_factory=dict)


class IntakeResult(BaseModel):
    """Complete output of run_intake with partial-success semantics."""
    model_config = {"frozen": True}

    review_request: ReviewRequest
    errors: List[IntakeError] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    hunk_count: int = 0
    classified_hunk_count: int = 0

    @field_validator("hunk_count")
    @classmethod
    def _hunk_count_ge_0(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Hunk count must be non-negative.")
        return v

    @field_validator("classified_hunk_count")
    @classmethod
    def _classified_ge_0(cls, v: int) -> int:
        if v < 0:
            raise ValueError("Classified hunk count must be non-negative.")
        return v


class ChroniclerEvent(BaseModel):
    """A structured event emitted at review lifecycle boundaries."""
    model_config = {"frozen": True}

    event_id: str
    event_type: str  # Use str to accept custom event type strings
    review_request_id: str
    timestamp: str
    stage: Optional[ReviewStage] = None
    reviewer_id: Optional[str] = None
    payload: Dict[str, str] = Field(default_factory=dict)
    message: str = ""


class LedgerFieldRule(BaseModel):
    """A single Ledger classification rule: regex pattern -> label."""
    model_config = {"frozen": True}

    pattern: str
    label: ClassificationLabel
    description: str = ""


class LedgerConfig(BaseModel):
    """Configuration for Ledger field classification."""
    model_config = {"frozen": True}

    rules: List[LedgerFieldRule] = Field(default_factory=list)
    default_label: ClassificationLabel = ClassificationLabel.public


# ═══════════════════════════════════════════════════════════════════════
# Protocols
# ═══════════════════════════════════════════════════════════════════════


@runtime_checkable
class DiffSource(Protocol):
    kind: DiffSourceKind

    async def read(self) -> str: ...


@runtime_checkable
class EventEmitter(Protocol):
    async def emit(self, event: ChroniclerEvent) -> None: ...


# ═══════════════════════════════════════════════════════════════════════
# Language detection
# ═══════════════════════════════════════════════════════════════════════

EXTENSION_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".rb": "ruby",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".css": "css",
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".md": "markdown",
    ".sql": "sql",
    ".r": "r",
    ".swift": "swift",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".scala": "scala",
    ".php": "php",
    ".pl": "perl",
    ".pm": "perl",
    ".lua": "lua",
    ".ex": "elixir",
    ".exs": "elixir",
    ".erl": "erlang",
    ".hs": "haskell",
    ".ml": "ocaml",
    ".fs": "fsharp",
    ".vim": "vim",
    ".tf": "terraform",
    ".dockerfile": "dockerfile",
    ".ini": "ini",
    ".cfg": "ini",
    ".proto": "protobuf",
}


def detect_language(file_path: str) -> str:
    """Map a file path's extension to a programming language name.

    Returns 'unknown' for unrecognised extensions or files without extensions.
    Raises ValueError if file_path is empty.
    """
    if not file_path:
        raise ValueError("file_path must not be empty for language detection.")

    # Get the last component for extension extraction
    # Handle compound extensions like "app.test.js" — take the final extension
    basename = file_path.rsplit("/", 1)[-1]

    # Find the last dot that gives us a known extension
    # For ".gitignore" (dotfile with no secondary ext), there is only one dot at position 0
    dot_idx = basename.rfind(".")
    if dot_idx < 0:
        return "unknown"

    # Dotfile without secondary extension: e.g. ".gitignore"
    # A dot at position 0 with no further dots means it's a bare dotfile
    if dot_idx == 0 and "." not in basename[1:]:
        return "unknown"

    ext = basename[dot_idx:].lower()
    return EXTENSION_LANGUAGE_MAP.get(ext, "unknown")


# ═══════════════════════════════════════════════════════════════════════
# Hunk & request ID generation
# ═══════════════════════════════════════════════════════════════════════


def generate_hunk_id(file_path: str, raw_header: str, added_lines: List[str]) -> str:
    """Deterministic hunk ID: 'hunk-' + 12 hex chars from SHA-256.

    SHA-256 is computed over the concatenation of file_path, raw_header,
    and the joined added_lines.
    """
    if not file_path:
        raise ValueError("file_path must not be empty for hunk ID generation.")
    if not raw_header:
        raise ValueError("raw_header must not be empty for hunk ID generation.")
    payload = file_path + raw_header + "\n".join(added_lines)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"hunk-{digest[:12]}"


def generate_request_id() -> str:
    """Generate a ReviewRequest ID: 'req-' + 32 hex chars from UUID4."""
    return f"req-{uuid.uuid4().hex}"


# ═══════════════════════════════════════════════════════════════════════
# Diff parsing regex patterns
# ═══════════════════════════════════════════════════════════════════════

_DIFF_GIT_RE = re.compile(r"^diff --git a/(.*?) b/(.*?)$")
_FILE_OLD_RE = re.compile(r"^--- a/(.+)$")
_FILE_NEW_RE = re.compile(r"^\+\+\+ b/(.+)$")
_HUNK_HEADER_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$"
)
_BINARY_RE = re.compile(r"^Binary files .+ and .+ differ$")


# ═══════════════════════════════════════════════════════════════════════
# parse_diff
# ═══════════════════════════════════════════════════════════════════════


async def parse_diff(raw: str) -> Tuple[List[DiffHunk], List[IntakeError]]:
    """Pure parsing of unified diff text into DiffHunk records.

    Returns (hunks, errors).  Classification fields are left empty.
    """
    if not raw:
        return ([], [])

    # Normalise CRLF -> LF before splitting
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")

    lines = raw.split("\n")
    # Remove trailing empty line from trailing newline
    if lines and lines[-1] == "":
        lines = lines[:-1]

    hunks: List[DiffHunk] = []
    errors: List[IntakeError] = []

    current_file: Optional[str] = None
    saw_any_diff_header = False

    i = 0
    while i < len(lines):
        line = lines[i]

        # Binary file marker
        if _BINARY_RE.match(line):
            saw_any_diff_header = True
            errors.append(IntakeError(
                line_number=i + 1,
                message="Binary file diff detected; cannot parse as text hunk.",
                raw_content=line,
                phase=IntakePhase.parse,
            ))
            i += 1
            continue

        # diff --git header
        m_git = _DIFF_GIT_RE.match(line)
        if m_git:
            saw_any_diff_header = True
            # The b/ side is the canonical file path
            current_file = m_git.group(2)
            i += 1
            continue

        # --- a/file
        m_old = _FILE_OLD_RE.match(line)
        if m_old:
            saw_any_diff_header = True
            i += 1
            continue

        # +++ b/file
        m_new = _FILE_NEW_RE.match(line)
        if m_new:
            saw_any_diff_header = True
            if current_file is None:
                current_file = m_new.group(1)
            i += 1
            continue

        # Hunk header
        if line.startswith("@@"):
            saw_any_diff_header = True
            m_hunk = _HUNK_HEADER_RE.match(line)
            if not m_hunk:
                errors.append(IntakeError(
                    line_number=i + 1,
                    message="Malformed hunk header: could not extract line ranges.",
                    raw_content=line,
                    phase=IntakePhase.parse,
                ))
                i += 1
                continue

            old_start = int(m_hunk.group(1))
            old_count = int(m_hunk.group(2)) if m_hunk.group(2) is not None else 1
            new_start = int(m_hunk.group(3))
            new_count = int(m_hunk.group(4)) if m_hunk.group(4) is not None else 1
            section_header = m_hunk.group(5).strip()
            raw_header = line

            file_path = current_file or "unknown"

            context_before: List[str] = []
            added_lines: List[str] = []
            removed_lines: List[str] = []
            context_after: List[str] = []

            # Track whether we've seen any change lines (to separate
            # context_before from context_after)
            seen_change = False
            i += 1

            while i < len(lines):
                hline = lines[i]
                # Stop at next diff/hunk header
                if (hline.startswith("diff --git ")
                        or hline.startswith("@@")
                        or _FILE_OLD_RE.match(hline)
                        or _FILE_NEW_RE.match(hline)):
                    break
                if hline.startswith("+"):
                    seen_change = True
                    # Move any accumulated context_after back to ... well,
                    # they stay as context_after of the previous change.
                    # For simplicity, treat mid-hunk context as context_after
                    # when there's a subsequent change.
                    added_lines.append(hline[1:])
                elif hline.startswith("-"):
                    seen_change = True
                    removed_lines.append(hline[1:])
                elif hline.startswith(" ") or hline == "":
                    ctx_line = hline[1:] if hline.startswith(" ") else hline
                    if not seen_change:
                        context_before.append(ctx_line)
                    else:
                        context_after.append(ctx_line)
                else:
                    # Non-standard line inside a hunk; treat as context
                    if not seen_change:
                        context_before.append(hline)
                    else:
                        context_after.append(hline)
                i += 1

            # Check for truncation
            declared_old_lines = old_count
            declared_new_lines = new_count
            actual_old_lines = len(removed_lines) + len(context_before) + len(context_after)
            actual_new_lines = len(added_lines) + len(context_before) + len(context_after)
            if actual_old_lines < declared_old_lines or actual_new_lines < declared_new_lines:
                errors.append(IntakeError(
                    line_number=None,
                    message="Hunk appears truncated \u2014 fewer lines than header declares.",
                    raw_content=raw_header,
                    phase=IntakePhase.parse,
                ))

            lang = detect_language(file_path)
            hunk_id = generate_hunk_id(file_path, raw_header, added_lines)

            meta = HunkMetadata(
                old_range=LineRange(start=max(old_start, 1), count=old_count),
                new_range=LineRange(start=max(new_start, 1), count=new_count),
                section_header=section_header,
            )

            hunks.append(DiffHunk(
                id=hunk_id,
                file_path=file_path,
                start_line_old=old_start,
                count_old=old_count,
                start_line_new=new_start,
                count_new=new_count,
                context_before=context_before,
                added_lines=added_lines,
                removed_lines=removed_lines,
                context_after=context_after,
                raw_header=raw_header,
                metadata=meta,
                classifications=[],
                language=lang,
            ))
            continue

        # Ordinary line outside any hunk — skip
        i += 1

    # If we never saw a recognisable diff header, emit an error
    if not saw_any_diff_header and raw.strip():
        errors.append(IntakeError(
            line_number=None,
            message="No diff headers found in input. Expected unified diff format.",
            raw_content=None,
            phase=IntakePhase.parse,
        ))

    return (hunks, errors)


# ═══════════════════════════════════════════════════════════════════════
# classify_hunks
# ═══════════════════════════════════════════════════════════════════════


def classify_hunks(hunks: List[DiffHunk], config: LedgerConfig) -> List[DiffHunk]:
    """Apply Ledger field classification rules to a list of DiffHunks.

    Scans only added_lines.  Returns new frozen DiffHunk instances with
    classifications populated.  Sync — CPU-bound regex matching.
    """
    if not hunks:
        return []

    # Pre-compile all regex patterns; raise on invalid
    compiled: List[Tuple[re.Pattern, ClassificationLabel]] = []
    for rule in config.rules:
        try:
            pat = re.compile(rule.pattern)
        except re.error as exc:
            raise ValueError(
                f"Ledger config contains invalid regex pattern: {rule.pattern}"
            ) from exc
        compiled.append((pat, rule.label))

    result: List[DiffHunk] = []
    for hunk in hunks:
        labels_seen: set = set()
        for line in hunk.added_lines:
            for pat, label in compiled:
                if pat.search(line) and label not in labels_seen:
                    labels_seen.add(label)
        classifications = sorted(labels_seen, key=lambda l: l.value)
        # Build a new hunk with classifications set
        result.append(DiffHunk(
            id=hunk.id,
            file_path=hunk.file_path,
            start_line_old=hunk.start_line_old,
            count_old=hunk.count_old,
            start_line_new=hunk.start_line_new,
            count_new=hunk.count_new,
            context_before=hunk.context_before,
            added_lines=hunk.added_lines,
            removed_lines=hunk.removed_lines,
            context_after=hunk.context_after,
            raw_header=hunk.raw_header,
            metadata=hunk.metadata,
            classifications=classifications,
            language=hunk.language,
        ))
    return result


# ═══════════════════════════════════════════════════════════════════════
# run_intake  (top-level orchestrator)
# ═══════════════════════════════════════════════════════════════════════


async def _safe_emit(emitter: Optional[Any], event: ChroniclerEvent, warnings: List[str]) -> None:
    """Fire-and-forget event emission — failures become warnings."""
    if emitter is None:
        return
    try:
        await emitter.emit(event)
    except Exception as exc:
        warnings.append(f"EventEmitter failure: {exc}")


async def run_intake(
    source: Any,
    config: LedgerConfig,
    emitter: Any = None,
) -> IntakeResult:
    """Top-level async orchestrator.

    Reads diff text from source, parses, classifies, assembles ReviewRequest.
    Emits three Chronicler events (started, parsed, classified).
    """
    warnings: List[str] = []
    all_errors: List[IntakeError] = []
    request_id = generate_request_id()
    now_iso = datetime.now(timezone.utc).isoformat()

    source_label = "stdin"
    if hasattr(source, "kind"):
        source_label = source.kind.value if hasattr(source.kind, "value") else str(source.kind)

    # Event: intake started
    await _safe_emit(emitter, ChroniclerEvent(
        event_id=uuid.uuid4().hex,
        event_type="review.intake.started",
        review_request_id=request_id,
        timestamp=now_iso,
        message="Intake started",
    ), warnings)

    # Phase 1: read
    raw = ""
    try:
        raw = await source.read()
    except Exception as exc:
        all_errors.append(IntakeError(
            line_number=None,
            message=f"Failed to read diff from source: {exc}",
            raw_content=None,
            phase=IntakePhase.read,
        ))
        return IntakeResult(
            review_request=ReviewRequest(
                id=request_id,
                source=source_label,
                hunks=[],
                file_paths=[],
                created_at=now_iso,
                metadata={},
            ),
            errors=all_errors,
            warnings=warnings,
            hunk_count=0,
            classified_hunk_count=0,
        )

    # Phase 2: parse
    hunks, parse_errors = await parse_diff(raw)
    all_errors.extend(parse_errors)

    # Event: parsed
    await _safe_emit(emitter, ChroniclerEvent(
        event_id=uuid.uuid4().hex,
        event_type="review.intake.parsed",
        review_request_id=request_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        message=f"Parsed {len(hunks)} hunks with {len(parse_errors)} errors",
        payload={"hunk_count": str(len(hunks)), "error_count": str(len(parse_errors))},
    ), warnings)

    # Phase 3: classify
    classified_hunks: List[DiffHunk] = []
    try:
        classified_hunks = classify_hunks(hunks, config)
    except ValueError as exc:
        all_errors.append(IntakeError(
            line_number=None,
            message=f"Classification failed: invalid regex pattern in Ledger config.",
            raw_content=None,
            phase=IntakePhase.classify,
        ))
        classified_hunks = hunks  # Fall back to unclassified

    # Event: classified
    await _safe_emit(emitter, ChroniclerEvent(
        event_id=uuid.uuid4().hex,
        event_type="review.intake.classified",
        review_request_id=request_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        message=f"Classified {len(classified_hunks)} hunks",
        payload={"classified_count": str(len(classified_hunks))},
    ), warnings)

    # Assemble ReviewRequest
    file_paths = list(dict.fromkeys(h.file_path for h in classified_hunks))
    classified_count = sum(1 for h in classified_hunks if h.classifications)

    rr = ReviewRequest(
        id=request_id,
        source=source_label,
        hunks=classified_hunks,
        file_paths=file_paths,
        created_at=now_iso,
        metadata={},
    )

    return IntakeResult(
        review_request=rr,
        errors=all_errors,
        warnings=warnings,
        hunk_count=len(classified_hunks),
        classified_hunk_count=classified_count,
    )


# ═══════════════════════════════════════════════════════════════════════
# Emission-compliant class wrapper
# ═══════════════════════════════════════════════════════════════════════

PACT_COMPONENT = "intake"


def _emit(handler: Any, event: str, pact_key: str, **kwargs: Any) -> None:
    if handler is None:
        return
    try:
        handler({"event": event, "pact_key": pact_key, **kwargs})
    except Exception:
        pass


class Intake:
    """Class wrapper around intake functions for PACT emission compliance."""

    def __init__(self, event_handler: Any = None) -> None:
        self._handler = event_handler

    def parse_diff(self, raw: Optional[str] = None) -> Any:
        pact_key = f"PACT:{PACT_COMPONENT}:parse_diff"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if raw is None:
                raise TypeError("raw is required")
            import asyncio
            result = asyncio.get_event_loop().run_until_complete(parse_diff(raw))
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def classify_hunks(self, hunks: Optional[List[DiffHunk]] = None, config: Optional[LedgerConfig] = None) -> Any:
        pact_key = f"PACT:{PACT_COMPONENT}:classify_hunks"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if hunks is None or config is None:
                raise TypeError("hunks and config are required")
            result = classify_hunks(hunks, config)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def run_intake(self, source: Any = None, config: Optional[LedgerConfig] = None, emitter: Any = None) -> Any:
        pact_key = f"PACT:{PACT_COMPONENT}:run_intake"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if source is None or config is None:
                raise TypeError("source and config are required")
            import asyncio
            result = asyncio.get_event_loop().run_until_complete(run_intake(source, config, emitter))
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def generate_hunk_id(self, file_path: Optional[str] = None, raw_header: str = "", added_lines: Optional[List[str]] = None) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:generate_hunk_id"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if file_path is None:
                raise TypeError("file_path is required")
            result = generate_hunk_id(file_path, raw_header, added_lines or [])
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def generate_request_id(self) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:generate_request_id"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = generate_request_id()
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def detect_language(self, file_path: Optional[str] = None) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:detect_language"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if file_path is None:
                raise TypeError("file_path is required")
            result = detect_language(file_path)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise
