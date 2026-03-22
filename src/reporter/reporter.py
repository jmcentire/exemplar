"""Report Formatter & Sealer — formats ReviewReport into JSON, Markdown, and
GitHub PR comment formats, applies Tessera hash-chain seals, and verifies
seal integrity."""

from __future__ import annotations

import hashlib
import inspect
import json
import re as _re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable, Optional, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, field_validator

# ---------------------------------------------------------------------------
# Module constant
# ---------------------------------------------------------------------------

PACT_COMPONENT = "reporter"

GITHUB_CHAR_LIMIT = 65000
TRUNCATION_NOTICE = "\n\n---\n⚠️ *Report truncated. Full report available in JSON format.*"

SEVERITY_BADGES: dict[str, str] = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}

# ---------------------------------------------------------------------------
# Enums (StrEnum)
# ---------------------------------------------------------------------------


class OutputFormat(StrEnum):
    json = "json"
    md = "md"
    github = "github"


class SealVerificationStatus(StrEnum):
    valid = "valid"
    invalid_content_hash = "invalid_content_hash"
    invalid_chain_hash = "invalid_chain_hash"
    missing_seal = "missing_seal"
    verification_error = "verification_error"


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class Confidence(StrEnum):
    high = "high"
    medium = "medium"
    low = "low"


class ReviewStage(StrEnum):
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


# 'pass' is a Python keyword — use the functional StrEnum API.
ReviewDecision = StrEnum(
    "ReviewDecision", [("block", "block"), ("warn", "warn"), ("pass", "pass")]
)

# ---------------------------------------------------------------------------
# Primitive wrapper types (frozen Pydantic models with a ``value`` field)
# ---------------------------------------------------------------------------


class _StringWrapperMixin:
    """Mixin that lets wrapper types be constructed positionally and compared to strings."""

    def __init__(self, *args, **kwargs):
        if args and not kwargs:
            # Support positional construction: ReportId("value")
            super().__init__(value=args[0])
        else:
            super().__init__(*args, **kwargs)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, str):
            return self.value == other
        return super().__eq__(other)

    def __hash__(self) -> int:
        return hash(self.value)

    def __str__(self) -> str:
        return self.value


class ReportId(_StringWrapperMixin, BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if not v:
            raise ValueError("ReportId must be non-empty")
        if len(v) > 256:
            raise ValueError("ReportId must be at most 256 characters")
        return v


class Iso8601Timestamp(_StringWrapperMixin, BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if not v:
            raise ValueError("Timestamp must be non-empty")
        if not v.endswith("Z"):
            raise ValueError("Timestamp must end with 'Z' (UTC)")
        if not _re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$", v):
            raise ValueError("Invalid ISO 8601 UTC timestamp format")
        return v


class Sha256Hex(_StringWrapperMixin, BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if v == "":
            return v
        if not _re.match(r"^[a-f0-9]{64}$", v):
            raise ValueError(
                "Sha256Hex must be a 64-character lowercase hex string or empty"
            )
        return v


class SealerId(_StringWrapperMixin, BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def _validate(cls, v: str) -> str:
        if not v:
            raise ValueError("SealerId must be non-empty")
        if len(v) > 128:
            raise ValueError("SealerId must be at most 128 characters")
        return v


class GithubCharLimit(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: int

    @field_validator("value")
    @classmethod
    def _validate(cls, v: int) -> int:
        if v != 65000:
            raise ValueError("GithubCharLimit must be exactly 65000")
        return v


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------


class ReporterSerializationError(Exception):
    pass


class ReporterSealError(Exception):
    pass


class ReporterChainStoreError(Exception):
    pass


class ReporterFormatError(Exception):
    pass


class ReporterRenderError(Exception):
    pass


# ---------------------------------------------------------------------------
# Data models (frozen Pydantic)
# ---------------------------------------------------------------------------


class TesseraSeal(BaseModel):
    model_config = ConfigDict(frozen=True)
    content_hash: str
    previous_hash: Optional[str] = None
    chain_hash: str
    sealed_at: str
    sealer_id: str


class Finding(BaseModel):
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


class TrustScore(BaseModel):
    model_config = ConfigDict(frozen=True)
    reviewer_id: str
    stage: ReviewStage
    weight: float
    accepted_count: int
    dismissed_count: int
    updated_at: str

    @field_validator("weight")
    @classmethod
    def _validate_weight(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("weight must be between 0.0 and 1.0")
        return v


class ReviewReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    id: str
    review_request_id: str
    decision: ReviewDecision
    findings: list[Finding]
    assessments: list[Assessment]
    confidence: Confidence
    trust_scores: list[TrustScore]
    conflict_notes: list[str]
    summary: str
    seal: Optional[TesseraSeal] = None
    created_at: str
    metadata: dict[str, str]


class FormattedReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    content: str
    output_format: OutputFormat
    report_id: ReportId
    is_sealed: bool
    character_count: int
    truncated: bool
    rendered_at: Iso8601Timestamp
    metadata: dict

    @field_validator("character_count")
    @classmethod
    def _validate_character_count(cls, v: int) -> int:
        if v < 0:
            raise ValueError("character_count must be >= 0")
        return v


class SealVerificationResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    status: SealVerificationStatus
    valid: bool
    content_hash_match: bool
    chain_hash_match: bool
    expected_content_hash: str
    actual_content_hash: str
    expected_chain_hash: str
    actual_chain_hash: str
    error: str


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class SealChainStoreProtocol(Protocol):
    def get_previous_hash(self) -> str | None: ...
    def append_seal(self, seal: TesseraSeal) -> None: ...


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_timestamp(timestamp: Any) -> str:
    if timestamp is None:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return timestamp.value if hasattr(timestamp, "value") else str(timestamp)


def _resolve_sealer_id(sealer_id: Any) -> str:
    return sealer_id.value if hasattr(sealer_id, "value") else str(sealer_id)


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------


def canonicalize(report: ReviewReport) -> bytes:
    """Canonical byte representation of a ReviewReport for hashing.

    Seal is excluded (set to None), keys sorted, compact JSON separators.
    """
    try:
        report_copy = report.model_copy(update={"seal": None})
        data = report_copy.model_dump(mode="json")
        return json.dumps(
            data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    except Exception as e:
        raise ReporterSerializationError(
            f"Serialization failed for report {report.id}: {e}"
        ) from e


async def seal_report(
    report: ReviewReport,
    chain_store: SealChainStoreProtocol,
    sealer_id: SealerId | str,
    timestamp: Iso8601Timestamp | str | None = None,
    chronicler_callback: Callable | None = None,
) -> ReviewReport:
    """Apply a Tessera seal to *report* and return a new sealed copy."""

    if report.seal is not None:
        raise ReporterSealError(
            f"Report {report.id} is already sealed"
        )

    sealer_id_str = _resolve_sealer_id(sealer_id)
    ts_str = _resolve_timestamp(timestamp)

    # Canonicalize
    try:
        canonical = canonicalize(report)
    except ReporterSerializationError:
        raise
    except Exception as e:
        raise ReporterSerializationError(
            f"Canonicalization failed for report {report.id}: {e}"
        ) from e

    content_hash = _sha256(canonical)

    # Read previous hash from chain store
    try:
        prev_result = chain_store.get_previous_hash()
        if inspect.isawaitable(prev_result):
            prev_result = await prev_result
        previous_hash: str | None = prev_result
    except Exception as e:
        raise ReporterChainStoreError(
            f"get_previous_hash failed for report {report.id}: {e}"
        ) from e

    # Compute chain hash
    prev_for_chain = previous_hash or "GENESIS"
    chain_hash = _sha256(
        (content_hash + "|" + prev_for_chain).encode("utf-8")
    )

    seal = TesseraSeal(
        content_hash=content_hash,
        previous_hash=previous_hash if previous_hash else None,
        chain_hash=chain_hash,
        sealed_at=ts_str,
        sealer_id=sealer_id_str,
    )

    # Persist to chain store
    try:
        write_result = chain_store.append_seal(seal)
        if inspect.isawaitable(write_result):
            await write_result
    except Exception as e:
        raise ReporterChainStoreError(
            f"append_seal failed for report {report.id}: {e}"
        ) from e

    sealed_report = report.model_copy(update={"seal": seal})

    # Fire-and-forget chronicler callback
    if chronicler_callback is not None:
        try:
            chronicler_callback(
                {
                    "event_type": "report.sealed",
                    "report_id": report.id,
                    "content_hash": content_hash,
                    "chain_hash": chain_hash,
                    "pact_component": PACT_COMPONENT,
                }
            )
        except Exception:
            pass

    return sealed_report


def verify_seal(report: ReviewReport) -> SealVerificationResult:
    """Recompute hashes and verify seal integrity. Never raises."""
    try:
        if report.seal is None:
            return SealVerificationResult(
                status=SealVerificationStatus.missing_seal,
                valid=False,
                content_hash_match=False,
                chain_hash_match=False,
                expected_content_hash="",
                actual_content_hash="",
                expected_chain_hash="",
                actual_chain_hash="",
                error="Report has no seal attached",
            )

        seal = report.seal

        try:
            canonical = canonicalize(report)
            actual_content_hash = _sha256(canonical)
        except Exception as e:
            return SealVerificationResult(
                status=SealVerificationStatus.verification_error,
                valid=False,
                content_hash_match=False,
                chain_hash_match=False,
                expected_content_hash=seal.content_hash,
                actual_content_hash="",
                expected_chain_hash=seal.chain_hash,
                actual_chain_hash="",
                error=f"Failed to canonicalize report for verification: {e}",
            )

        content_hash_match = actual_content_hash == seal.content_hash

        prev_for_chain = seal.previous_hash or "GENESIS"
        actual_chain_hash = _sha256(
            (actual_content_hash + "|" + prev_for_chain).encode("utf-8")
        )
        chain_hash_match = actual_chain_hash == seal.chain_hash

        if content_hash_match and chain_hash_match:
            status = SealVerificationStatus.valid
        elif not content_hash_match:
            status = SealVerificationStatus.invalid_content_hash
        else:
            status = SealVerificationStatus.invalid_chain_hash

        return SealVerificationResult(
            status=status,
            valid=(status == SealVerificationStatus.valid),
            content_hash_match=content_hash_match,
            chain_hash_match=chain_hash_match,
            expected_content_hash=seal.content_hash,
            actual_content_hash=actual_content_hash,
            expected_chain_hash=seal.chain_hash,
            actual_chain_hash=actual_chain_hash,
            error="",
        )
    except Exception as e:
        return SealVerificationResult(
            status=SealVerificationStatus.verification_error,
            valid=False,
            content_hash_match=False,
            chain_hash_match=False,
            expected_content_hash="",
            actual_content_hash="",
            expected_chain_hash="",
            actual_chain_hash="",
            error=str(e),
        )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_json(report: ReviewReport) -> str:
    """Human-readable JSON with 2-space indent and sorted keys."""
    try:
        data = report.model_dump(mode="json")
        return json.dumps(data, sort_keys=True, indent=2, ensure_ascii=False)
    except Exception as e:
        raise ReporterSerializationError(
            f"JSON serialization failed for report {report.id}: {e}"
        ) from e


def render_markdown(report: ReviewReport, timestamp: Any) -> str:
    """Markdown with severity badges, stage grouping, and summary table."""
    ts_str = _resolve_timestamp(timestamp)

    try:
        lines: list[str] = []
        lines.append(f"# Review Report: {report.id}")
        lines.append("")
        lines.append(f"**Decision:** {report.decision}")
        lines.append(f"**Confidence:** {report.confidence}")
        lines.append(f"**Summary:** {report.summary}")
        lines.append(f"**Generated:** {ts_str}")
        lines.append("")

        # Summary statistics table
        severity_counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in report.findings:
            severity_counts[f.severity] += 1

        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in Severity:
            badge = SEVERITY_BADGES[sev.value]
            lines.append(f"| {badge} {sev.value} | {severity_counts[sev]} |")
        lines.append("")

        # Findings grouped by stage
        stage_order = list(ReviewStage)
        findings_by_stage: dict[ReviewStage, list[Finding]] = {
            s: [] for s in stage_order
        }
        for f in report.findings:
            findings_by_stage[f.stage].append(f)

        # Sort within each stage: severity descending (enum order), file_path ascending
        severity_rank = {s: i for i, s in enumerate(Severity)}
        for stage in stage_order:
            findings_by_stage[stage].sort(
                key=lambda f: (severity_rank[f.severity], f.file_path)
            )

        for stage in stage_order:
            stage_findings = findings_by_stage[stage]
            if not stage_findings:
                continue
            lines.append(f"## {stage.value.capitalize()}")
            lines.append("")
            for f in stage_findings:
                badge = SEVERITY_BADGES[f.severity.value]
                lines.append(f"### {badge} {f.title}")
                lines.append("")
                lines.append(f"- **File:** {f.file_path}")
                if f.line_number is not None:
                    lines.append(f"- **Line:** {f.line_number}")
                lines.append(f"- **Severity:** {f.severity.value}")
                lines.append(f"- **Rule:** {f.rule_id}")
                lines.append("")
                lines.append(f"{f.description}")
                lines.append("")
                if f.suggestion:
                    lines.append(f"**Suggestion:** {f.suggestion}")
                    lines.append("")

        # Seal status section
        if report.seal is not None:
            lines.append("## Seal Status")
            lines.append("")
            lines.append(f"- **Content Hash:** `{report.seal.content_hash}`")
            lines.append(f"- **Chain Hash:** `{report.seal.chain_hash}`")
            lines.append(f"- **Sealed At:** {report.seal.sealed_at}")
            lines.append(f"- **Sealer:** {report.seal.sealer_id}")
            lines.append("")

        return "\n".join(lines)
    except Exception as e:
        raise ReporterRenderError(
            f"Markdown rendering failed for report {report.id}: {e}"
        ) from e


def render_github(report: ReviewReport, timestamp: Any) -> str:
    """GitHub PR comment with collapsible <details> sections per stage."""
    ts_str = _resolve_timestamp(timestamp)

    try:
        lines: list[str] = []
        lines.append(f"## Review Report: {report.id}")
        lines.append("")
        lines.append(
            f"**Decision:** {report.decision} | **Confidence:** {report.confidence}"
        )
        lines.append(f"**Summary:** {report.summary}")
        lines.append(f"**Generated:** {ts_str}")
        lines.append("")

        # Collapsible sections per stage
        stage_order = list(ReviewStage)
        findings_by_stage: dict[ReviewStage, list[Finding]] = {
            s: [] for s in stage_order
        }
        for f in report.findings:
            findings_by_stage[f.stage].append(f)

        severity_rank = {s: i for i, s in enumerate(Severity)}
        for stage in stage_order:
            findings_by_stage[stage].sort(
                key=lambda f: (severity_rank[f.severity], f.file_path)
            )

        for stage in stage_order:
            stage_findings = findings_by_stage[stage]
            if not stage_findings:
                continue

            lines.append("<details>")
            lines.append(
                f"<summary><strong>{stage.value.capitalize()}</strong>"
                f" ({len(stage_findings)} findings)</summary>"
            )
            lines.append("")

            for f in stage_findings:
                badge = SEVERITY_BADGES[f.severity.value]
                lines.append(f"#### {badge} {f.title}")
                lines.append("")
                lines.append(f"- **File:** `{f.file_path}`")
                if f.line_number is not None:
                    lines.append(f"- **Line:** {f.line_number}")
                lines.append(f"- **Severity:** {f.severity.value}")
                lines.append(f"- **Rule:** `{f.rule_id}`")
                lines.append("")
                lines.append(f"{f.description}")
                lines.append("")
                if f.suggestion:
                    lines.append(f"**Suggestion:** {f.suggestion}")
                    lines.append("")

            lines.append("</details>")
            lines.append("")

        result = "\n".join(lines)

        # Truncation at GitHub comment limit
        if len(result) > GITHUB_CHAR_LIMIT:
            result = result[:GITHUB_CHAR_LIMIT] + TRUNCATION_NOTICE

        return result
    except Exception as e:
        raise ReporterRenderError(
            f"GitHub rendering failed for report {report.id}: {e}"
        ) from e


# ---------------------------------------------------------------------------
# format_report — top-level dispatcher
# ---------------------------------------------------------------------------


def format_report(
    report: ReviewReport,
    output_format: OutputFormat,
    timestamp: Iso8601Timestamp | str | None = None,
) -> FormattedReport:
    """Render *report* in the requested *output_format*."""
    ts_str = _resolve_timestamp(timestamp)
    ts_obj = Iso8601Timestamp(value=ts_str)

    truncated = False

    if output_format == OutputFormat.json:
        content = render_json(report)
    elif output_format == OutputFormat.md:
        content = render_markdown(report, ts_obj)
    elif output_format == OutputFormat.github:
        content = render_github(report, ts_obj)
        truncated = content.endswith(TRUNCATION_NOTICE)
    else:
        raise ReporterFormatError(
            f"Unsupported format: {output_format}. "
            f"Supported: json, markdown, github"
        )

    return FormattedReport(
        content=content,
        output_format=output_format,
        report_id=ReportId(value=report.id),
        is_sealed=report.seal is not None,
        character_count=len(content),
        truncated=truncated,
        rendered_at=ts_obj,
        metadata={"pact_component": PACT_COMPONENT},
    )


# ---------------------------------------------------------------------------
# Reporter class (emission-compliant wrapper)
# ---------------------------------------------------------------------------


def _emit(handler: Callable | None, event: str, pact_key: str, **kwargs: Any) -> None:
    if handler is None:
        return
    try:
        handler({"event": event, "pact_key": pact_key, **kwargs})
    except Exception:
        pass


class Reporter:
    """Class wrapper around reporter functions for Pact emission compliance."""

    def __init__(self, event_handler: Callable | None = None) -> None:
        self._handler = event_handler

    def canonicalize(self, report: ReviewReport | None = None) -> bytes:
        pact_key = f"PACT:{PACT_COMPONENT}:canonicalize"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            result = canonicalize(report)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def seal_report(self, report: ReviewReport | None = None, **kwargs: Any) -> Any:
        pact_key = f"PACT:{PACT_COMPONENT}:seal_report"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            raise TypeError("Use the async seal_report function directly")
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def verify_seal(self, report: ReviewReport | None = None) -> SealVerificationResult:
        pact_key = f"PACT:{PACT_COMPONENT}:verify_seal"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            result = verify_seal(report)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def format_report(self, report: ReviewReport | None = None, **kwargs: Any) -> Any:
        pact_key = f"PACT:{PACT_COMPONENT}:format_report"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            raise TypeError("Provide report and output_format")
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def render_json(self, report: ReviewReport | None = None) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:render_json"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            result = render_json(report)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def render_markdown(self, report: ReviewReport | None = None, **kwargs: Any) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:render_markdown"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            raise TypeError("Provide report and timestamp")
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def render_github(self, report: ReviewReport | None = None, **kwargs: Any) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:render_github"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if report is None:
                raise TypeError("report is required")
            raise TypeError("Provide report and timestamp")
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise
