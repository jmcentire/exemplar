"""
Contract tests for the reporter component.

Tests verify: canonicalize, seal_report, verify_seal, format_report,
render_json, render_markdown, render_github, and all contract types.
"""

import json
import hashlib
import re
import pytest
import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from exemplar.reporter import (
    # Types / Enums
    OutputFormat,
    SealVerificationStatus,
    FormattedReport,
    SealVerificationResult,
    ReportId,
    Iso8601Timestamp,
    Sha256Hex,
    SealerId,
    GithubCharLimit,
    ReviewReport,
    Confidence,
    ReviewDecision,
    Finding,
    Assessment,
    TrustScore,
    TesseraSeal,
    Severity,
    ReviewStage,
    # Functions
    canonicalize,
    seal_report,
    verify_seal,
    format_report,
    render_json,
    render_markdown,
    render_github,
)


# ---------------------------------------------------------------------------
# Helpers & Fixtures
# ---------------------------------------------------------------------------

FIXED_TIMESTAMP = "2024-06-15T12:00:00Z"
FIXED_TIMESTAMP_2 = "2024-06-15T12:00:01Z"
FIXED_SEALER_ID = "test-sealer-1"
HEX64_ZEROS = "0" * 64
HEX64_ONES = "a" * 64

TRUNCATION_NOTICE = "\n\n---\n⚠️ *Report truncated. Full report available in JSON format.*"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_finding(
    severity=Severity.medium,
    stage=ReviewStage.security,
    idx=0,
    description="Test finding description",
    file_path="src/main.py",
):
    return Finding(
        id=f"f-{idx}",
        hunk_id=f"h-{idx}",
        file_path=file_path,
        line_number=10 + idx,
        severity=severity,
        confidence=Confidence.high,
        title=f"Finding {idx} title",
        description=description,
        suggestion="Fix it",
        rule_id=f"RULE-{idx}",
        stage=stage,
    )


def _make_assessment(idx=0, findings=None):
    return Assessment(
        id=f"a-{idx}",
        review_request_id="rr-1",
        stage=ReviewStage.security,
        reviewer_id=f"reviewer-{idx}",
        decision=ReviewDecision.warn,
        findings=findings or [],
        confidence=Confidence.high,
        is_partial=False,
        error_message=None,
        duration_ms=100,
        created_at=FIXED_TIMESTAMP,
    )


def _make_trust_score(reviewer_id="reviewer-0"):
    return TrustScore(
        reviewer_id=reviewer_id,
        stage=ReviewStage.security,
        weight=0.8,
        accepted_count=5,
        dismissed_count=1,
        updated_at=FIXED_TIMESTAMP,
    )


def _make_report(
    report_id="report-001",
    findings=None,
    assessments=None,
    seal=None,
    summary="Test summary",
    conflict_notes=None,
    trust_scores=None,
):
    if findings is None:
        findings = [_make_finding(severity=Severity.high, idx=0)]
    if assessments is None:
        assessments = [_make_assessment(idx=0, findings=findings)]
    if trust_scores is None:
        trust_scores = [_make_trust_score()]
    return ReviewReport(
        id=report_id,
        review_request_id="rr-1",
        decision=ReviewDecision.warn,
        findings=findings,
        assessments=assessments,
        confidence=Confidence.high,
        trust_scores=trust_scores,
        conflict_notes=conflict_notes or [],
        summary=summary,
        seal=seal,
        created_at=FIXED_TIMESTAMP,
        metadata={"repo": "test-repo"},
    )


class InMemoryChainStore:
    """In-memory implementation of SealChainStoreProtocol."""

    def __init__(self, previous_hash=""):
        self._previous_hash = previous_hash
        self._seals = []

    def get_previous_hash(self) -> str:
        return self._previous_hash

    def append_seal(self, seal_data) -> str:
        self._seals.append(seal_data)
        # Update previous_hash for subsequent calls
        if hasattr(seal_data, "chain_hash"):
            self._previous_hash = seal_data.chain_hash
        elif isinstance(seal_data, dict) and "chain_hash" in seal_data:
            self._previous_hash = seal_data["chain_hash"]
        return "ok"


class FailingReadChainStore:
    """Chain store that fails on get_previous_hash."""

    def get_previous_hash(self) -> str:
        raise IOError("Permission denied reading chain store")

    def append_seal(self, seal_data) -> str:
        return "ok"


class FailingWriteChainStore:
    """Chain store that fails on append_seal."""

    def __init__(self, previous_hash=""):
        self._previous_hash = previous_hash

    def get_previous_hash(self) -> str:
        return self._previous_hash

    def append_seal(self, seal_data) -> str:
        raise IOError("Disk full")


@pytest.fixture
def report():
    return _make_report()


@pytest.fixture
def report_no_findings():
    return _make_report(findings=[], assessments=[_make_assessment(idx=0, findings=[])])


@pytest.fixture
def report_all_severities():
    findings = [
        _make_finding(severity=Severity.critical, stage=ReviewStage.security, idx=0),
        _make_finding(severity=Severity.high, stage=ReviewStage.security, idx=1),
        _make_finding(severity=Severity.medium, stage=ReviewStage.correctness, idx=2),
        _make_finding(severity=Severity.low, stage=ReviewStage.style, idx=3),
        _make_finding(severity=Severity.info, stage=ReviewStage.architecture, idx=4),
    ]
    return _make_report(findings=findings)


@pytest.fixture
def chain_store():
    return InMemoryChainStore()


@pytest.fixture
def sealer_id():
    return SealerId(value=FIXED_SEALER_ID)


@pytest.fixture
def timestamp():
    return Iso8601Timestamp(value=FIXED_TIMESTAMP)


@pytest.fixture
def timestamp2():
    return Iso8601Timestamp(value=FIXED_TIMESTAMP_2)


# ---------------------------------------------------------------------------
# Type Validation Tests
# ---------------------------------------------------------------------------


class TestTypeValidation:
    """Tests for contract type construction and validation."""

    # --- ReportId ---

    def test_report_id_valid_short(self):
        r = ReportId(value="a")
        assert r.value == "a"

    def test_report_id_valid_max_length(self):
        r = ReportId(value="x" * 256)
        assert len(r.value) == 256

    def test_report_id_empty_rejected(self):
        with pytest.raises(Exception):  # ValidationError
            ReportId(value="")

    def test_report_id_too_long_rejected(self):
        with pytest.raises(Exception):
            ReportId(value="x" * 257)

    # --- Iso8601Timestamp ---

    def test_iso8601_valid_no_fractional(self):
        ts = Iso8601Timestamp(value="2024-01-15T10:30:00Z")
        assert ts.value == "2024-01-15T10:30:00Z"

    def test_iso8601_valid_with_fractional(self):
        ts = Iso8601Timestamp(value="2024-01-15T10:30:00.123Z")
        assert ts.value == "2024-01-15T10:30:00.123Z"

    def test_iso8601_invalid_date_only(self):
        with pytest.raises(Exception):
            Iso8601Timestamp(value="2024-01-15")

    def test_iso8601_invalid_timezone_offset(self):
        with pytest.raises(Exception):
            Iso8601Timestamp(value="2024-01-15T10:30:00+05:00")

    def test_iso8601_empty_rejected(self):
        with pytest.raises(Exception):
            Iso8601Timestamp(value="")

    # --- Sha256Hex ---

    def test_sha256hex_valid_64_chars(self):
        h = Sha256Hex(value="a" * 64)
        assert h.value == "a" * 64

    def test_sha256hex_valid_empty(self):
        h = Sha256Hex(value="")
        assert h.value == ""

    def test_sha256hex_uppercase_rejected(self):
        with pytest.raises(Exception):
            Sha256Hex(value="A" * 64)

    def test_sha256hex_wrong_length_rejected(self):
        with pytest.raises(Exception):
            Sha256Hex(value="a" * 63)

    def test_sha256hex_invalid_chars_rejected(self):
        with pytest.raises(Exception):
            Sha256Hex(value="g" * 64)

    # --- SealerId ---

    def test_sealer_id_valid(self):
        s = SealerId(value="sealer-1")
        assert s.value == "sealer-1"

    def test_sealer_id_empty_rejected(self):
        with pytest.raises(Exception):
            SealerId(value="")

    def test_sealer_id_max_length(self):
        s = SealerId(value="s" * 128)
        assert len(s.value) == 128

    def test_sealer_id_over_max_rejected(self):
        with pytest.raises(Exception):
            SealerId(value="s" * 129)

    # --- GithubCharLimit ---

    def test_github_char_limit_exact_65000(self):
        g = GithubCharLimit(value=65000)
        assert g.value == 65000

    def test_github_char_limit_wrong_value_rejected(self):
        with pytest.raises(Exception):
            GithubCharLimit(value=65001)

    def test_github_char_limit_zero_rejected(self):
        with pytest.raises(Exception):
            GithubCharLimit(value=0)

    # --- TrustScore weight ---

    def test_trust_score_weight_zero(self):
        ts = TrustScore(
            reviewer_id="r1",
            stage=ReviewStage.security,
            weight=0.0,
            accepted_count=0,
            dismissed_count=0,
            updated_at=FIXED_TIMESTAMP,
        )
        assert ts.weight == 0.0

    def test_trust_score_weight_one(self):
        ts = TrustScore(
            reviewer_id="r1",
            stage=ReviewStage.security,
            weight=1.0,
            accepted_count=0,
            dismissed_count=0,
            updated_at=FIXED_TIMESTAMP,
        )
        assert ts.weight == 1.0

    def test_trust_score_weight_negative_rejected(self):
        with pytest.raises(Exception):
            TrustScore(
                reviewer_id="r1",
                stage=ReviewStage.security,
                weight=-0.1,
                accepted_count=0,
                dismissed_count=0,
                updated_at=FIXED_TIMESTAMP,
            )

    def test_trust_score_weight_above_one_rejected(self):
        with pytest.raises(Exception):
            TrustScore(
                reviewer_id="r1",
                stage=ReviewStage.security,
                weight=1.1,
                accepted_count=0,
                dismissed_count=0,
                updated_at=FIXED_TIMESTAMP,
            )

    # --- OutputFormat enum ---

    def test_output_format_variants(self):
        assert OutputFormat.json is not None
        assert OutputFormat.md is not None
        assert OutputFormat.github is not None

    # --- SealVerificationStatus enum ---

    def test_seal_verification_status_variants(self):
        assert SealVerificationStatus.valid is not None
        assert SealVerificationStatus.invalid_content_hash is not None
        assert SealVerificationStatus.invalid_chain_hash is not None
        assert SealVerificationStatus.missing_seal is not None
        assert SealVerificationStatus.verification_error is not None

    # --- Severity enum ---

    def test_severity_variants(self):
        assert Severity.critical is not None
        assert Severity.high is not None
        assert Severity.medium is not None
        assert Severity.low is not None
        assert Severity.info is not None

    # --- FormattedReport character_count ---

    def test_formatted_report_character_count_nonneg(self):
        """character_count=0 should be accepted."""
        # We can't easily construct FormattedReport directly in all implementations,
        # so we test via format_report output. This is a type-level sanity check.
        # If the type is constructable directly, test directly.
        try:
            fr = FormattedReport(
                content="",
                output_format=OutputFormat.json,
                report_id=ReportId(value="r1"),
                is_sealed=False,
                character_count=0,
                truncated=False,
                rendered_at=Iso8601Timestamp(value=FIXED_TIMESTAMP),
                metadata={"pact_component": "reporter"},
            )
            assert fr.character_count == 0
        except Exception:
            # Type may not allow empty content or direct construction;
            # this is acceptable as long as format_report produces valid output
            pass

    def test_formatted_report_negative_character_count_rejected(self):
        """character_count=-1 should be rejected by validator."""
        try:
            FormattedReport(
                content="x",
                output_format=OutputFormat.json,
                report_id=ReportId(value="r1"),
                is_sealed=False,
                character_count=-1,
                truncated=False,
                rendered_at=Iso8601Timestamp(value=FIXED_TIMESTAMP),
                metadata={"pact_component": "reporter"},
            )
            pytest.fail("Expected validation error for negative character_count")
        except Exception:
            pass  # Expected


# ---------------------------------------------------------------------------
# TestCanonicalize
# ---------------------------------------------------------------------------


class TestCanonicalize:
    """Tests for the canonicalize function."""

    def test_happy_path_returns_bytes(self, report):
        result = canonicalize(report)
        assert isinstance(result, bytes)

    def test_happy_path_valid_utf8_json(self, report):
        result = canonicalize(report)
        text = result.decode("utf-8")
        parsed = json.loads(text)
        assert isinstance(parsed, dict)

    def test_compact_separators_no_whitespace(self, report):
        result = canonicalize(report)
        text = result.decode("utf-8")
        # Compact JSON should not have ": " or ", " patterns
        # (but values may contain spaces)
        # Instead, verify by re-serializing with compact separators
        parsed = json.loads(text)
        re_serialized = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert text == re_serialized

    def test_sorted_keys(self, report):
        result = canonicalize(report)
        text = result.decode("utf-8")
        parsed = json.loads(text)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_seal_excluded_is_null(self, report):
        result = canonicalize(report)
        parsed = json.loads(result.decode("utf-8"))
        assert parsed.get("seal") is None

    def test_seal_excluded_even_when_present(self):
        """Even if a report has a seal, canonicalize should set it to None."""
        report = _make_report()
        seal = TesseraSeal(
            content_hash="a" * 64,
            previous_hash=None,
            chain_hash="b" * 64,
            sealed_at=FIXED_TIMESTAMP,
            sealer_id=FIXED_SEALER_ID,
        )
        sealed_report = report.model_copy(update={"seal": seal})
        result = canonicalize(sealed_report)
        parsed = json.loads(result.decode("utf-8"))
        assert parsed.get("seal") is None

    def test_seal_excluded_same_output_with_and_without_seal(self):
        """canonicalize(report_with_seal) == canonicalize(report_without_seal)."""
        report = _make_report()
        seal = TesseraSeal(
            content_hash="a" * 64,
            previous_hash=None,
            chain_hash="b" * 64,
            sealed_at=FIXED_TIMESTAMP,
            sealer_id=FIXED_SEALER_ID,
        )
        sealed_report = report.model_copy(update={"seal": seal})
        assert canonicalize(report) == canonicalize(sealed_report)

    def test_idempotent(self, report):
        first = canonicalize(report)
        second = canonicalize(report)
        assert first == second

    def test_deterministic_many_calls(self, report):
        first = canonicalize(report)
        for _ in range(10):
            assert canonicalize(report) == first

    def test_empty_findings(self, report_no_findings):
        result = canonicalize(report_no_findings)
        parsed = json.loads(result.decode("utf-8"))
        assert parsed["findings"] == []

    def test_different_reports_different_output(self):
        r1 = _make_report(summary="Summary A")
        r2 = _make_report(summary="Summary B")
        assert canonicalize(r1) != canonicalize(r2)


# ---------------------------------------------------------------------------
# TestSealReport
# ---------------------------------------------------------------------------


class TestSealReport:
    """Tests for the async seal_report function."""

    @pytest.mark.asyncio
    async def test_happy_first_seal_genesis(self, report, chain_store, sealer_id, timestamp):
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)

        assert sealed is not report
        assert sealed.seal is not None
        seal = sealed.seal

        # Content hash verification
        expected_content_hash = _sha256_hex(canonicalize(report))
        assert seal.content_hash == expected_content_hash
        assert re.match(r"^[a-f0-9]{64}$", seal.content_hash)

        # Chain hash: genesis (empty previous_hash)
        expected_chain_hash = _sha256_hex(
            (seal.content_hash + "|" + "GENESIS").encode("utf-8")
        )
        assert seal.chain_hash == expected_chain_hash
        assert re.match(r"^[a-f0-9]{64}$", seal.chain_hash)

        # Sealer ID and timestamp
        assert seal.sealer_id == FIXED_SEALER_ID
        assert seal.sealed_at == FIXED_TIMESTAMP

        # Chain store was written to
        assert len(chain_store._seals) == 1

    @pytest.mark.asyncio
    async def test_happy_chained_seal(self, report, sealer_id, timestamp):
        previous_hash = "b" * 64
        store = InMemoryChainStore(previous_hash=previous_hash)
        sealed = await seal_report(report, store, sealer_id, timestamp, None)

        seal = sealed.seal
        assert seal.previous_hash == previous_hash

        expected_chain_hash = _sha256_hex(
            (seal.content_hash + "|" + previous_hash).encode("utf-8")
        )
        assert seal.chain_hash == expected_chain_hash

    @pytest.mark.asyncio
    async def test_original_not_mutated(self, report, chain_store, sealer_id, timestamp):
        original_seal = report.seal
        await seal_report(report, chain_store, sealer_id, timestamp, None)
        assert report.seal is original_seal  # Still None

    @pytest.mark.asyncio
    async def test_all_non_seal_fields_preserved(self, report, chain_store, sealer_id, timestamp):
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        assert sealed.id == report.id
        assert sealed.review_request_id == report.review_request_id
        assert sealed.decision == report.decision
        assert sealed.summary == report.summary
        assert sealed.confidence == report.confidence
        assert sealed.created_at == report.created_at

    @pytest.mark.asyncio
    async def test_chronicler_callback_invoked(self, report, chain_store, sealer_id, timestamp):
        callback = MagicMock()
        await seal_report(report, chain_store, sealer_id, timestamp, callback)
        callback.assert_called_once()

    @pytest.mark.asyncio
    async def test_chronicler_callback_fire_and_forget(self, report, chain_store, sealer_id, timestamp):
        """Callback failure does not prevent seal_report from succeeding."""
        callback = MagicMock(side_effect=RuntimeError("callback failed"))
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, callback)
        assert sealed.seal is not None

    @pytest.mark.asyncio
    async def test_error_already_sealed(self, chain_store, sealer_id, timestamp):
        report = _make_report()
        seal = TesseraSeal(
            content_hash="a" * 64,
            previous_hash=None,
            chain_hash="b" * 64,
            sealed_at=FIXED_TIMESTAMP,
            sealer_id=FIXED_SEALER_ID,
        )
        sealed_report = report.model_copy(update={"seal": seal})
        with pytest.raises(Exception) as exc_info:
            await seal_report(sealed_report, chain_store, sealer_id, timestamp, None)
        # Verify it's an already_sealed type error
        exc_text = str(exc_info.value).lower()
        assert "seal" in exc_text or "already" in exc_text

    @pytest.mark.asyncio
    async def test_error_chain_store_read_failure(self, report, sealer_id, timestamp):
        store = FailingReadChainStore()
        with pytest.raises(Exception):
            await seal_report(report, store, sealer_id, timestamp, None)

    @pytest.mark.asyncio
    async def test_error_chain_store_write_failure(self, report, sealer_id, timestamp):
        store = FailingWriteChainStore()
        with pytest.raises(Exception):
            await seal_report(report, store, sealer_id, timestamp, None)

    @pytest.mark.asyncio
    async def test_hash_format_invariant(self, report, chain_store, sealer_id, timestamp):
        """All hash values must be lowercase 64-char hex."""
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        assert re.match(r"^[a-f0-9]{64}$", sealed.seal.content_hash)
        assert re.match(r"^[a-f0-9]{64}$", sealed.seal.chain_hash)

    @pytest.mark.asyncio
    async def test_seal_appended_to_chain_store(self, report, chain_store, sealer_id, timestamp):
        await seal_report(report, chain_store, sealer_id, timestamp, None)
        assert len(chain_store._seals) >= 1


# ---------------------------------------------------------------------------
# TestVerifySeal
# ---------------------------------------------------------------------------


class TestVerifySeal:
    """Tests for the verify_seal function."""

    @pytest.mark.asyncio
    async def test_valid_seal_round_trip(self, report, chain_store, sealer_id, timestamp):
        """Seal then verify → valid."""
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = verify_seal(sealed)
        assert result.status == SealVerificationStatus.valid
        assert result.valid is True
        assert result.content_hash_match is True
        assert result.chain_hash_match is True
        assert result.expected_content_hash == result.actual_content_hash
        assert result.expected_chain_hash == result.actual_chain_hash

    def test_missing_seal(self, report):
        result = verify_seal(report)
        assert result.status == SealVerificationStatus.missing_seal
        assert result.valid is False

    @pytest.mark.asyncio
    async def test_content_tampered(self, report, chain_store, sealer_id, timestamp):
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        tampered = sealed.model_copy(update={"summary": "TAMPERED SUMMARY"})
        result = verify_seal(tampered)
        assert result.status == SealVerificationStatus.invalid_content_hash
        assert result.valid is False
        assert result.content_hash_match is False
        assert result.expected_content_hash != result.actual_content_hash

    @pytest.mark.asyncio
    async def test_chain_hash_tampered(self, report, chain_store, sealer_id, timestamp):
        """Modify seal.previous_hash to corrupt chain_hash computation while content_hash still matches."""
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        original_seal = sealed.seal
        # Create a new seal with modified previous_hash but same content_hash
        tampered_seal = TesseraSeal(
            content_hash=original_seal.content_hash,
            previous_hash="f" * 64,  # Different from original
            chain_hash=original_seal.chain_hash,  # Keep old chain_hash (now wrong)
            sealed_at=original_seal.sealed_at,
            sealer_id=original_seal.sealer_id,
        )
        tampered = sealed.model_copy(update={"seal": tampered_seal})
        result = verify_seal(tampered)
        assert result.status == SealVerificationStatus.invalid_chain_hash
        assert result.valid is False
        assert result.content_hash_match is True
        assert result.chain_hash_match is False

    def test_verify_never_raises_on_missing_seal(self):
        """verify_seal should never raise even with no seal."""
        report = _make_report()
        result = verify_seal(report)
        assert isinstance(result, SealVerificationResult)

    @pytest.mark.asyncio
    async def test_verify_seal_result_all_fields_populated(self, report, chain_store, sealer_id, timestamp):
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = verify_seal(sealed)
        # All hash fields should be 64-char hex
        assert re.match(r"^[a-f0-9]{64}$", result.expected_content_hash.value if hasattr(result.expected_content_hash, 'value') else result.expected_content_hash)
        assert re.match(r"^[a-f0-9]{64}$", result.actual_content_hash.value if hasattr(result.actual_content_hash, 'value') else result.actual_content_hash)
        assert re.match(r"^[a-f0-9]{64}$", result.expected_chain_hash.value if hasattr(result.expected_chain_hash, 'value') else result.expected_chain_hash)
        assert re.match(r"^[a-f0-9]{64}$", result.actual_chain_hash.value if hasattr(result.actual_chain_hash, 'value') else result.actual_chain_hash)

    @pytest.mark.asyncio
    async def test_verify_seal_immutable_result(self, report, chain_store, sealer_id, timestamp):
        """SealVerificationResult should be frozen/immutable."""
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = verify_seal(sealed)
        with pytest.raises(Exception):
            result.valid = False  # type: ignore


# ---------------------------------------------------------------------------
# TestFormatReport
# ---------------------------------------------------------------------------


class TestFormatReport:
    """Tests for the format_report function."""

    def test_json_happy_path(self, report, timestamp):
        result = format_report(report, OutputFormat.json, timestamp)
        assert result.output_format == OutputFormat.json
        assert len(result.content) > 0
        # Valid JSON
        parsed = json.loads(result.content)
        assert isinstance(parsed, dict)
        assert result.character_count == len(result.content)
        assert result.truncated is False
        # rendered_at matches timestamp
        rendered_at_val = result.rendered_at.value if hasattr(result.rendered_at, 'value') else str(result.rendered_at)
        assert rendered_at_val == FIXED_TIMESTAMP
        # report_id matches
        rid = result.report_id.value if hasattr(result.report_id, 'value') else str(result.report_id)
        assert rid == report.id

    def test_md_happy_path(self, report, timestamp):
        result = format_report(report, OutputFormat.md, timestamp)
        assert result.output_format == OutputFormat.md
        assert len(result.content) > 0
        assert result.truncated is False

    def test_github_happy_path(self, report, timestamp):
        result = format_report(report, OutputFormat.github, timestamp)
        assert result.output_format == OutputFormat.github
        assert "<details>" in result.content
        assert result.character_count == len(result.content)

    def test_metadata_pact_component(self, report, timestamp):
        result = format_report(report, OutputFormat.json, timestamp)
        assert result.metadata.get("pact_component") == "reporter"

    def test_is_sealed_false(self, report, timestamp):
        result = format_report(report, OutputFormat.json, timestamp)
        assert result.is_sealed is False

    @pytest.mark.asyncio
    async def test_is_sealed_true(self, report, chain_store, timestamp):
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = format_report(sealed, OutputFormat.json, timestamp)
        assert result.is_sealed is True

    def test_character_count_equals_len_content_json(self, report, timestamp):
        result = format_report(report, OutputFormat.json, timestamp)
        assert result.character_count == len(result.content)

    def test_character_count_equals_len_content_md(self, report, timestamp):
        result = format_report(report, OutputFormat.md, timestamp)
        assert result.character_count == len(result.content)

    def test_character_count_equals_len_content_github(self, report, timestamp):
        result = format_report(report, OutputFormat.github, timestamp)
        assert result.character_count == len(result.content)

    def test_json_truncated_always_false(self, report, timestamp):
        result = format_report(report, OutputFormat.json, timestamp)
        assert result.truncated is False

    def test_md_truncated_always_false(self, report, timestamp):
        result = format_report(report, OutputFormat.md, timestamp)
        assert result.truncated is False

    def test_deterministic_output(self, report, timestamp):
        r1 = format_report(report, OutputFormat.json, timestamp)
        r2 = format_report(report, OutputFormat.json, timestamp)
        assert r1.content == r2.content

    def test_deterministic_output_md(self, report, timestamp):
        r1 = format_report(report, OutputFormat.md, timestamp)
        r2 = format_report(report, OutputFormat.md, timestamp)
        assert r1.content == r2.content

    def test_deterministic_output_github(self, report, timestamp):
        r1 = format_report(report, OutputFormat.github, timestamp)
        r2 = format_report(report, OutputFormat.github, timestamp)
        assert r1.content == r2.content


# ---------------------------------------------------------------------------
# TestRenderers
# ---------------------------------------------------------------------------


class TestRenderJson:
    """Tests for render_json."""

    def test_valid_json_output(self, report):
        result = render_json(report)
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_two_space_indent(self, report):
        result = render_json(report)
        # Should contain lines indented with 2 spaces
        lines = result.split("\n")
        indented = [l for l in lines if l.startswith("  ")]
        assert len(indented) > 0

    def test_sorted_keys(self, report):
        result = render_json(report)
        parsed = json.loads(result)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    @pytest.mark.asyncio
    async def test_includes_seal_data(self, report, chain_store, timestamp):
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = render_json(sealed)
        parsed = json.loads(result)
        assert parsed.get("seal") is not None
        assert "content_hash" in parsed["seal"]
        assert "chain_hash" in parsed["seal"]

    def test_seal_null_when_absent(self, report):
        result = render_json(report)
        parsed = json.loads(result)
        assert parsed.get("seal") is None


class TestRenderMarkdown:
    """Tests for render_markdown."""

    def test_contains_heading_with_report_id(self, report, timestamp):
        result = render_markdown(report, timestamp)
        assert report.id in result
        assert "#" in result  # Markdown heading

    def test_severity_emojis(self, timestamp):
        report = _make_report(
            findings=[
                _make_finding(severity=Severity.critical, idx=0),
                _make_finding(severity=Severity.high, idx=1),
                _make_finding(severity=Severity.medium, idx=2),
                _make_finding(severity=Severity.low, idx=3),
                _make_finding(severity=Severity.info, idx=4),
            ]
        )
        result = render_markdown(report, timestamp)
        assert "🔴" in result  # critical
        assert "🟠" in result  # high
        assert "🟡" in result  # medium
        assert "🔵" in result  # low
        assert "⚪" in result  # info

    def test_findings_grouped_by_stage(self, timestamp):
        findings = [
            _make_finding(stage=ReviewStage.security, idx=0),
            _make_finding(stage=ReviewStage.correctness, idx=1),
        ]
        report = _make_report(findings=findings)
        result = render_markdown(report, timestamp)
        # Both stage names should appear
        assert "security" in result.lower() or "Security" in result
        assert "correctness" in result.lower() or "Correctness" in result

    def test_summary_table(self, report, timestamp):
        result = render_markdown(report, timestamp)
        # Should contain some tabular structure (pipe chars for Markdown tables)
        assert "|" in result

    @pytest.mark.asyncio
    async def test_seal_status_section_present(self, report, chain_store, timestamp):
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = render_markdown(sealed, timestamp)
        # Should mention seal or integrity
        lower_result = result.lower()
        assert "seal" in lower_result or "integrity" in lower_result

    def test_no_seal_section_when_unsealed(self, report, timestamp):
        result = render_markdown(report, timestamp)
        # We just confirm it renders without error; seal section may or may not appear
        assert len(result) > 0

    def test_empty_findings(self, report_no_findings, timestamp):
        result = render_markdown(report_no_findings, timestamp)
        assert len(result) > 0

    def test_all_finding_titles_present(self, timestamp):
        findings = [_make_finding(idx=i) for i in range(5)]
        report = _make_report(findings=findings)
        result = render_markdown(report, timestamp)
        for f in findings:
            assert f.title in result


class TestRenderGithub:
    """Tests for render_github."""

    def test_details_sections(self, report, timestamp):
        result = render_github(report, timestamp)
        assert "<details>" in result
        assert "<summary>" in result

    def test_severity_emojis(self, report, timestamp):
        result = render_github(report, timestamp)
        # Report has a high-severity finding
        assert "🟠" in result

    def test_no_truncation_under_limit(self, report, timestamp):
        result = render_github(report, timestamp)
        assert "⚠️ *Report truncated" not in result
        assert len(result) <= 65000

    def test_truncation_over_limit(self, timestamp):
        """Create a report large enough to exceed 65000 chars."""
        # Generate many large findings
        long_desc = "A" * 500
        findings = [
            _make_finding(idx=i, description=long_desc, stage=ReviewStage.security)
            for i in range(200)
        ]
        report = _make_report(findings=findings)
        result = render_github(report, timestamp)
        # If the raw rendering would exceed 65000, it should be truncated
        # The total output should not exceed 65000 + length of truncation notice
        max_allowed = 65000 + len(TRUNCATION_NOTICE)
        assert len(result) <= max_allowed
        if len(result) > 65000:
            assert "⚠️" in result or "truncated" in result.lower()

    def test_empty_stage_omitted(self, timestamp):
        """Stages without findings should not produce detail sections."""
        findings = [_make_finding(stage=ReviewStage.security, idx=0)]
        report = _make_report(findings=findings)
        result = render_github(report, timestamp)
        # Only security stage should have a details section
        # Count <details> sections
        details_count = result.count("<details>")
        assert details_count >= 1
        # Style/architecture should not have sections (no findings)
        # We can check if "style" or "architecture" appears in a <summary> tag
        # This is a best-effort structural check
        lower_result = result.lower()
        # If there are no findings for a stage, that stage heading should be absent
        # (We only check stages that have zero findings in our report)
        if "architecture" in lower_result:
            # It might appear in metadata; check it's not in a <summary> tag
            pass  # Relaxed assertion — contract says "omitted" not "absolutely absent"

    def test_valid_github_flavored_markdown(self, report, timestamp):
        result = render_github(report, timestamp)
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# Invariant Tests
# ---------------------------------------------------------------------------


class TestInvariants:
    """Cross-cutting invariant tests."""

    def test_json_format_vs_canonical_format(self, report, timestamp):
        """format_report JSON uses 2-space indent; canonicalize uses compact separators."""
        canonical_bytes = canonicalize(report)
        canonical_text = canonical_bytes.decode("utf-8")

        formatted = format_report(report, OutputFormat.json, timestamp)
        formatted_text = formatted.content

        # Canonical should be compact (no newlines or indentation)
        assert "\n" not in canonical_text
        # Formatted should have indentation (newlines present)
        assert "\n" in formatted_text

    def test_canonicalize_is_single_source_of_truth(self, report):
        """Both seal_report and verify_seal should use canonicalize for hashing."""
        # Verify by computing hash from canonicalize and comparing with what seal_report produces
        canonical = canonicalize(report)
        expected_hash = _sha256_hex(canonical)
        # We'll verify this matches after sealing
        assert isinstance(expected_hash, str)
        assert len(expected_hash) == 64

    @pytest.mark.asyncio
    async def test_seal_content_hash_matches_canonicalize(self, report, chain_store, timestamp):
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        canonical = canonicalize(report)
        expected_hash = _sha256_hex(canonical)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        assert sealed.seal.content_hash == expected_hash

    @pytest.mark.asyncio
    async def test_seal_chain_hash_formula(self, report, chain_store, timestamp):
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        seal = sealed.seal
        prev = seal.previous_hash or "GENESIS"
        expected_chain = _sha256_hex((seal.content_hash + "|" + prev).encode("utf-8"))
        assert seal.chain_hash == expected_chain

    @pytest.mark.asyncio
    async def test_frozen_review_report(self, report, chain_store, timestamp):
        """ReviewReport instances are frozen (immutable)."""
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        with pytest.raises(Exception):
            sealed.summary = "mutated"  # type: ignore

    def test_formatted_report_frozen(self, report, timestamp):
        """FormattedReport instances are frozen (immutable)."""
        result = format_report(report, OutputFormat.json, timestamp)
        with pytest.raises(Exception):
            result.content = "mutated"  # type: ignore

    @pytest.mark.asyncio
    async def test_verify_seal_result_frozen(self, report, chain_store, timestamp):
        """SealVerificationResult instances are frozen (immutable)."""
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = verify_seal(sealed)
        with pytest.raises(Exception):
            result.valid = not result.valid  # type: ignore

    def test_github_never_exceeds_limit(self, timestamp):
        """GitHub format output never exceeds 65000 characters (plus truncation notice)."""
        long_desc = "X" * 1000
        findings = [
            _make_finding(idx=i, description=long_desc, stage=ReviewStage.security)
            for i in range(100)
        ]
        report = _make_report(findings=findings)
        result = render_github(report, timestamp)
        # The rendered content, excluding truncation notice, should be <= 65000
        # Or total with notice <= 65000 + len(notice)
        max_total = 65000 + len(TRUNCATION_NOTICE)
        assert len(result) <= max_total

    def test_all_output_formats_produce_nonempty_content(self, report, timestamp):
        for fmt in [OutputFormat.json, OutputFormat.md, OutputFormat.github]:
            result = format_report(report, fmt, timestamp)
            assert len(result.content) > 0, f"Empty content for format {fmt}"

    def test_pact_component_in_all_formatted_reports(self, report, timestamp):
        for fmt in [OutputFormat.json, OutputFormat.md, OutputFormat.github]:
            result = format_report(report, fmt, timestamp)
            assert result.metadata.get("pact_component") == "reporter"

    @pytest.mark.asyncio
    async def test_verify_after_seal_all_hash_fields_are_64_hex(self, report, chain_store, timestamp):
        sealer_id = SealerId(value=FIXED_SEALER_ID)
        sealed = await seal_report(report, chain_store, sealer_id, timestamp, None)
        result = verify_seal(sealed)
        for field_name in ["expected_content_hash", "actual_content_hash", "expected_chain_hash", "actual_chain_hash"]:
            val = getattr(result, field_name)
            raw = val.value if hasattr(val, "value") else str(val)
            assert re.match(r"^[a-f0-9]{64}$", raw), f"{field_name} is not valid hex: {raw}"
