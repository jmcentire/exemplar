"""
Contract tests for exemplar.schemas module.
Tests verify behavior at boundaries per the contract specification.
"""

import hashlib
import json

import pytest
from pydantic import ValidationError

from exemplar.schemas import (
    Assessment,
    ChroniclerEvent,
    ChroniclerEventType,
    ClassificationLabel,
    CliExitCode,
    Confidence,
    DiffHunk,
    Finding,
    KindexEntry,
    LearnerPhase,
    LearningRecord,
    OutputFormat,
    PipelineResult,
    PolicyToken,
    ReviewDecision,
    ReviewReport,
    ReviewRequest,
    ReviewStage,
    ReviewerCredential,
    Severity,
    StigmergySignal,
    StigmergyVerb,
    TesseraSeal,
    TrustScore,
    confidence_rank,
    learner_phase_rank,
    severity_rank,
    validate_iso_timestamp,
    _ExemplarBase,
)


# ============================================================================
# Fixtures — reusable valid instances of each model
# ============================================================================

@pytest.fixture
def valid_diff_hunk():
    return DiffHunk(
        id="hunk-001",
        file_path="src/main.py",
        start_line_old=10,
        count_old=5,
        start_line_new=10,
        count_new=7,
        context_before=["import os"],
        added_lines=["import sys", "import json"],
        removed_lines=["import csv"],
        context_after=["def main():"],
        raw_header="@@ -10,5 +10,7 @@",
        classifications=[ClassificationLabel.public],
        language="python",
    )


@pytest.fixture
def valid_diff_hunk_no_language():
    return DiffHunk(
        id="hunk-002",
        file_path="README.md",
        start_line_old=1,
        count_old=1,
        start_line_new=1,
        count_new=1,
        context_before=[],
        added_lines=["# Title"],
        removed_lines=["# Old Title"],
        context_after=[],
        raw_header="@@ -1,1 +1,1 @@",
        classifications=[],
        language=None,
    )


@pytest.fixture
def valid_finding():
    return Finding(
        id="finding-001",
        hunk_id="hunk-001",
        file_path="src/main.py",
        line_number=15,
        severity=Severity.high,
        confidence=Confidence.high,
        title="Hardcoded secret",
        description="A hardcoded API key was found.",
        suggestion="Use environment variables instead.",
        rule_id="SEC-001",
        stage=ReviewStage.security,
    )


@pytest.fixture
def valid_finding_no_optionals():
    return Finding(
        id="finding-002",
        hunk_id="hunk-001",
        file_path="src/main.py",
        line_number=None,
        severity=Severity.low,
        confidence=Confidence.low,
        title="Minor style issue",
        description="Trailing whitespace.",
        suggestion=None,
        rule_id="STY-001",
        stage=ReviewStage.style,
    )


@pytest.fixture
def valid_assessment(valid_finding):
    return Assessment(
        id="assessment-001",
        review_request_id="rr-001",
        stage=ReviewStage.security,
        reviewer_id="reviewer-sec-01",
        decision=ReviewDecision.warn,
        findings=[valid_finding],
        confidence=Confidence.high,
        is_partial=False,
        error_message=None,
        duration_ms=1234,
        created_at="2024-06-15T10:30:00Z",
    )


@pytest.fixture
def valid_trust_score():
    return TrustScore(
        reviewer_id="reviewer-sec-01",
        stage=ReviewStage.security,
        weight=0.85,
        accepted_count=100,
        dismissed_count=15,
        updated_at="2024-06-15T10:30:00Z",
    )


@pytest.fixture
def valid_tessera_seal():
    return TesseraSeal(
        content_hash="a" * 64,
        previous_hash=None,
        chain_hash="b" * 64,
        sealed_at="2024-06-15T10:30:00Z",
        sealer_id="sealer-001",
    )


@pytest.fixture
def valid_review_request(valid_diff_hunk):
    return ReviewRequest(
        id="rr-001",
        source="github",
        hunks=[valid_diff_hunk],
        file_paths=["src/main.py"],
        created_at="2024-06-15T10:00:00Z",
        metadata={"pr_number": "42"},
    )


@pytest.fixture
def valid_review_report(valid_finding, valid_assessment, valid_trust_score, valid_tessera_seal):
    return ReviewReport(
        id="report-001",
        review_request_id="rr-001",
        decision=ReviewDecision.warn,
        findings=[valid_finding],
        assessments=[valid_assessment],
        confidence=Confidence.high,
        trust_scores=[valid_trust_score],
        conflict_notes=["Minor disagreement on severity."],
        summary="Review complete with warnings.",
        seal=valid_tessera_seal,
        created_at="2024-06-15T11:00:00Z",
        metadata={"output": "github"},
    )


@pytest.fixture
def valid_reviewer_credential():
    return ReviewerCredential(
        reviewer_id="reviewer-sec-01",
        display_name="Security Reviewer",
        stage=ReviewStage.security,
        public_key_hex="deadbeef" * 8,
        created_at="2024-01-01T00:00:00Z",
        is_active=True,
    )


@pytest.fixture
def valid_policy_token():
    return PolicyToken(
        token_id="token-001",
        reviewer_id="reviewer-sec-01",
        allowed_file_patterns=["*.py"],
        denied_file_patterns=["*.secret"],
        allowed_classifications=[ClassificationLabel.public, ClassificationLabel.internal_api],
        max_severity=Severity.high,
        issued_at="2024-06-15T10:00:00Z",
        expires_at="2025-06-15T10:00:00Z",
    )


@pytest.fixture
def valid_chronicler_event():
    return ChroniclerEvent(
        event_id="evt-001",
        event_type=ChroniclerEventType["review.started"],
        review_request_id="rr-001",
        timestamp="2024-06-15T10:00:00Z",
        stage=None,
        reviewer_id=None,
        payload={"detail": "starting review"},
        message="Review started for PR #42",
    )


@pytest.fixture
def valid_stigmergy_signal():
    return StigmergySignal(
        signal_id="sig-001",
        pattern_key="hardcoded-secret",
        description="Hardcoded secrets in config files",
        occurrences=5,
        first_seen_at="2024-01-01T00:00:00Z",
        last_seen_at="2024-06-15T10:00:00Z",
        reviewer_id="reviewer-sec-01",
        stage=ReviewStage.security,
        metadata={"severity": "high"},
    )


@pytest.fixture
def valid_learning_record():
    return LearningRecord(
        record_id="lr-001",
        finding_id="finding-001",
        reviewer_id="reviewer-sec-01",
        stage=ReviewStage.security,
        rule_id="SEC-001",
        severity=Severity.high,
        accepted=True,
        human_comment="Good catch!",
        recorded_at="2024-06-15T12:00:00Z",
    )


@pytest.fixture
def valid_kindex_entry():
    return KindexEntry(
        key="kindex-001",
        kind="review",
        summary="Past review of auth module",
        data={"file": "auth.py"},
        tags=["auth", "security"],
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-06-15T10:00:00Z",
    )


@pytest.fixture
def valid_pipeline_result(valid_review_request, valid_assessment, valid_review_report, valid_chronicler_event):
    return PipelineResult(
        review_request=valid_review_request,
        assessments=[valid_assessment],
        report=valid_review_report,
        events=[valid_chronicler_event],
        formatted_output="## Review Report\nWarnings found.",
        output_format=OutputFormat.md,
        exit_code=1,
    )


# ============================================================================
# Enum Tests
# ============================================================================

class TestSeverityEnum:
    """Tests for the Severity StrEnum."""

    @pytest.mark.parametrize("member_name,expected_value", [
        ("critical", "critical"),
        ("high", "high"),
        ("medium", "medium"),
        ("low", "low"),
        ("info", "info"),
    ])
    def test_member_values(self, member_name, expected_value):
        member = Severity(expected_value)
        assert member.value == expected_value
        assert member.name == member_name

    def test_is_str_subclass(self):
        for member in Severity:
            assert isinstance(member, str), f"{member} is not a str instance"

    def test_member_count(self):
        assert len(Severity) == 5

    def test_iteration_order(self):
        names = [m.name for m in Severity]
        assert "critical" in names
        assert "info" in names

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            Severity("nonexistent")


class TestConfidenceEnum:
    """Tests for the Confidence StrEnum."""

    @pytest.mark.parametrize("value", ["high", "medium", "low"])
    def test_member_values(self, value):
        member = Confidence(value)
        assert member.value == value

    def test_is_str_subclass(self):
        for member in Confidence:
            assert isinstance(member, str)

    def test_member_count(self):
        assert len(Confidence) == 3

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            Confidence("invalid")


class TestReviewStageEnum:
    """Tests for the ReviewStage StrEnum."""

    @pytest.mark.parametrize("value", ["security", "correctness", "style", "architecture"])
    def test_member_values(self, value):
        member = ReviewStage(value)
        assert member.value == value

    def test_member_count(self):
        assert len(ReviewStage) == 4

    def test_is_str_subclass(self):
        for member in ReviewStage:
            assert isinstance(member, str)


class TestReviewDecisionEnum:
    """Tests for the ReviewDecision StrEnum."""

    @pytest.mark.parametrize("value", ["block", "warn", "pass"])
    def test_member_values(self, value):
        member = ReviewDecision(value)
        assert member.value == value

    def test_member_count(self):
        assert len(ReviewDecision) == 3

    # 'pass' is a Python keyword but should work as enum value
    def test_pass_member_accessible(self):
        p = ReviewDecision("pass")
        assert p == "pass"


class TestClassificationLabelEnum:
    """Tests for the ClassificationLabel StrEnum."""

    @pytest.mark.parametrize("value", ["secret", "pii", "internal_api", "public"])
    def test_member_values(self, value):
        member = ClassificationLabel(value)
        assert member.value == value

    def test_member_count(self):
        assert len(ClassificationLabel) == 4


class TestChroniclerEventTypeEnum:
    """Tests for the ChroniclerEventType StrEnum."""

    EXPECTED_VALUES = [
        "review.started", "stage.started", "stage.complete",
        "assessment.merged", "report.sealed", "review.complete",
        "policy.violation", "pattern.detected", "learning.recorded",
    ]

    @pytest.mark.parametrize("value", EXPECTED_VALUES)
    def test_member_values(self, value):
        member = ChroniclerEventType(value)
        assert member.value == value

    def test_is_str_subclass(self):
        for member in ChroniclerEventType:
            assert isinstance(member, str)


class TestLearnerPhaseEnum:
    """Tests for the LearnerPhase StrEnum."""

    @pytest.mark.parametrize("value", ["shadow", "canary", "primary"])
    def test_member_values(self, value):
        member = LearnerPhase(value)
        assert member.value == value

    def test_member_count(self):
        assert len(LearnerPhase) == 3


class TestStigmergyVerbEnum:
    """Tests for the StigmergyVerb StrEnum."""

    @pytest.mark.parametrize("value", ["deposit", "reinforce", "decay", "query"])
    def test_member_values(self, value):
        member = StigmergyVerb(value)
        assert member.value == value

    def test_is_str_subclass(self):
        for member in StigmergyVerb:
            assert isinstance(member, str)


class TestCliExitCodeEnum:
    """Tests for the CliExitCode IntEnum."""

    @pytest.mark.parametrize("value", [0, 1, 2, 3])
    def test_member_values(self, value):
        member = CliExitCode(value)
        assert member.value == value
        assert isinstance(member.value, int)

    def test_member_count(self):
        assert len(CliExitCode) == 4


class TestOutputFormatEnum:
    """Tests for the OutputFormat StrEnum."""

    @pytest.mark.parametrize("value", ["json", "md", "github"])
    def test_member_values(self, value):
        member = OutputFormat(value)
        assert member.value == value

    def test_member_count(self):
        assert len(OutputFormat) == 3


# ============================================================================
# Rank Function Tests
# ============================================================================

class TestSeverityRank:
    """Tests for the severity_rank function."""

    @pytest.mark.parametrize("severity,expected_rank", [
        (Severity.critical, 4),
        (Severity.high, 3),
        (Severity.medium, 2),
        (Severity.low, 1),
        (Severity.info, 0),
    ])
    def test_correct_rank(self, severity, expected_rank):
        assert severity_rank(severity) == expected_rank

    @pytest.mark.parametrize("severity", list(Severity))
    def test_return_type_is_int(self, severity):
        result = severity_rank(severity)
        assert isinstance(result, int)

    @pytest.mark.parametrize("severity", list(Severity))
    def test_range_0_to_4(self, severity):
        result = severity_rank(severity)
        assert 0 <= result <= 4

    def test_ordering_invariant(self):
        assert severity_rank(Severity.critical) > severity_rank(Severity.high)
        assert severity_rank(Severity.high) > severity_rank(Severity.medium)
        assert severity_rank(Severity.medium) > severity_rank(Severity.low)
        assert severity_rank(Severity.low) > severity_rank(Severity.info)

    def test_invalid_input_raises(self):
        with pytest.raises((ValueError, KeyError, TypeError, AttributeError)):
            severity_rank("not_a_severity")

    def test_invalid_input_none(self):
        with pytest.raises((ValueError, KeyError, TypeError, AttributeError)):
            severity_rank(None)


class TestConfidenceRank:
    """Tests for the confidence_rank function."""

    @pytest.mark.parametrize("confidence,expected_rank", [
        (Confidence.high, 2),
        (Confidence.medium, 1),
        (Confidence.low, 0),
    ])
    def test_correct_rank(self, confidence, expected_rank):
        assert confidence_rank(confidence) == expected_rank

    @pytest.mark.parametrize("confidence", list(Confidence))
    def test_return_type_is_int(self, confidence):
        result = confidence_rank(confidence)
        assert isinstance(result, int)

    @pytest.mark.parametrize("confidence", list(Confidence))
    def test_range_0_to_2(self, confidence):
        result = confidence_rank(confidence)
        assert 0 <= result <= 2

    def test_ordering_invariant(self):
        assert confidence_rank(Confidence.high) > confidence_rank(Confidence.medium)
        assert confidence_rank(Confidence.medium) > confidence_rank(Confidence.low)

    def test_invalid_input_raises(self):
        with pytest.raises((ValueError, KeyError, TypeError, AttributeError)):
            confidence_rank("not_a_confidence")


class TestLearnerPhaseRank:
    """Tests for the learner_phase_rank function."""

    @pytest.mark.parametrize("phase", list(LearnerPhase))
    def test_return_type_is_int(self, phase):
        result = learner_phase_rank(phase)
        assert isinstance(result, int)

    @pytest.mark.parametrize("phase", list(LearnerPhase))
    def test_range_0_to_3(self, phase):
        result = learner_phase_rank(phase)
        assert 0 <= result <= 3

    def test_ordering_is_monotonic(self):
        """Phases should have a well-defined ordering."""
        ranks = [learner_phase_rank(p) for p in LearnerPhase]
        # All ranks should be distinct
        assert len(set(ranks)) == len(ranks)

    def test_invalid_input_raises(self):
        with pytest.raises((ValueError, KeyError, TypeError, AttributeError)):
            learner_phase_rank("not_a_phase")


# ============================================================================
# Timestamp Validation Tests
# ============================================================================

class TestValidateIsoTimestamp:
    """Tests for the validate_iso_timestamp function."""

    @pytest.mark.parametrize("valid_ts", [
        "2024-01-01T00:00:00",
        "2024-06-15T10:30:00Z",
        "2024-06-15T10:30:00+00:00",
        "2024-06-15T10:30:00-05:00",
        "2024-01-01T00:00:00.123456",
        "2024-01-01",
    ])
    def test_valid_iso_strings_accepted(self, valid_ts):
        result = validate_iso_timestamp(valid_ts)
        assert result == valid_ts, "Returned value should be identical to input"

    def test_returns_input_unchanged(self):
        ts = "2024-06-15T10:30:00+00:00"
        result = validate_iso_timestamp(ts)
        assert result is ts or result == ts

    @pytest.mark.parametrize("invalid_ts", [
        "not-a-date",
        "2024/01/01",
        "yesterday",
        "12345",
        "2024-13-01T00:00:00",  # invalid month
        "abcdefg",
    ])
    def test_invalid_iso_strings_rejected(self, invalid_ts):
        with pytest.raises((ValueError, TypeError)):
            validate_iso_timestamp(invalid_ts)

    def test_empty_string_rejected(self):
        with pytest.raises((ValueError, TypeError)):
            validate_iso_timestamp("")


# ============================================================================
# Frozen Model Tests — DiffHunk
# ============================================================================

class TestDiffHunk:
    """Tests for the DiffHunk frozen model."""

    def test_construction_happy_path(self, valid_diff_hunk):
        assert valid_diff_hunk.id == "hunk-001"
        assert valid_diff_hunk.file_path == "src/main.py"
        assert valid_diff_hunk.start_line_old == 10
        assert valid_diff_hunk.count_old == 5
        assert valid_diff_hunk.start_line_new == 10
        assert valid_diff_hunk.count_new == 7
        assert valid_diff_hunk.language == "python"
        assert ClassificationLabel.public in valid_diff_hunk.classifications

    def test_optional_language_none(self, valid_diff_hunk_no_language):
        assert valid_diff_hunk_no_language.language is None

    def test_frozen_immutability(self, valid_diff_hunk):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_diff_hunk.id = "changed"

    def test_extra_field_forbidden(self):
        with pytest.raises(ValidationError):
            DiffHunk(
                id="hunk-001",
                file_path="src/main.py",
                start_line_old=10,
                count_old=5,
                start_line_new=10,
                count_new=7,
                context_before=[],
                added_lines=[],
                removed_lines=[],
                context_after=[],
                raw_header="@@",
                classifications=[],
                language=None,
                extra_field="should fail",
            )

    def test_missing_required_field(self):
        with pytest.raises(ValidationError):
            DiffHunk(id="hunk-001")  # missing many required fields

    def test_json_roundtrip(self, valid_diff_hunk):
        json_str = valid_diff_hunk.model_dump_json()
        restored = DiffHunk.model_validate_json(json_str)
        assert restored == valid_diff_hunk

    def test_hashable(self, valid_diff_hunk):
        h = hash(valid_diff_hunk)
        assert isinstance(h, int)


# ============================================================================
# Frozen Model Tests — ReviewRequest
# ============================================================================

class TestReviewRequest:
    """Tests for the ReviewRequest frozen model."""

    def test_construction_happy_path(self, valid_review_request):
        assert valid_review_request.id == "rr-001"
        assert valid_review_request.source == "github"
        assert len(valid_review_request.hunks) == 1
        assert isinstance(valid_review_request.hunks[0], DiffHunk)
        assert valid_review_request.file_paths == ["src/main.py"]

    def test_frozen_immutability(self, valid_review_request):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_review_request.id = "changed"

    def test_json_roundtrip(self, valid_review_request):
        json_str = valid_review_request.model_dump_json()
        restored = ReviewRequest.model_validate_json(json_str)
        assert restored == valid_review_request


# ============================================================================
# Frozen Model Tests — Finding
# ============================================================================

class TestFinding:
    """Tests for the Finding frozen model."""

    def test_construction_happy_path(self, valid_finding):
        assert valid_finding.id == "finding-001"
        assert valid_finding.severity == Severity.high
        assert valid_finding.confidence == Confidence.high
        assert valid_finding.stage == ReviewStage.security
        assert valid_finding.line_number == 15
        assert valid_finding.suggestion == "Use environment variables instead."

    def test_optional_fields_none(self, valid_finding_no_optionals):
        assert valid_finding_no_optionals.line_number is None
        assert valid_finding_no_optionals.suggestion is None

    def test_frozen_immutability(self, valid_finding):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_finding.title = "changed"

    def test_wrong_type_severity(self):
        with pytest.raises(ValidationError):
            Finding(
                id="f-001",
                hunk_id="h-001",
                file_path="x.py",
                line_number=1,
                severity="NOT_A_SEVERITY",
                confidence=Confidence.low,
                title="t",
                description="d",
                suggestion=None,
                rule_id="R001",
                stage=ReviewStage.security,
            )

    def test_json_roundtrip(self, valid_finding):
        json_str = valid_finding.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert restored == valid_finding

    def test_hashable_and_equal_instances_same_hash(self):
        kwargs = dict(
            id="f-001", hunk_id="h-001", file_path="x.py", line_number=1,
            severity=Severity.low, confidence=Confidence.low, title="t",
            description="d", suggestion=None, rule_id="R001", stage=ReviewStage.style,
        )
        f1 = Finding(**kwargs)
        f2 = Finding(**kwargs)
        assert hash(f1) == hash(f2)
        assert f1 == f2


# ============================================================================
# Frozen Model Tests — Assessment
# ============================================================================

class TestAssessment:
    """Tests for the Assessment frozen model."""

    def test_construction_happy_path(self, valid_assessment):
        assert valid_assessment.id == "assessment-001"
        assert valid_assessment.stage == ReviewStage.security
        assert valid_assessment.decision == ReviewDecision.warn
        assert len(valid_assessment.findings) == 1
        assert valid_assessment.is_partial is False
        assert valid_assessment.error_message is None

    def test_frozen_immutability(self, valid_assessment):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_assessment.decision = ReviewDecision.block

    def test_json_roundtrip(self, valid_assessment):
        json_str = valid_assessment.model_dump_json()
        restored = Assessment.model_validate_json(json_str)
        assert restored == valid_assessment


# ============================================================================
# Frozen Model Tests — TrustScore
# ============================================================================

class TestTrustScore:
    """Tests for the TrustScore frozen model with weight validator."""

    def test_construction_happy_path(self, valid_trust_score):
        assert valid_trust_score.weight == 0.85
        assert valid_trust_score.accepted_count == 100

    def test_weight_boundary_zero(self):
        ts = TrustScore(
            reviewer_id="r1", stage=ReviewStage.security,
            weight=0.0, accepted_count=0, dismissed_count=0,
            updated_at="2024-01-01T00:00:00Z",
        )
        assert ts.weight == 0.0

    def test_weight_boundary_one(self):
        ts = TrustScore(
            reviewer_id="r1", stage=ReviewStage.security,
            weight=1.0, accepted_count=0, dismissed_count=0,
            updated_at="2024-01-01T00:00:00Z",
        )
        assert ts.weight == 1.0

    def test_weight_below_zero_rejected(self):
        with pytest.raises(ValidationError):
            TrustScore(
                reviewer_id="r1", stage=ReviewStage.security,
                weight=-0.1, accepted_count=0, dismissed_count=0,
                updated_at="2024-01-01T00:00:00Z",
            )

    def test_weight_above_one_rejected(self):
        with pytest.raises(ValidationError):
            TrustScore(
                reviewer_id="r1", stage=ReviewStage.security,
                weight=1.1, accepted_count=0, dismissed_count=0,
                updated_at="2024-01-01T00:00:00Z",
            )

    def test_weight_just_inside_lower_bound(self):
        ts = TrustScore(
            reviewer_id="r1", stage=ReviewStage.security,
            weight=0.001, accepted_count=0, dismissed_count=0,
            updated_at="2024-01-01T00:00:00Z",
        )
        assert ts.weight == pytest.approx(0.001)

    def test_weight_just_inside_upper_bound(self):
        ts = TrustScore(
            reviewer_id="r1", stage=ReviewStage.security,
            weight=0.999, accepted_count=0, dismissed_count=0,
            updated_at="2024-01-01T00:00:00Z",
        )
        assert ts.weight == pytest.approx(0.999)

    def test_frozen_immutability(self, valid_trust_score):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_trust_score.weight = 0.5

    def test_json_roundtrip(self, valid_trust_score):
        json_str = valid_trust_score.model_dump_json()
        restored = TrustScore.model_validate_json(json_str)
        assert restored == valid_trust_score


# ============================================================================
# Frozen Model Tests — TesseraSeal
# ============================================================================

class TestTesseraSeal:
    """Tests for the TesseraSeal frozen model."""

    def test_construction_happy_path(self, valid_tessera_seal):
        assert valid_tessera_seal.content_hash == "a" * 64
        assert valid_tessera_seal.previous_hash is None
        assert valid_tessera_seal.chain_hash == "b" * 64

    def test_with_previous_hash(self):
        seal = TesseraSeal(
            content_hash="a" * 64,
            previous_hash="c" * 64,
            chain_hash="d" * 64,
            sealed_at="2024-06-15T10:30:00Z",
            sealer_id="sealer-001",
        )
        assert seal.previous_hash == "c" * 64

    def test_frozen_immutability(self, valid_tessera_seal):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_tessera_seal.content_hash = "changed"


# ============================================================================
# Frozen Model Tests — ReviewReport
# ============================================================================

class TestReviewReport:
    """Tests for the ReviewReport frozen model with deep nesting."""

    def test_construction_happy_path(self, valid_review_report):
        assert valid_review_report.id == "report-001"
        assert valid_review_report.decision == ReviewDecision.warn
        assert len(valid_review_report.findings) == 1
        assert len(valid_review_report.assessments) == 1
        assert len(valid_review_report.trust_scores) == 1
        assert valid_review_report.seal is not None
        assert valid_review_report.confidence == Confidence.high

    def test_seal_optional_none(self, valid_finding, valid_assessment, valid_trust_score):
        report = ReviewReport(
            id="report-002",
            review_request_id="rr-002",
            decision=ReviewDecision("pass"),
            findings=[valid_finding],
            assessments=[valid_assessment],
            confidence=Confidence.medium,
            trust_scores=[valid_trust_score],
            conflict_notes=[],
            summary="All clear.",
            seal=None,
            created_at="2024-06-15T11:00:00Z",
            metadata={},
        )
        assert report.seal is None

    def test_frozen_immutability(self, valid_review_report):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_review_report.summary = "changed"

    def test_json_roundtrip(self, valid_review_report):
        json_str = valid_review_report.model_dump_json()
        restored = ReviewReport.model_validate_json(json_str)
        assert restored == valid_review_report


# ============================================================================
# Frozen Model Tests — ReviewerCredential
# ============================================================================

class TestReviewerCredential:
    """Tests for the ReviewerCredential frozen model."""

    def test_construction_happy_path(self, valid_reviewer_credential):
        assert valid_reviewer_credential.reviewer_id == "reviewer-sec-01"
        assert valid_reviewer_credential.is_active is True

    def test_frozen_immutability(self, valid_reviewer_credential):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_reviewer_credential.is_active = False


# ============================================================================
# Frozen Model Tests — PolicyToken
# ============================================================================

class TestPolicyToken:
    """Tests for the PolicyToken frozen model."""

    def test_construction_happy_path(self, valid_policy_token):
        assert valid_policy_token.token_id == "token-001"
        assert ClassificationLabel.public in valid_policy_token.allowed_classifications
        assert valid_policy_token.max_severity == Severity.high

    def test_expires_at_optional(self):
        token = PolicyToken(
            token_id="t-002",
            reviewer_id="r1",
            allowed_file_patterns=[],
            denied_file_patterns=[],
            allowed_classifications=[],
            max_severity=Severity.info,
            issued_at="2024-01-01T00:00:00Z",
            expires_at=None,
        )
        assert token.expires_at is None

    def test_frozen_immutability(self, valid_policy_token):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_policy_token.token_id = "changed"


# ============================================================================
# Frozen Model Tests — ChroniclerEvent
# ============================================================================

class TestChroniclerEvent:
    """Tests for the ChroniclerEvent frozen model."""

    def test_construction_happy_path(self, valid_chronicler_event):
        assert valid_chronicler_event.event_id == "evt-001"
        assert valid_chronicler_event.event_type == ChroniclerEventType["review.started"]
        assert valid_chronicler_event.stage is None
        assert valid_chronicler_event.reviewer_id is None

    def test_with_optional_stage_and_reviewer(self):
        event = ChroniclerEvent(
            event_id="evt-002",
            event_type=ChroniclerEventType["stage.complete"],
            review_request_id="rr-001",
            timestamp="2024-06-15T10:05:00Z",
            stage=ReviewStage.security,
            reviewer_id="reviewer-sec-01",
            payload={"findings_count": "3"},
            message="Security stage complete.",
        )
        assert event.stage == ReviewStage.security
        assert event.reviewer_id == "reviewer-sec-01"

    def test_frozen_immutability(self, valid_chronicler_event):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_chronicler_event.message = "changed"


# ============================================================================
# Frozen Model Tests — StigmergySignal
# ============================================================================

class TestStigmergySignal:
    """Tests for the StigmergySignal frozen model."""

    def test_construction_happy_path(self, valid_stigmergy_signal):
        assert valid_stigmergy_signal.signal_id == "sig-001"
        assert valid_stigmergy_signal.occurrences == 5

    def test_optional_fields_none(self):
        signal = StigmergySignal(
            signal_id="sig-002",
            pattern_key="unused-import",
            description="Unused imports detected",
            occurrences=1,
            first_seen_at="2024-01-01T00:00:00Z",
            last_seen_at="2024-01-01T00:00:00Z",
            reviewer_id=None,
            stage=None,
            metadata={},
        )
        assert signal.reviewer_id is None
        assert signal.stage is None

    def test_frozen_immutability(self, valid_stigmergy_signal):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_stigmergy_signal.occurrences = 99


# ============================================================================
# Frozen Model Tests — LearningRecord
# ============================================================================

class TestLearningRecord:
    """Tests for the LearningRecord frozen model."""

    def test_construction_happy_path(self, valid_learning_record):
        assert valid_learning_record.record_id == "lr-001"
        assert valid_learning_record.accepted is True
        assert valid_learning_record.human_comment == "Good catch!"

    def test_optional_human_comment_none(self):
        lr = LearningRecord(
            record_id="lr-002",
            finding_id="f-002",
            reviewer_id="r1",
            stage=ReviewStage.style,
            rule_id="STY-001",
            severity=Severity.low,
            accepted=False,
            human_comment=None,
            recorded_at="2024-06-15T12:00:00Z",
        )
        assert lr.human_comment is None

    def test_frozen_immutability(self, valid_learning_record):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_learning_record.accepted = False


# ============================================================================
# Frozen Model Tests — KindexEntry
# ============================================================================

class TestKindexEntry:
    """Tests for the KindexEntry frozen model."""

    def test_construction_happy_path(self, valid_kindex_entry):
        assert valid_kindex_entry.key == "kindex-001"
        assert valid_kindex_entry.kind == "review"
        assert "auth" in valid_kindex_entry.tags

    def test_empty_tags_and_data(self):
        entry = KindexEntry(
            key="k-002",
            kind="context",
            summary="Empty context",
            data={},
            tags=[],
            created_at="2024-01-01T00:00:00Z",
            updated_at="2024-01-01T00:00:00Z",
        )
        assert entry.data == {}
        assert entry.tags == []

    def test_frozen_immutability(self, valid_kindex_entry):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_kindex_entry.key = "changed"


# ============================================================================
# Frozen Model Tests — PipelineResult
# ============================================================================

class TestPipelineResult:
    """Tests for the PipelineResult frozen model."""

    def test_construction_happy_path(self, valid_pipeline_result):
        assert valid_pipeline_result.output_format == OutputFormat.md
        assert valid_pipeline_result.exit_code == 1
        assert isinstance(valid_pipeline_result.review_request, ReviewRequest)
        assert isinstance(valid_pipeline_result.report, ReviewReport)
        assert len(valid_pipeline_result.assessments) == 1
        assert len(valid_pipeline_result.events) == 1

    def test_frozen_immutability(self, valid_pipeline_result):
        with pytest.raises((ValidationError, TypeError, AttributeError)):
            valid_pipeline_result.exit_code = 0


# ============================================================================
# Canonical Serialization Tests
# ============================================================================

class TestCanonicalBytes:
    """Tests for canonical_bytes() on _ExemplarBase subclasses."""

    def test_returns_bytes(self, valid_finding):
        result = valid_finding.canonical_bytes()
        assert isinstance(result, bytes)

    def test_valid_utf8_json(self, valid_finding):
        raw = valid_finding.canonical_bytes()
        text = raw.decode("utf-8")
        parsed = json.loads(text)
        assert isinstance(parsed, dict)

    def test_deterministic_same_instance(self, valid_finding):
        first = valid_finding.canonical_bytes()
        second = valid_finding.canonical_bytes()
        assert first == second

    def test_deterministic_equivalent_instances(self):
        kwargs = dict(
            id="f-001", hunk_id="h-001", file_path="x.py", line_number=1,
            severity=Severity.low, confidence=Confidence.low, title="t",
            description="d", suggestion=None, rule_id="R001", stage=ReviewStage.style,
        )
        f1 = Finding(**kwargs)
        f2 = Finding(**kwargs)
        assert f1.canonical_bytes() == f2.canonical_bytes()

    def test_json_matches_model_dump(self, valid_finding):
        raw = valid_finding.canonical_bytes()
        parsed = json.loads(raw)
        expected = valid_finding.model_dump(mode="json")
        assert parsed == expected

    def test_different_instances_different_bytes(self):
        f1 = Finding(
            id="f-001", hunk_id="h-001", file_path="x.py", line_number=1,
            severity=Severity.low, confidence=Confidence.low, title="t",
            description="d", suggestion=None, rule_id="R001", stage=ReviewStage.style,
        )
        f2 = Finding(
            id="f-002", hunk_id="h-001", file_path="x.py", line_number=1,
            severity=Severity.high, confidence=Confidence.high, title="different",
            description="d", suggestion=None, rule_id="R002", stage=ReviewStage.security,
        )
        assert f1.canonical_bytes() != f2.canonical_bytes()

    def test_sort_keys_compact_format(self, valid_finding):
        raw = valid_finding.canonical_bytes()
        text = raw.decode("utf-8")
        # Compact separators means no spaces after : or ,
        assert ": " not in text or text.count(": ") == 0  # heuristic
        # Verify by re-serializing with same params
        expected = json.dumps(
            valid_finding.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        assert raw == expected


class TestCanonicalHash:
    """Tests for canonical_hash() on _ExemplarBase subclasses."""

    def test_returns_64_char_hex_string(self, valid_finding):
        result = valid_finding.canonical_hash()
        assert isinstance(result, str)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_matches_sha256_of_canonical_bytes(self, valid_finding):
        expected = hashlib.sha256(valid_finding.canonical_bytes()).hexdigest()
        assert valid_finding.canonical_hash() == expected

    def test_deterministic_same_instance(self, valid_finding):
        first = valid_finding.canonical_hash()
        second = valid_finding.canonical_hash()
        assert first == second

    def test_deterministic_equivalent_instances(self):
        kwargs = dict(
            id="f-001", hunk_id="h-001", file_path="x.py", line_number=1,
            severity=Severity.low, confidence=Confidence.low, title="t",
            description="d", suggestion=None, rule_id="R001", stage=ReviewStage.style,
        )
        f1 = Finding(**kwargs)
        f2 = Finding(**kwargs)
        assert f1.canonical_hash() == f2.canonical_hash()

    def test_different_instances_different_hash(self):
        f1 = Finding(
            id="f-001", hunk_id="h-001", file_path="x.py", line_number=1,
            severity=Severity.low, confidence=Confidence.low, title="t",
            description="d", suggestion=None, rule_id="R001", stage=ReviewStage.style,
        )
        f2 = Finding(
            id="f-002", hunk_id="h-002", file_path="y.py", line_number=2,
            severity=Severity.high, confidence=Confidence.high, title="u",
            description="e", suggestion="fix", rule_id="R002", stage=ReviewStage.security,
        )
        assert f1.canonical_hash() != f2.canonical_hash()

    def test_hash_on_nested_model(self, valid_review_report):
        """canonical_hash works on deeply nested models."""
        result = valid_review_report.canonical_hash()
        assert len(result) == 64
        expected = hashlib.sha256(valid_review_report.canonical_bytes()).hexdigest()
        assert result == expected

    def test_canonical_hash_on_trust_score(self, valid_trust_score):
        result = valid_trust_score.canonical_hash()
        assert len(result) == 64
        assert result == hashlib.sha256(valid_trust_score.canonical_bytes()).hexdigest()


# ============================================================================
# Invariant Tests — PACT_KEY, frozen, extra='forbid'
# ============================================================================

class TestExemplarBaseInvariants:
    """Tests for _ExemplarBase class-level invariants."""

    def test_pact_key_present(self):
        assert hasattr(_ExemplarBase, "PACT_KEY")
        assert _ExemplarBase.PACT_KEY == "exemplar.schemas"

    def test_pact_key_inherited(self, valid_finding):
        assert hasattr(valid_finding, "PACT_KEY")
        assert valid_finding.PACT_KEY == "exemplar.schemas"

    def test_all_models_frozen(self, valid_finding, valid_diff_hunk, valid_assessment,
                                valid_trust_score, valid_tessera_seal,
                                valid_review_request, valid_review_report,
                                valid_reviewer_credential, valid_policy_token,
                                valid_chronicler_event, valid_stigmergy_signal,
                                valid_learning_record, valid_kindex_entry):
        """All model instances should reject attribute assignment."""
        instances = [
            valid_finding, valid_diff_hunk, valid_assessment,
            valid_trust_score, valid_tessera_seal,
            valid_review_request, valid_review_report,
            valid_reviewer_credential, valid_policy_token,
            valid_chronicler_event, valid_stigmergy_signal,
            valid_learning_record, valid_kindex_entry,
        ]
        for inst in instances:
            # Get first field name
            field_name = next(iter(inst.model_fields))
            with pytest.raises((ValidationError, TypeError, AttributeError)):
                setattr(inst, field_name, "INVALID_MUTATION")


class TestJsonRoundTrips:
    """Test JSON round-trip invariant across multiple models."""

    def test_diffhunk_roundtrip(self, valid_diff_hunk):
        restored = DiffHunk.model_validate_json(valid_diff_hunk.model_dump_json())
        assert restored == valid_diff_hunk

    def test_finding_roundtrip(self, valid_finding):
        restored = Finding.model_validate_json(valid_finding.model_dump_json())
        assert restored == valid_finding

    def test_assessment_roundtrip(self, valid_assessment):
        restored = Assessment.model_validate_json(valid_assessment.model_dump_json())
        assert restored == valid_assessment

    def test_trust_score_roundtrip(self, valid_trust_score):
        restored = TrustScore.model_validate_json(valid_trust_score.model_dump_json())
        assert restored == valid_trust_score

    def test_tessera_seal_roundtrip(self, valid_tessera_seal):
        restored = TesseraSeal.model_validate_json(valid_tessera_seal.model_dump_json())
        assert restored == valid_tessera_seal

    def test_review_report_roundtrip(self, valid_review_report):
        restored = ReviewReport.model_validate_json(valid_review_report.model_dump_json())
        assert restored == valid_review_report

    def test_review_request_roundtrip(self, valid_review_request):
        restored = ReviewRequest.model_validate_json(valid_review_request.model_dump_json())
        assert restored == valid_review_request

    def test_reviewer_credential_roundtrip(self, valid_reviewer_credential):
        restored = ReviewerCredential.model_validate_json(valid_reviewer_credential.model_dump_json())
        assert restored == valid_reviewer_credential

    def test_policy_token_roundtrip(self, valid_policy_token):
        restored = PolicyToken.model_validate_json(valid_policy_token.model_dump_json())
        assert restored == valid_policy_token

    def test_chronicler_event_roundtrip(self, valid_chronicler_event):
        restored = ChroniclerEvent.model_validate_json(valid_chronicler_event.model_dump_json())
        assert restored == valid_chronicler_event

    def test_stigmergy_signal_roundtrip(self, valid_stigmergy_signal):
        restored = StigmergySignal.model_validate_json(valid_stigmergy_signal.model_dump_json())
        assert restored == valid_stigmergy_signal

    def test_learning_record_roundtrip(self, valid_learning_record):
        restored = LearningRecord.model_validate_json(valid_learning_record.model_dump_json())
        assert restored == valid_learning_record

    def test_kindex_entry_roundtrip(self, valid_kindex_entry):
        restored = KindexEntry.model_validate_json(valid_kindex_entry.model_dump_json())
        assert restored == valid_kindex_entry


# ============================================================================
# Edge Case Tests — Empty Collections and Boundary Values
# ============================================================================

class TestEdgeCases:
    """Edge case tests for boundary conditions."""

    def test_review_request_empty_hunks(self):
        rr = ReviewRequest(
            id="rr-empty",
            source="manual",
            hunks=[],
            file_paths=[],
            created_at="2024-01-01T00:00:00Z",
            metadata={},
        )
        assert rr.hunks == []
        assert rr.file_paths == []

    def test_review_report_empty_findings(self, valid_assessment, valid_trust_score):
        report = ReviewReport(
            id="report-empty",
            review_request_id="rr-001",
            decision=ReviewDecision("pass"),
            findings=[],
            assessments=[valid_assessment],
            confidence=Confidence.high,
            trust_scores=[valid_trust_score],
            conflict_notes=[],
            summary="No issues found.",
            seal=None,
            created_at="2024-06-15T11:00:00Z",
            metadata={},
        )
        assert report.findings == []
        assert report.conflict_notes == []

    def test_assessment_empty_findings(self):
        assessment = Assessment(
            id="a-empty",
            review_request_id="rr-001",
            stage=ReviewStage.style,
            reviewer_id="r1",
            decision=ReviewDecision("pass"),
            findings=[],
            confidence=Confidence.high,
            is_partial=False,
            error_message=None,
            duration_ms=0,
            created_at="2024-01-01T00:00:00Z",
        )
        assert assessment.findings == []
        assert assessment.duration_ms == 0

    def test_diffhunk_empty_lines(self):
        hunk = DiffHunk(
            id="h-empty",
            file_path="empty.py",
            start_line_old=0,
            count_old=0,
            start_line_new=0,
            count_new=0,
            context_before=[],
            added_lines=[],
            removed_lines=[],
            context_after=[],
            raw_header="@@",
            classifications=[],
            language=None,
        )
        assert hunk.added_lines == []
        assert hunk.removed_lines == []

    def test_multiple_classifications_on_hunk(self):
        hunk = DiffHunk(
            id="h-multi",
            file_path="config.py",
            start_line_old=1,
            count_old=1,
            start_line_new=1,
            count_new=1,
            context_before=[],
            added_lines=["SECRET=abc"],
            removed_lines=[],
            context_after=[],
            raw_header="@@",
            classifications=[ClassificationLabel.secret, ClassificationLabel.pii],
            language="python",
        )
        assert len(hunk.classifications) == 2
        assert ClassificationLabel.secret in hunk.classifications
        assert ClassificationLabel.pii in hunk.classifications

    def test_model_dump_returns_dict(self, valid_finding):
        dumped = valid_finding.model_dump()
        assert isinstance(dumped, dict)
        assert "id" in dumped
        assert "severity" in dumped

    def test_model_validate_from_dict(self, valid_finding):
        dumped = valid_finding.model_dump()
        restored = Finding.model_validate(dumped)
        assert restored == valid_finding
