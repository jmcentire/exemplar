"""
Adversarial hidden acceptance tests for Data Models & Schemas.
These tests detect implementations that pass visible tests through shortcuts
(hardcoded returns, missing validation, incomplete invariants).
"""
import hashlib
import json

import pytest

from exemplar.schemas import (
    _ExemplarBase,
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
    ReviewerCredential,
    ReviewReport,
    ReviewRequest,
    ReviewStage,
    Severity,
    StigmergySignal,
    StigmergyVerb,
    TesseraSeal,
    TrustScore,
    canonical_hash,
    confidence_rank,
    learner_phase_rank,
    severity_rank,
    validate_iso_timestamp,
)


# ---- Helpers ----

def _make_diffhunk(**overrides):
    defaults = dict(
        id="hunk-1",
        file_path="src/main.py",
        start_line_old=10,
        count_old=5,
        start_line_new=10,
        count_new=7,
        context_before=["# context"],
        added_lines=["+ new line"],
        removed_lines=["- old line"],
        context_after=["# after"],
        raw_header="@@ -10,5 +10,7 @@",
        classifications=[ClassificationLabel.public],
        language="python",
    )
    defaults.update(overrides)
    return DiffHunk(**defaults)


def _make_finding(**overrides):
    defaults = dict(
        id="finding-1",
        hunk_id="hunk-1",
        file_path="src/main.py",
        line_number=42,
        severity=Severity.high,
        confidence=Confidence.high,
        title="Test finding",
        description="A test finding",
        suggestion="Fix it",
        rule_id="RULE-001",
        stage=ReviewStage.security,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_assessment(**overrides):
    defaults = dict(
        id="assess-1",
        review_request_id="rr-1",
        stage=ReviewStage.security,
        reviewer_id="reviewer-1",
        decision=ReviewDecision.warn,
        findings=[],
        confidence=Confidence.medium,
        is_partial=False,
        error_message=None,
        duration_ms=150,
        created_at="2024-01-01T00:00:00Z",
    )
    defaults.update(overrides)
    return Assessment(**defaults)


def _make_trust_score(**overrides):
    defaults = dict(
        reviewer_id="reviewer-1",
        stage=ReviewStage.security,
        weight=0.75,
        accepted_count=10,
        dismissed_count=2,
        updated_at="2024-01-01T00:00:00Z",
    )
    defaults.update(overrides)
    return TrustScore(**defaults)


def _make_tessera_seal(**overrides):
    defaults = dict(
        content_hash="abc123",
        previous_hash=None,
        chain_hash="def456",
        sealed_at="2024-01-01T00:00:00Z",
        sealer_id="sealer-1",
    )
    defaults.update(overrides)
    return TesseraSeal(**defaults)


def _make_review_report(**overrides):
    defaults = dict(
        id="report-1",
        review_request_id="rr-1",
        decision=ReviewDecision.warn,
        findings=[],
        assessments=[],
        confidence=Confidence.medium,
        trust_scores=[],
        conflict_notes=[],
        summary="Summary",
        seal=None,
        created_at="2024-01-01T00:00:00Z",
        metadata={},
    )
    defaults.update(overrides)
    return ReviewReport(**defaults)


def _make_reviewer_credential(**overrides):
    defaults = dict(
        reviewer_id="rev-1",
        display_name="Test Reviewer",
        stage=ReviewStage.security,
        public_key_hex="aabbccdd",
        created_at="2024-01-01T00:00:00Z",
        is_active=True,
    )
    defaults.update(overrides)
    return ReviewerCredential(**defaults)


def _make_policy_token(**overrides):
    defaults = dict(
        token_id="tok-1",
        reviewer_id="rev-1",
        allowed_file_patterns=["*.py"],
        denied_file_patterns=["*.secret"],
        allowed_classifications=[ClassificationLabel.public],
        max_severity=Severity.high,
        issued_at="2024-01-01T00:00:00Z",
        expires_at=None,
    )
    defaults.update(overrides)
    return PolicyToken(**defaults)


def _make_chronicler_event(**overrides):
    defaults = dict(
        event_id="evt-1",
        event_type=ChroniclerEventType("review.started"),
        review_request_id="rr-1",
        timestamp="2024-01-01T00:00:00Z",
        stage=None,
        reviewer_id=None,
        payload={},
        message="Review started",
    )
    defaults.update(overrides)
    return ChroniclerEvent(**defaults)


def _make_stigmergy_signal(**overrides):
    defaults = dict(
        signal_id="sig-1",
        pattern_key="pattern.test",
        description="A test pattern",
        occurrences=5,
        first_seen_at="2024-01-01T00:00:00Z",
        last_seen_at="2024-01-02T00:00:00Z",
        reviewer_id=None,
        stage=None,
        metadata={},
    )
    defaults.update(overrides)
    return StigmergySignal(**defaults)


def _make_learning_record(**overrides):
    defaults = dict(
        record_id="lr-1",
        finding_id="finding-1",
        reviewer_id="rev-1",
        stage=ReviewStage.security,
        rule_id="RULE-001",
        severity=Severity.high,
        accepted=True,
        human_comment=None,
        recorded_at="2024-01-01T00:00:00Z",
    )
    defaults.update(overrides)
    return LearningRecord(**defaults)


def _make_kindex_entry(**overrides):
    defaults = dict(
        key="kindex-1",
        kind="review",
        summary="A review entry",
        data={"file": "main.py"},
        tags=["test"],
        created_at="2024-01-01T00:00:00Z",
        updated_at="2024-01-02T00:00:00Z",
    )
    defaults.update(overrides)
    return KindexEntry(**defaults)


def _make_review_request(**overrides):
    defaults = dict(
        id="rr-1",
        source="github",
        hunks=[],
        file_paths=[],
        created_at="2024-01-01T00:00:00Z",
        metadata={},
    )
    defaults.update(overrides)
    return ReviewRequest(**defaults)


def _make_pipeline_result(**overrides):
    rr = _make_review_request()
    report = _make_review_report()
    defaults = dict(
        review_request=rr,
        assessments=[],
        report=report,
        events=[],
        formatted_output="{}",
        output_format=OutputFormat.json,
        exit_code=0,
    )
    defaults.update(overrides)
    return PipelineResult(**defaults)


# ---- Enum member count tests ----

class TestGoodhartEnumCounts:
    def test_goodhart_severity_member_count(self):
        """Severity enum should have exactly 5 members — no extra or missing members"""
        assert len(Severity) == 5

    def test_goodhart_confidence_member_count(self):
        """Confidence enum should have exactly 3 members"""
        assert len(Confidence) == 3

    def test_goodhart_review_stage_member_count(self):
        """ReviewStage enum should have exactly 4 members"""
        assert len(ReviewStage) == 4

    def test_goodhart_chronicler_event_type_member_count(self):
        """ChroniclerEventType enum should have exactly 9 members"""
        assert len(ChroniclerEventType) == 9

    def test_goodhart_learner_phase_member_count(self):
        """LearnerPhase enum should have exactly 3 members"""
        assert len(LearnerPhase) == 3

    def test_goodhart_review_decision_member_count(self):
        """ReviewDecision enum should have exactly 3 members"""
        assert len(ReviewDecision) == 3

    def test_goodhart_classification_label_member_count(self):
        """ClassificationLabel enum should have exactly 4 members"""
        assert len(ClassificationLabel) == 4

    def test_goodhart_stigmergy_verb_member_count(self):
        """StigmergyVerb enum should have exactly 4 members"""
        assert len(StigmergyVerb) == 4

    def test_goodhart_output_format_member_count(self):
        """OutputFormat enum should have exactly 3 members"""
        assert len(OutputFormat) == 3

    def test_goodhart_cli_exit_code_member_count(self):
        """CliExitCode enum should have exactly 4 members"""
        assert len(CliExitCode) == 4


# ---- StrEnum / IntEnum type tests ----

class TestGoodhartEnumTypes:
    def test_goodhart_cli_exit_code_is_int(self):
        """CliExitCode should be an IntEnum — members are int instances"""
        for member in CliExitCode:
            assert isinstance(member, int), f"{member} should be int instance"

    def test_goodhart_review_stage_is_str(self):
        """ReviewStage members should be str instances (StrEnum)"""
        for member in ReviewStage:
            assert isinstance(member, str), f"{member} should be str"

    def test_goodhart_review_decision_is_str(self):
        """ReviewDecision members should be str instances (StrEnum)"""
        for member in ReviewDecision:
            assert isinstance(member, str), f"{member} should be str"

    def test_goodhart_classification_label_is_str(self):
        """ClassificationLabel members should be str instances (StrEnum)"""
        for member in ClassificationLabel:
            assert isinstance(member, str)

    def test_goodhart_stigmergy_verb_is_str(self):
        """StigmergyVerb members should be str instances (StrEnum)"""
        for member in StigmergyVerb:
            assert isinstance(member, str)

    def test_goodhart_output_format_is_str(self):
        """OutputFormat members should be str instances (StrEnum)"""
        for member in OutputFormat:
            assert isinstance(member, str)

    def test_goodhart_chronicler_event_type_is_str(self):
        """ChroniclerEventType members should be str instances (StrEnum)"""
        for member in ChroniclerEventType:
            assert isinstance(member, str)

    def test_goodhart_learner_phase_is_str(self):
        """LearnerPhase members should be str instances (StrEnum)"""
        for member in LearnerPhase:
            assert isinstance(member, str)


# ---- Rank function input validation ----

class TestGoodhartRankInputValidation:
    def test_goodhart_severity_rank_none(self):
        """severity_rank should reject None"""
        with pytest.raises(Exception):
            severity_rank(None)

    def test_goodhart_severity_rank_plain_string(self):
        """severity_rank should reject plain string 'critical' not an enum member"""
        with pytest.raises(Exception):
            severity_rank("critical")

    def test_goodhart_severity_rank_int_input(self):
        """severity_rank should reject integer input"""
        with pytest.raises(Exception):
            severity_rank(4)

    def test_goodhart_confidence_rank_none(self):
        """confidence_rank should reject None"""
        with pytest.raises(Exception):
            confidence_rank(None)

    def test_goodhart_confidence_rank_plain_string(self):
        """confidence_rank should reject plain string 'high'"""
        with pytest.raises(Exception):
            confidence_rank("high")

    def test_goodhart_learner_phase_rank_plain_string(self):
        """learner_phase_rank should reject plain string 'shadow'"""
        with pytest.raises(Exception):
            learner_phase_rank("shadow")

    def test_goodhart_learner_phase_rank_none(self):
        """learner_phase_rank should reject None"""
        with pytest.raises(Exception):
            learner_phase_rank(None)


# ---- Rank function return type and range ----

class TestGoodhartRankProperties:
    def test_goodhart_confidence_rank_return_type(self):
        """confidence_rank should return int for all valid members"""
        for c in Confidence:
            assert isinstance(confidence_rank(c), int)

    def test_goodhart_confidence_rank_range(self):
        """confidence_rank values should be in [0, 2]"""
        for c in Confidence:
            assert 0 <= confidence_rank(c) <= 2

    def test_goodhart_learner_phase_rank_return_type(self):
        """learner_phase_rank should return int for all valid members"""
        for p in LearnerPhase:
            assert isinstance(learner_phase_rank(p), int)

    def test_goodhart_learner_phase_rank_range(self):
        """learner_phase_rank values should be in [0, 3]"""
        for p in LearnerPhase:
            assert 0 <= learner_phase_rank(p) <= 3

    def test_goodhart_severity_rank_unique(self):
        """severity_rank should return distinct values for all severity levels"""
        ranks = [severity_rank(s) for s in Severity]
        assert len(set(ranks)) == len(ranks)

    def test_goodhart_confidence_rank_unique(self):
        """confidence_rank should return distinct values for all confidence levels"""
        ranks = [confidence_rank(c) for c in Confidence]
        assert len(set(ranks)) == len(ranks)

    def test_goodhart_learner_phase_rank_unique(self):
        """learner_phase_rank should return distinct values for all phases"""
        ranks = [learner_phase_rank(p) for p in LearnerPhase]
        assert len(set(ranks)) == len(ranks)


# ---- validate_iso_timestamp ----

class TestGoodhartIsoTimestamp:
    def test_goodhart_iso_returns_unchanged_with_offset(self):
        """validate_iso_timestamp must return exact input with non-UTC offset"""
        v = "2024-06-15T08:30:00+05:30"
        assert validate_iso_timestamp(v) == v

    def test_goodhart_iso_microseconds(self):
        """validate_iso_timestamp should accept microsecond precision"""
        v = "2024-01-15T12:30:45.123456"
        assert validate_iso_timestamp(v) == v

    def test_goodhart_iso_negative_offset(self):
        """validate_iso_timestamp should accept negative UTC offsets"""
        v = "2024-03-01T00:00:00-08:00"
        assert validate_iso_timestamp(v) == v

    def test_goodhart_iso_rejects_random_text(self):
        """validate_iso_timestamp should reject arbitrary non-date text"""
        with pytest.raises(Exception):
            validate_iso_timestamp("hello-world")

    def test_goodhart_iso_rejects_whitespace(self):
        """validate_iso_timestamp should reject whitespace-only strings"""
        with pytest.raises(Exception):
            validate_iso_timestamp("   ")

    def test_goodhart_iso_midnight(self):
        """validate_iso_timestamp should accept midnight time"""
        v = "2024-12-31T00:00:00"
        assert validate_iso_timestamp(v) == v

    def test_goodhart_iso_rejects_partial_date(self):
        """validate_iso_timestamp should reject incomplete date like '2024-13'"""
        with pytest.raises(Exception):
            validate_iso_timestamp("2024-13")


# ---- PACT_KEY ----

class TestGoodhartPactKey:
    def test_goodhart_pact_key_exact_value(self):
        """PACT_KEY should have exact value 'exemplar.schemas'"""
        assert _ExemplarBase.PACT_KEY == "exemplar.schemas"

    def test_goodhart_pact_key_inherited_by_diffhunk(self):
        """DiffHunk should inherit PACT_KEY from _ExemplarBase"""
        assert DiffHunk.PACT_KEY == "exemplar.schemas"

    def test_goodhart_pact_key_inherited_by_finding(self):
        """Finding should inherit PACT_KEY"""
        assert Finding.PACT_KEY == "exemplar.schemas"

    def test_goodhart_pact_key_inherited_by_review_report(self):
        """ReviewReport should inherit PACT_KEY"""
        assert ReviewReport.PACT_KEY == "exemplar.schemas"

    def test_goodhart_pact_key_inherited_by_trust_score(self):
        """TrustScore should inherit PACT_KEY"""
        assert TrustScore.PACT_KEY == "exemplar.schemas"

    def test_goodhart_pact_key_inherited_by_kindex(self):
        """KindexEntry should inherit PACT_KEY"""
        assert KindexEntry.PACT_KEY == "exemplar.schemas"


# ---- Inheritance ----

class TestGoodhartInheritance:
    def test_goodhart_all_models_inherit_exemplar_base(self):
        """All domain model classes should be subclasses of _ExemplarBase"""
        model_classes = [
            DiffHunk, ReviewRequest, Finding, Assessment, TrustScore,
            TesseraSeal, ReviewReport, ReviewerCredential, PolicyToken,
            ChroniclerEvent, StigmergySignal, LearningRecord, KindexEntry,
            PipelineResult,
        ]
        for cls in model_classes:
            assert issubclass(cls, _ExemplarBase), f"{cls.__name__} should inherit from _ExemplarBase"


# ---- Extra forbid on multiple models ----

class TestGoodhartExtraForbid:
    def test_goodhart_finding_extra_forbid(self):
        """Finding should forbid extra fields"""
        with pytest.raises(Exception):
            _make_finding(extra_unknown_field="bad")

    def test_goodhart_assessment_extra_forbid(self):
        """Assessment should forbid extra fields"""
        with pytest.raises(Exception):
            _make_assessment(extra_unknown_field="bad")

    def test_goodhart_trust_score_extra_forbid(self):
        """TrustScore should forbid extra fields"""
        with pytest.raises(Exception):
            _make_trust_score(extra_unknown_field="bad")

    def test_goodhart_review_report_extra_forbid(self):
        """ReviewReport should forbid extra fields"""
        with pytest.raises(Exception):
            _make_review_report(extra_unknown_field="bad")

    def test_goodhart_review_request_extra_forbid(self):
        """ReviewRequest should forbid extra fields"""
        with pytest.raises(Exception):
            _make_review_request(extra_unknown_field="bad")

    def test_goodhart_reviewer_credential_extra_forbid(self):
        """ReviewerCredential should forbid extra fields"""
        with pytest.raises(Exception):
            _make_reviewer_credential(extra_unknown_field="bad")

    def test_goodhart_policy_token_extra_forbid(self):
        """PolicyToken should forbid extra fields"""
        with pytest.raises(Exception):
            _make_policy_token(extra_unknown_field="bad")

    def test_goodhart_chronicler_event_extra_forbid(self):
        """ChroniclerEvent should forbid extra fields"""
        with pytest.raises(Exception):
            _make_chronicler_event(extra_unknown_field="bad")

    def test_goodhart_stigmergy_signal_extra_forbid(self):
        """StigmergySignal should forbid extra fields"""
        with pytest.raises(Exception):
            _make_stigmergy_signal(extra_unknown_field="bad")

    def test_goodhart_learning_record_extra_forbid(self):
        """LearningRecord should forbid extra fields"""
        with pytest.raises(Exception):
            _make_learning_record(extra_unknown_field="bad")

    def test_goodhart_kindex_entry_extra_forbid(self):
        """KindexEntry should forbid extra fields"""
        with pytest.raises(Exception):
            _make_kindex_entry(extra_unknown_field="bad")


# ---- Frozen on multiple models ----

class TestGoodhartFrozen:
    def test_goodhart_finding_frozen(self):
        """Finding should be immutable"""
        f = _make_finding()
        with pytest.raises(Exception):
            f.title = "changed"

    def test_goodhart_assessment_frozen(self):
        """Assessment should be immutable"""
        a = _make_assessment()
        with pytest.raises(Exception):
            a.decision = ReviewDecision.block

    def test_goodhart_trust_score_frozen(self):
        """TrustScore should be immutable"""
        ts = _make_trust_score()
        with pytest.raises(Exception):
            ts.weight = 0.5

    def test_goodhart_tessera_seal_frozen(self):
        """TesseraSeal should be immutable"""
        s = _make_tessera_seal()
        with pytest.raises(Exception):
            s.content_hash = "changed"

    def test_goodhart_kindex_entry_frozen(self):
        """KindexEntry should be immutable"""
        k = _make_kindex_entry()
        with pytest.raises(Exception):
            k.key = "changed"

    def test_goodhart_learning_record_frozen(self):
        """LearningRecord should be immutable"""
        lr = _make_learning_record()
        with pytest.raises(Exception):
            lr.accepted = False

    def test_goodhart_reviewer_credential_frozen(self):
        """ReviewerCredential should be immutable"""
        rc = _make_reviewer_credential()
        with pytest.raises(Exception):
            rc.is_active = False

    def test_goodhart_policy_token_frozen(self):
        """PolicyToken should be immutable"""
        pt = _make_policy_token()
        with pytest.raises(Exception):
            pt.token_id = "changed"

    def test_goodhart_review_report_frozen(self):
        """ReviewReport should be immutable"""
        rr = _make_review_report()
        with pytest.raises(Exception):
            rr.summary = "changed"

    def test_goodhart_chronicler_event_frozen(self):
        """ChroniclerEvent should be immutable"""
        ce = _make_chronicler_event()
        with pytest.raises(Exception):
            ce.message = "changed"

    def test_goodhart_stigmergy_signal_frozen(self):
        """StigmergySignal should be immutable"""
        ss = _make_stigmergy_signal()
        with pytest.raises(Exception):
            ss.occurrences = 99


# ---- TrustScore weight boundary adjacency ----

class TestGoodhartTrustScoreBoundaries:
    def test_goodhart_trust_score_weight_slightly_negative(self):
        """TrustScore should reject weight=-0.001 just below range"""
        with pytest.raises(Exception):
            _make_trust_score(weight=-0.001)

    def test_goodhart_trust_score_weight_slightly_above(self):
        """TrustScore should reject weight=1.001 just above range"""
        with pytest.raises(Exception):
            _make_trust_score(weight=1.001)

    def test_goodhart_trust_score_weight_mid_range(self):
        """TrustScore should accept typical mid-range weight 0.5"""
        ts = _make_trust_score(weight=0.5)
        assert ts.weight == 0.5

    def test_goodhart_trust_score_weight_near_zero(self):
        """TrustScore should accept weight very close to zero (0.0001)"""
        ts = _make_trust_score(weight=0.0001)
        assert ts.weight == 0.0001

    def test_goodhart_trust_score_weight_near_one(self):
        """TrustScore should accept weight very close to one (0.9999)"""
        ts = _make_trust_score(weight=0.9999)
        assert ts.weight == 0.9999

    def test_goodhart_trust_score_large_negative(self):
        """TrustScore should reject large negative weight"""
        with pytest.raises(Exception):
            _make_trust_score(weight=-100.0)

    def test_goodhart_trust_score_large_positive(self):
        """TrustScore should reject large positive weight"""
        with pytest.raises(Exception):
            _make_trust_score(weight=100.0)


# ---- canonical_bytes properties ----

class TestGoodhartCanonicalBytes:
    def test_goodhart_canonical_bytes_sorted_keys(self):
        """canonical_bytes should produce JSON with keys in sorted order"""
        ts = _make_trust_score()
        data = json.loads(ts.canonical_bytes().decode("utf-8"))
        keys = list(data.keys())
        assert keys == sorted(keys), "Keys should be sorted"

    def test_goodhart_canonical_bytes_compact_separators(self):
        """canonical_bytes should use compact separators (no spaces after : or ,)"""
        ts = _make_trust_score()
        raw = ts.canonical_bytes().decode("utf-8")
        # Compact JSON should not have ": " or ", " patterns
        assert ": " not in raw, "Should use compact separators without spaces"
        assert ", " not in raw, "Should use compact separators without spaces"

    def test_goodhart_canonical_bytes_nested_model(self):
        """canonical_bytes should work correctly on models with nested sub-models"""
        finding = _make_finding()
        assessment = _make_assessment(findings=[finding])
        raw = assessment.canonical_bytes()
        assert isinstance(raw, bytes)
        parsed = json.loads(raw.decode("utf-8"))
        assert isinstance(parsed, dict)
        assert "findings" in parsed
        assert len(parsed["findings"]) == 1

    def test_goodhart_canonical_bytes_model_dump_equivalence(self):
        """json.loads(canonical_bytes()) should equal model_dump(mode='json')"""
        for instance in [
            _make_trust_score(),
            _make_finding(),
            _make_diffhunk(),
            _make_kindex_entry(),
        ]:
            parsed = json.loads(instance.canonical_bytes().decode("utf-8"))
            dumped = instance.model_dump(mode="json")
            assert parsed == dumped, f"Mismatch for {type(instance).__name__}"

    def test_goodhart_canonical_bytes_utf8_encoding(self):
        """canonical_bytes output should be valid UTF-8"""
        instances = [
            _make_trust_score(),
            _make_finding(),
            _make_kindex_entry(),
        ]
        for inst in instances:
            raw = inst.canonical_bytes()
            # Should not raise
            raw.decode("utf-8")

    def test_goodhart_canonical_bytes_deterministic_across_model_types(self):
        """canonical_bytes called twice on different model types should both be deterministic"""
        for factory in [_make_trust_score, _make_finding, _make_diffhunk, _make_kindex_entry]:
            inst = factory()
            assert inst.canonical_bytes() == inst.canonical_bytes()


# ---- canonical_hash properties ----

class TestGoodhartCanonicalHash:
    def test_goodhart_canonical_hash_lowercase_hex(self):
        """canonical_hash must return only lowercase hex characters"""
        for factory in [_make_trust_score, _make_finding, _make_diffhunk]:
            h = factory().canonical_hash()
            assert h == h.lower()
            assert all(c in "0123456789abcdef" for c in h)

    def test_goodhart_canonical_hash_length_multiple_models(self):
        """canonical_hash should return 64 chars for all model types"""
        for factory in [_make_trust_score, _make_finding, _make_diffhunk,
                        _make_kindex_entry, _make_assessment, _make_tessera_seal]:
            h = factory().canonical_hash()
            assert len(h) == 64, f"Hash length should be 64 for {factory.__name__}"

    def test_goodhart_canonical_hash_matches_sha256_multiple(self):
        """canonical_hash should equal SHA-256 of canonical_bytes for various model types"""
        for factory in [_make_trust_score, _make_finding, _make_diffhunk,
                        _make_kindex_entry, _make_learning_record]:
            inst = factory()
            expected = hashlib.sha256(inst.canonical_bytes()).hexdigest()
            assert inst.canonical_hash() == expected

    def test_goodhart_canonical_hash_changes_with_single_field(self):
        """Changing one field should produce a different hash"""
        f1 = _make_finding(title="Title A")
        f2 = _make_finding(title="Title B")
        assert f1.canonical_hash() != f2.canonical_hash()

    def test_goodhart_canonical_hash_changes_with_numeric_field(self):
        """Changing a numeric field should produce a different hash"""
        ts1 = _make_trust_score(accepted_count=10)
        ts2 = _make_trust_score(accepted_count=11)
        assert ts1.canonical_hash() != ts2.canonical_hash()


# ---- JSON round-trip for models not covered by visible tests ----

class TestGoodhartJsonRoundtrip:
    def test_goodhart_json_roundtrip_trust_score(self):
        """TrustScore should survive JSON round-trip"""
        ts = _make_trust_score()
        assert TrustScore.model_validate_json(ts.model_dump_json()) == ts

    def test_goodhart_json_roundtrip_reviewer_credential(self):
        """ReviewerCredential should survive JSON round-trip"""
        rc = _make_reviewer_credential()
        assert ReviewerCredential.model_validate_json(rc.model_dump_json()) == rc

    def test_goodhart_json_roundtrip_policy_token(self):
        """PolicyToken should survive JSON round-trip"""
        pt = _make_policy_token()
        assert PolicyToken.model_validate_json(pt.model_dump_json()) == pt

    def test_goodhart_json_roundtrip_chronicler_event(self):
        """ChroniclerEvent should survive JSON round-trip"""
        ce = _make_chronicler_event()
        assert ChroniclerEvent.model_validate_json(ce.model_dump_json()) == ce

    def test_goodhart_json_roundtrip_stigmergy_signal(self):
        """StigmergySignal should survive JSON round-trip"""
        ss = _make_stigmergy_signal()
        assert StigmergySignal.model_validate_json(ss.model_dump_json()) == ss

    def test_goodhart_json_roundtrip_learning_record(self):
        """LearningRecord should survive JSON round-trip"""
        lr = _make_learning_record()
        assert LearningRecord.model_validate_json(lr.model_dump_json()) == lr

    def test_goodhart_json_roundtrip_kindex_entry(self):
        """KindexEntry should survive JSON round-trip"""
        ke = _make_kindex_entry()
        assert KindexEntry.model_validate_json(ke.model_dump_json()) == ke

    def test_goodhart_json_roundtrip_tessera_seal(self):
        """TesseraSeal should survive JSON round-trip"""
        ts = _make_tessera_seal()
        assert TesseraSeal.model_validate_json(ts.model_dump_json()) == ts

    def test_goodhart_json_roundtrip_review_request(self):
        """ReviewRequest with nested hunks should survive JSON round-trip"""
        hunk = _make_diffhunk()
        rr = _make_review_request(hunks=[hunk], file_paths=["src/main.py"])
        assert ReviewRequest.model_validate_json(rr.model_dump_json()) == rr

    def test_goodhart_json_roundtrip_pipeline_result(self):
        """PipelineResult should survive JSON round-trip"""
        pr = _make_pipeline_result()
        assert PipelineResult.model_validate_json(pr.model_dump_json()) == pr


# ---- Optional field tests ----

class TestGoodhartOptionalFields:
    def test_goodhart_assessment_optional_error_message(self):
        """Assessment allows None for optional error_message"""
        a = _make_assessment(error_message=None)
        assert a.error_message is None

    def test_goodhart_tessera_seal_optional_previous_hash(self):
        """TesseraSeal allows None for previous_hash (first in chain)"""
        s = _make_tessera_seal(previous_hash=None)
        assert s.previous_hash is None

    def test_goodhart_review_report_optional_seal(self):
        """ReviewReport allows None seal (unsealed report)"""
        r = _make_review_report(seal=None)
        assert r.seal is None

    def test_goodhart_policy_token_optional_expires_at(self):
        """PolicyToken allows None for expires_at (non-expiring)"""
        pt = _make_policy_token(expires_at=None)
        assert pt.expires_at is None

    def test_goodhart_chronicler_event_optional_stage_and_reviewer(self):
        """ChroniclerEvent allows None for both stage and reviewer_id"""
        ce = _make_chronicler_event(stage=None, reviewer_id=None)
        assert ce.stage is None
        assert ce.reviewer_id is None

    def test_goodhart_learning_record_optional_human_comment(self):
        """LearningRecord allows None for human_comment"""
        lr = _make_learning_record(human_comment=None)
        assert lr.human_comment is None

    def test_goodhart_stigmergy_signal_optional_reviewer_and_stage(self):
        """StigmergySignal allows None for reviewer_id and stage"""
        ss = _make_stigmergy_signal(reviewer_id=None, stage=None)
        assert ss.reviewer_id is None
        assert ss.stage is None


# ---- Empty list fields ----

class TestGoodhartEmptyLists:
    def test_goodhart_review_report_empty_lists(self):
        """ReviewReport should accept empty lists for all list fields"""
        r = _make_review_report(
            findings=[], assessments=[], trust_scores=[], conflict_notes=[]
        )
        assert r.findings == []
        assert r.assessments == []
        assert r.trust_scores == []
        assert r.conflict_notes == []

    def test_goodhart_assessment_empty_findings(self):
        """Assessment should accept empty findings list"""
        a = _make_assessment(findings=[])
        assert a.findings == []

    def test_goodhart_diffhunk_empty_lines(self):
        """DiffHunk should accept empty line lists"""
        h = _make_diffhunk(
            context_before=[], added_lines=[], removed_lines=[], context_after=[]
        )
        assert h.context_before == []
        assert h.added_lines == []
        assert h.removed_lines == []
        assert h.context_after == []

    def test_goodhart_review_request_empty_hunks(self):
        """ReviewRequest should accept empty hunks list"""
        rr = _make_review_request(hunks=[], file_paths=[])
        assert rr.hunks == []
        assert rr.file_paths == []


# ---- Enum validation in model fields ----

class TestGoodhartEnumFieldValidation:
    def test_goodhart_diffhunk_invalid_classification(self):
        """DiffHunk should reject invalid classification labels"""
        with pytest.raises(Exception):
            _make_diffhunk(classifications=["not_a_label"])

    def test_goodhart_finding_invalid_severity(self):
        """Finding should reject invalid severity values"""
        with pytest.raises(Exception):
            _make_finding(severity="extreme")

    def test_goodhart_finding_invalid_stage(self):
        """Finding should reject invalid stage values"""
        with pytest.raises(Exception):
            _make_finding(stage="testing")

    def test_goodhart_assessment_invalid_decision(self):
        """Assessment should reject invalid decision values"""
        with pytest.raises(Exception):
            _make_assessment(decision="maybe")

    def test_goodhart_finding_invalid_confidence(self):
        """Finding should reject invalid confidence values"""
        with pytest.raises(Exception):
            _make_finding(confidence="super_high")


# ---- Hashable models ----

class TestGoodhartHashable:
    def test_goodhart_multiple_model_types_hashable(self):
        """Multiple frozen model types should be hashable"""
        instances = [
            _make_diffhunk(),
            _make_trust_score(),
            _make_tessera_seal(),
            _make_kindex_entry(),
            _make_learning_record(),
            _make_reviewer_credential(),
        ]
        for inst in instances:
            # Should not raise
            h = hash(inst)
            assert isinstance(h, int)

    def test_goodhart_equal_instances_same_hash(self):
        """Two equal instances should have the same hash value"""
        f1 = _make_finding()
        f2 = _make_finding()
        assert f1 == f2
        assert hash(f1) == hash(f2)


# ---- DiffHunk with all classification labels ----

class TestGoodhartDiffHunkClassifications:
    def test_goodhart_diffhunk_all_classification_labels(self):
        """DiffHunk should accept all valid ClassificationLabel values"""
        all_labels = list(ClassificationLabel)
        h = _make_diffhunk(classifications=all_labels)
        assert len(h.classifications) == len(ClassificationLabel)


# ---- __all__ exports ----

class TestGoodhartAllExports:
    def test_goodhart_all_exports(self):
        """Module __all__ should contain all public types from the contract"""
        import exemplar.schemas as mod
        expected_names = [
            "Severity", "Confidence", "ReviewStage", "ReviewDecision",
            "ClassificationLabel", "ChroniclerEventType", "LearnerPhase",
            "StigmergyVerb", "CliExitCode", "OutputFormat",
            "DiffHunk", "ReviewRequest", "Finding", "Assessment",
            "TrustScore", "TesseraSeal", "ReviewReport",
            "ReviewerCredential", "PolicyToken", "ChroniclerEvent",
            "StigmergySignal", "LearningRecord", "KindexEntry",
            "PipelineResult",
        ]
        module_all = getattr(mod, "__all__", dir(mod))
        for name in expected_names:
            assert name in module_all, f"{name} should be in __all__"


# ---- Verify severity_rank specific values not hardcoded ----

class TestGoodhartRankSpecificValues:
    def test_goodhart_severity_rank_info_is_zero(self):
        """severity_rank for info should be 0 (the lowest)"""
        assert severity_rank(Severity.info) == 0

    def test_goodhart_severity_rank_critical_is_four(self):
        """severity_rank for critical should be 4 (the highest)"""
        assert severity_rank(Severity.critical) == 4

    def test_goodhart_severity_rank_low_is_one(self):
        """severity_rank for low should be 1"""
        assert severity_rank(Severity.low) == 1

    def test_goodhart_severity_rank_medium_is_two(self):
        """severity_rank for medium should be 2"""
        assert severity_rank(Severity.medium) == 2

    def test_goodhart_severity_rank_high_is_three(self):
        """severity_rank for high should be 3"""
        assert severity_rank(Severity.high) == 3

    def test_goodhart_confidence_rank_low_is_zero(self):
        """confidence_rank for low should be 0"""
        assert confidence_rank(Confidence.low) == 0

    def test_goodhart_confidence_rank_medium_is_one(self):
        """confidence_rank for medium should be 1"""
        assert confidence_rank(Confidence.medium) == 1

    def test_goodhart_confidence_rank_high_is_two(self):
        """confidence_rank for high should be 2"""
        assert confidence_rank(Confidence.high) == 2


# ---- LearnerPhase specific member values ----

class TestGoodhartLearnerPhaseValues:
    def test_goodhart_learner_phase_shadow_value(self):
        """LearnerPhase.shadow should have string value 'shadow'"""
        assert LearnerPhase.shadow == "shadow"

    def test_goodhart_learner_phase_canary_value(self):
        """LearnerPhase.canary should have string value 'canary'"""
        assert LearnerPhase.canary == "canary"

    def test_goodhart_learner_phase_primary_value(self):
        """LearnerPhase.primary should have string value 'primary'"""
        assert LearnerPhase.primary == "primary"

    def test_goodhart_learner_phase_rank_ordering_specific(self):
        """learner_phase_rank should have shadow < canary < primary"""
        assert learner_phase_rank(LearnerPhase.shadow) < learner_phase_rank(LearnerPhase.canary)
        assert learner_phase_rank(LearnerPhase.canary) < learner_phase_rank(LearnerPhase.primary)


# ---- ChroniclerEventType specific values ----

class TestGoodhartChroniclerEventTypeValues:
    def test_goodhart_chronicler_event_type_dotted_values(self):
        """ChroniclerEventType members should have dotted string values"""
        expected_values = {
            "review.started", "stage.started", "stage.complete",
            "assessment.merged", "report.sealed", "review.complete",
            "policy.violation", "pattern.detected", "learning.recorded",
        }
        actual_values = {m.value for m in ChroniclerEventType}
        assert actual_values == expected_values
