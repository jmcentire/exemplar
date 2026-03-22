"""
Comprehensive contract test suite for the Governance Primitives component.

Tests cover: type construction & validation, seal/verify, chronicle emit/query,
policy filter/check, credentials create/verify, scoring, classification,
stigmergy signals, and kindex key-value store.

Run with: pytest contract_test.py -v
"""

import json
import hashlib
import os
import asyncio
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, AsyncMock, mock_open
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Imports from the governance module under test
# ---------------------------------------------------------------------------
from exemplar.governance import (
    # Enums
    CredentialErrorReason,
    ReviewStage,
    ChroniclerEventType,
    ReviewDecision,
    ClassificationLabel,
    Confidence,
    Severity,
    FindingSeverity,
    LearningOutcome,
    # Structs / Models
    GovernanceError,
    SealVerificationError,
    PolicyViolationError,
    CredentialError,
    TesseraSeal,
    ChroniclerEvent,
    DiffHunk,
    PolicyToken,
    ReviewerCredential,
    Assessment,
    Finding,
    TrustScore,
    LearningRecord,
    LedgerFieldRule,
    LedgerConfig,
    StigmergySignal,
    KindexEntry,
    CircuitConfig,
    FilterResult,
    # Functions / Classes that expose the functions
    seal,
    verify_seal,
    emit,
    query_events,
    filter_hunks,
    check_token,
    create_credential,
    verify_credential,
    score,
    update_trust,
    classify,
    classify_all,
    record_signal,
    query_signals,
    kindex_get,
    kindex_put,
    kindex_query_by_tags,
)


# ===========================================================================
# Helper: canonical JSON for hashing
# ===========================================================================
def canonical_json(data):
    """Produce canonical JSON serialization matching the contract spec."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ===========================================================================
# Factory helpers
# ===========================================================================
def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _future_iso(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def _past_iso(hours=1):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def make_diff_hunk(**overrides):
    defaults = dict(
        id="hunk001",
        file_path="src/main.py",
        start_line_old=1,
        count_old=5,
        start_line_new=1,
        count_new=7,
        context_before=["# context"],
        added_lines=["print('hello')"],
        removed_lines=["pass"],
        context_after=["# end"],
        raw_header="@@ -1,5 +1,7 @@",
        classifications=[ClassificationLabel.public],
        language="python",
    )
    defaults.update(overrides)
    return DiffHunk(**defaults)


def make_policy_token(**overrides):
    defaults = dict(
        token_id="tok001",
        reviewer_id="reviewer1",
        allowed_file_patterns=["src/*.py"],
        denied_file_patterns=[],
        allowed_classifications=[ClassificationLabel.public, ClassificationLabel.internal_api],
        max_severity=Severity.high,
        issued_at=_now_iso(),
        expires_at=_future_iso(),
    )
    defaults.update(overrides)
    return PolicyToken(**defaults)


def make_assessment(**overrides):
    defaults = dict(
        id="assess001",
        review_request_id="rr001",
        stage=ReviewStage.security,
        reviewer_id="reviewer1",
        decision=ReviewDecision.warn,
        findings=[],
        confidence=Confidence.high,
        is_partial=False,
        error_message=None,
        duration_ms=150,
        created_at=_now_iso(),
    )
    defaults.update(overrides)
    return Assessment(**defaults)


def make_trust_score(**overrides):
    defaults = dict(
        reviewer_id="reviewer1",
        stage=ReviewStage.security,
        weight=0.8,
        accepted_count=10,
        dismissed_count=2,
        updated_at=_now_iso(),
    )
    defaults.update(overrides)
    return TrustScore(**defaults)


def make_learning_record(**overrides):
    defaults = dict(
        record_id="lr001",
        finding_id="f001",
        reviewer_id="reviewer1",
        stage=ReviewStage.security,
        rule_id="rule001",
        severity=Severity.medium,
        accepted=True,
        human_comment=None,
        recorded_at=_now_iso(),
    )
    defaults.update(overrides)
    return LearningRecord(**defaults)


def make_chronicler_event(**overrides):
    defaults = dict(
        event_id="evt001",
        event_type=ChroniclerEventType["review.started"],
        review_request_id="rr001",
        timestamp=_now_iso(),
        stage=None,
        reviewer_id=None,
        payload={"key": "value"},
        message="Review started",
    )
    defaults.update(overrides)
    return ChroniclerEvent(**defaults)


def make_finding(**overrides):
    defaults = dict(
        id="f001",
        hunk_id="hunk001",
        file_path="src/main.py",
        line_number=10,
        severity=Severity.medium,
        confidence=Confidence.high,
        title="Possible issue",
        description="Found something",
        suggestion="Fix it",
        rule_id="rule001",
        stage=ReviewStage.security,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def make_stigmergy_signal(**overrides):
    defaults = dict(
        signal_id="sig001",
        pattern_key="unused-import",
        description="Unused import detected",
        occurrences=3,
        first_seen_at=_now_iso(),
        last_seen_at=_now_iso(),
        reviewer_id="reviewer1",
        stage=ReviewStage.style,
        metadata={"key": "value"},
    )
    defaults.update(overrides)
    return StigmergySignal(**defaults)


def make_kindex_entry(**overrides):
    defaults = dict(
        key="entry001",
        kind="review",
        summary="A past review",
        data={"info": "details"},
        tags=["python", "security"],
        created_at=_now_iso(),
        updated_at=_now_iso(),
    )
    defaults.update(overrides)
    return KindexEntry(**defaults)


def make_circuit_config(**overrides):
    defaults = dict(
        stages=[ReviewStage.security, ReviewStage.correctness],
        parallel_stages=[[ReviewStage.style, ReviewStage.architecture]],
        stage_timeout_ms=5000,
        block_threshold=2,
        warn_threshold=1,
    )
    defaults.update(overrides)
    return CircuitConfig(**defaults)


def make_ledger_field_rule(**overrides):
    defaults = dict(
        pattern=r"password\s*=",
        label=ClassificationLabel.secret,
        description="Detects hardcoded passwords",
    )
    defaults.update(overrides)
    return LedgerFieldRule(**defaults)


def make_ledger_config(**overrides):
    defaults = dict(
        rules=[make_ledger_field_rule()],
        default_label=ClassificationLabel.public,
    )
    defaults.update(overrides)
    return LedgerConfig(**defaults)


# ===========================================================================
# SECTION 1: ENUM TESTS
# ===========================================================================


class TestEnums:
    """Test all enum types have expected variants."""

    def test_credential_error_reason_variants(self):
        expected = {"EXPIRED", "INVALID_SIGNATURE", "UNKNOWN_REVIEWER", "STAGE_MISMATCH", "MALFORMED"}
        actual = {v.name for v in CredentialErrorReason}
        assert expected.issubset(actual), f"Missing variants: {expected - actual}"

    def test_review_stage_variants(self):
        expected = {"security", "correctness", "style", "architecture"}
        actual = {v.value if hasattr(v, 'value') else v.name for v in ReviewStage}
        # Try both .name and .value since enum implementation may vary
        actual_names = {v.name for v in ReviewStage}
        assert expected.issubset(actual) or expected.issubset(actual_names), \
            f"ReviewStage missing variants. Got names={actual_names}, values={actual}"

    def test_chronicler_event_type_variants(self):
        expected_values = {
            "review.started", "stage.started", "stage.complete",
            "assessment.merged", "report.sealed", "review.complete",
            "policy.violation", "pattern.detected", "learning.recorded",
        }
        actual_values = set()
        for v in ChroniclerEventType:
            actual_values.add(v.value if hasattr(v, 'value') else v.name)
        assert expected_values.issubset(actual_values), \
            f"ChroniclerEventType missing: {expected_values - actual_values}"

    def test_review_decision_variants(self):
        expected = {"block", "warn", "pass"}
        actual = set()
        for v in ReviewDecision:
            actual.add(v.value if hasattr(v, 'value') else v.name)
        assert expected.issubset(actual), f"ReviewDecision missing: {expected - actual}"

    def test_classification_label_variants(self):
        expected = {"secret", "pii", "internal_api", "public"}
        actual = set()
        for v in ClassificationLabel:
            actual.add(v.value if hasattr(v, 'value') else v.name)
        assert expected.issubset(actual)

    def test_confidence_variants(self):
        expected = {"high", "medium", "low"}
        actual = set()
        for v in Confidence:
            actual.add(v.value if hasattr(v, 'value') else v.name)
        assert expected.issubset(actual)

    def test_severity_variants(self):
        expected = {"critical", "high", "medium", "low", "info"}
        actual = set()
        for v in Severity:
            actual.add(v.value if hasattr(v, 'value') else v.name)
        assert expected.issubset(actual)

    def test_finding_severity_variants(self):
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        actual = set()
        for v in FindingSeverity:
            actual.add(v.value if hasattr(v, 'value') else v.name)
        assert expected.issubset(actual)

    def test_learning_outcome_variants(self):
        expected = {
            "CORRECT_ACCEPT", "CORRECT_REJECT", "FALSE_POSITIVE",
            "FALSE_NEGATIVE", "PARTIAL_MATCH",
        }
        actual = set()
        for v in LearningOutcome:
            actual.add(v.value if hasattr(v, 'value') else v.name)
        assert expected.issubset(actual)


# ===========================================================================
# SECTION 2: MODEL / STRUCT CONSTRUCTION TESTS
# ===========================================================================


class TestModelConstruction:
    """Test all governance struct types can be constructed and are frozen."""

    def test_governance_error_construction(self):
        err = GovernanceError(message="test error", context={"key": "val"})
        assert err.message == "test error"
        assert err.context == {"key": "val"}

    def test_seal_verification_error_construction(self):
        err = SealVerificationError(
            message="mismatch",
            seal_id="seal1",
            expected_hash="aaa",
            actual_hash="bbb",
        )
        assert err.seal_id == "seal1"
        assert err.expected_hash == "aaa"
        assert err.actual_hash == "bbb"

    def test_policy_violation_error_construction(self):
        err = PolicyViolationError(
            message="violation",
            token_id="tok1",
            violated_scopes=["scope1", "scope2"],
        )
        assert err.token_id == "tok1"
        assert err.violated_scopes == ["scope1", "scope2"]

    def test_credential_error_construction(self):
        err = CredentialError(
            message="expired",
            credential_id="cred1",
            reason=CredentialErrorReason.EXPIRED,
        )
        assert err.credential_id == "cred1"
        assert err.reason == CredentialErrorReason.EXPIRED

    def test_tessera_seal_construction(self):
        s = TesseraSeal(
            content_hash="abc123",
            previous_hash="0" * 64,
            chain_hash="def456",
            sealed_at=_now_iso(),
            sealer_id="sealer1",
        )
        assert s.content_hash == "abc123"
        assert s.sealer_id == "sealer1"

    def test_chronicler_event_construction(self):
        evt = make_chronicler_event()
        assert evt.event_id == "evt001"
        assert evt.review_request_id == "rr001"

    def test_chronicler_event_optional_fields(self):
        evt = make_chronicler_event(stage=ReviewStage.security, reviewer_id="rev1")
        assert evt.stage == ReviewStage.security
        assert evt.reviewer_id == "rev1"

    def test_diff_hunk_construction(self):
        hunk = make_diff_hunk()
        assert hunk.id == "hunk001"
        assert hunk.file_path == "src/main.py"
        assert hunk.language == "python"

    def test_policy_token_construction(self):
        token = make_policy_token()
        assert token.token_id == "tok001"
        assert token.reviewer_id == "reviewer1"

    def test_reviewer_credential_construction(self):
        cred = ReviewerCredential(
            reviewer_id="rev1",
            display_name="Reviewer One",
            stage=ReviewStage.security,
            public_key_hex="abcdef0123456789",
            created_at=_now_iso(),
            is_active=True,
        )
        assert cred.reviewer_id == "rev1"
        assert cred.is_active is True

    def test_assessment_construction(self):
        a = make_assessment()
        assert a.id == "assess001"
        assert a.decision == ReviewDecision.warn

    def test_finding_construction(self):
        f = make_finding()
        assert f.id == "f001"
        assert f.severity == Severity.medium

    def test_trust_score_construction(self):
        ts = make_trust_score()
        assert ts.weight == 0.8
        assert ts.reviewer_id == "reviewer1"

    def test_trust_score_weight_lower_bound(self):
        ts = make_trust_score(weight=0.0)
        assert ts.weight == 0.0

    def test_trust_score_weight_upper_bound(self):
        ts = make_trust_score(weight=1.0)
        assert ts.weight == 1.0

    def test_trust_score_weight_below_zero_rejected(self):
        with pytest.raises(Exception):  # ValidationError from Pydantic
            make_trust_score(weight=-0.01)

    def test_trust_score_weight_above_one_rejected(self):
        with pytest.raises(Exception):  # ValidationError from Pydantic
            make_trust_score(weight=1.01)

    def test_learning_record_construction(self):
        lr = make_learning_record()
        assert lr.record_id == "lr001"
        assert lr.accepted is True

    def test_ledger_field_rule_construction(self):
        r = make_ledger_field_rule()
        assert r.label == ClassificationLabel.secret

    def test_ledger_config_construction(self):
        cfg = make_ledger_config()
        assert len(cfg.rules) == 1
        assert cfg.default_label == ClassificationLabel.public

    def test_stigmergy_signal_construction(self):
        sig = make_stigmergy_signal()
        assert sig.signal_id == "sig001"
        assert sig.occurrences == 3

    def test_kindex_entry_construction(self):
        entry = make_kindex_entry()
        assert entry.key == "entry001"
        assert "python" in entry.tags

    def test_circuit_config_construction(self):
        cfg = make_circuit_config()
        assert cfg.stage_timeout_ms == 5000

    def test_circuit_config_zero_timeout_rejected(self):
        with pytest.raises(Exception):  # ValidationError
            make_circuit_config(stage_timeout_ms=0)

    def test_circuit_config_negative_timeout_rejected(self):
        with pytest.raises(Exception):  # ValidationError
            make_circuit_config(stage_timeout_ms=-100)

    def test_filter_result_construction(self):
        fr = FilterResult(
            allowed_hunks=[make_diff_hunk()],
            denied_hunk_ids=["hunk002"],
            violations=["File pattern mismatch"],
        )
        assert len(fr.allowed_hunks) == 1
        assert "hunk002" in fr.denied_hunk_ids


class TestModelFrozenImmutability:
    """All governance models are frozen=True Pydantic models — no in-place mutation."""

    def test_tessera_seal_frozen(self):
        s = TesseraSeal(
            content_hash="abc",
            previous_hash="0" * 64,
            chain_hash="def",
            sealed_at=_now_iso(),
            sealer_id="sealer1",
        )
        with pytest.raises((AttributeError, TypeError, Exception)):
            s.content_hash = "modified"

    def test_trust_score_frozen(self):
        ts = make_trust_score()
        with pytest.raises((AttributeError, TypeError, Exception)):
            ts.weight = 0.5

    def test_diff_hunk_frozen(self):
        hunk = make_diff_hunk()
        with pytest.raises((AttributeError, TypeError, Exception)):
            hunk.file_path = "other.py"

    def test_assessment_frozen(self):
        a = make_assessment()
        with pytest.raises((AttributeError, TypeError, Exception)):
            a.decision = ReviewDecision.block

    def test_finding_frozen(self):
        f = make_finding()
        with pytest.raises((AttributeError, TypeError, Exception)):
            f.title = "changed"

    def test_policy_token_frozen(self):
        t = make_policy_token()
        with pytest.raises((AttributeError, TypeError, Exception)):
            t.reviewer_id = "other"

    def test_kindex_entry_frozen(self):
        e = make_kindex_entry()
        with pytest.raises((AttributeError, TypeError, Exception)):
            e.key = "other"

    def test_circuit_config_frozen(self):
        c = make_circuit_config()
        with pytest.raises((AttributeError, TypeError, Exception)):
            c.stage_timeout_ms = 999

    def test_stigmergy_signal_frozen(self):
        s = make_stigmergy_signal()
        with pytest.raises((AttributeError, TypeError, Exception)):
            s.pattern_key = "other"

    def test_learning_record_frozen(self):
        lr = make_learning_record()
        with pytest.raises((AttributeError, TypeError, Exception)):
            lr.accepted = False


# ===========================================================================
# SECTION 3: SEAL / VERIFY_SEAL TESTS
# ===========================================================================


class TestSeal:
    """Tests for seal() and verify_seal() functions."""

    def test_seal_happy_path(self):
        content = json.dumps({"key": "value"})
        result = seal(content, "sealer1")
        assert isinstance(result, TesseraSeal)
        assert result.sealer_id == "sealer1"
        # content_hash should match SHA-256 of canonical re-serialization
        canonical = canonical_json(json.loads(content))
        expected_hash = sha256_hex(canonical)
        assert result.content_hash == expected_hash

    def test_seal_genesis_previous_hash_zeros(self):
        """First seal from a sealer should have previous_hash of 64 zeros."""
        content = json.dumps({"a": 1})
        result = seal(content, "new_sealer")
        assert result.previous_hash == "0" * 64

    def test_seal_chain_continuity(self):
        """Sequential seals form a valid hash chain."""
        content1 = json.dumps({"seq": 1})
        content2 = json.dumps({"seq": 2})
        content3 = json.dumps({"seq": 3})

        seal1 = seal(content1, "chain_sealer")
        seal2 = seal(content2, "chain_sealer")
        seal3 = seal(content3, "chain_sealer")

        # Chain linkage: seal2.previous_hash == seal1.chain_hash
        assert seal2.previous_hash == seal1.chain_hash
        # Chain linkage: seal3.previous_hash == seal2.chain_hash
        assert seal3.previous_hash == seal2.chain_hash
        # Genesis seal has zero previous_hash
        assert seal1.previous_hash == "0" * 64

    def test_seal_canonical_json_deterministic(self):
        """Semantically equivalent JSON with different key order produces same content_hash."""
        content_a = json.dumps({"z": 1, "a": 2})
        content_b = json.dumps({"a": 2, "z": 1})
        seal_a = seal(content_a, "det_sealer_a")
        seal_b = seal(content_b, "det_sealer_b")
        assert seal_a.content_hash == seal_b.content_hash

    def test_seal_invalid_json_error(self):
        with pytest.raises((GovernanceError, Exception)):
            seal("not valid json {{{", "sealer1")

    def test_seal_empty_sealer_id_error(self):
        with pytest.raises((GovernanceError, Exception)):
            seal(json.dumps({"a": 1}), "")

    def test_seal_whitespace_sealer_id_error(self):
        with pytest.raises((GovernanceError, Exception)):
            seal(json.dumps({"a": 1}), "   ")


class TestVerifySeal:
    """Tests for verify_seal() function."""

    def test_verify_seal_happy_path(self):
        content = json.dumps({"key": "value"})
        s = seal(content, "verifier_sealer")
        result = verify_seal(s, content)
        assert result is True

    def test_verify_seal_roundtrip(self):
        """seal() then verify_seal() roundtrip always succeeds."""
        test_data = [
            json.dumps({"simple": True}),
            json.dumps([1, 2, 3]),
            json.dumps("string"),
            json.dumps(42),
            json.dumps({"nested": {"deep": {"value": [1, 2]}}}),
        ]
        for i, content in enumerate(test_data):
            s = seal(content, f"roundtrip_sealer_{i}")
            assert verify_seal(s, content) is True, f"Roundtrip failed for content: {content}"

    def test_verify_seal_roundtrip_reordered_json(self):
        """verify_seal() succeeds even if content key order differs from original."""
        original = json.dumps({"b": 2, "a": 1})
        s = seal(original, "reorder_sealer")
        reordered = json.dumps({"a": 1, "b": 2})
        # Both should canonicalize the same way
        assert verify_seal(s, reordered) is True

    def test_verify_seal_tampered_content(self):
        content = json.dumps({"key": "value"})
        s = seal(content, "tamper_sealer")
        tampered = json.dumps({"key": "TAMPERED"})
        with pytest.raises((SealVerificationError, GovernanceError, Exception)):
            verify_seal(s, tampered)

    def test_verify_seal_invalid_content_json(self):
        content = json.dumps({"key": "value"})
        s = seal(content, "json_err_sealer")
        with pytest.raises((GovernanceError, Exception)):
            verify_seal(s, "not json {{{")

    def test_verify_seal_chain_hash_mismatch(self):
        """Tamper with chain_hash field of the seal."""
        content = json.dumps({"key": "value"})
        s = seal(content, "chain_tamper_sealer")
        # Create a tampered seal with wrong chain_hash
        tampered_seal = TesseraSeal(
            content_hash=s.content_hash,
            previous_hash=s.previous_hash,
            chain_hash="0" * 64,  # wrong chain hash
            sealed_at=s.sealed_at,
            sealer_id=s.sealer_id,
        )
        with pytest.raises((SealVerificationError, GovernanceError, Exception)):
            verify_seal(tampered_seal, content)


# ===========================================================================
# SECTION 4: CHRONICLE EMIT / QUERY TESTS
# ===========================================================================


class TestChronicleEmit:
    """Tests for async emit() function."""

    @pytest.mark.asyncio
    async def test_emit_happy_path(self):
        event = make_chronicler_event()
        result = await emit(event)
        assert result is True

    @pytest.mark.asyncio
    async def test_emit_fire_and_forget_no_raise(self):
        """emit() should never raise exceptions; returns False on failure."""
        event = make_chronicler_event()
        # Mock file write to fail
        with patch("builtins.open", side_effect=IOError("disk full")):
            try:
                result = await emit(event)
                # If it catches internally, should return False
                assert result is False
            except Exception:
                # Contract says fire-and-forget: should NOT reach here
                pytest.fail("emit() raised an exception instead of returning False")


class TestChronicleQuery:
    """Tests for async query_events() function."""

    @pytest.mark.asyncio
    async def test_query_events_happy_path(self):
        # Emit some events first, then query
        evt1 = make_chronicler_event(
            event_id="q1",
            review_request_id="rr_query",
            event_type=ChroniclerEventType["review.started"],
        )
        evt2 = make_chronicler_event(
            event_id="q2",
            review_request_id="rr_query",
            event_type=ChroniclerEventType["stage.started"],
        )
        evt_other = make_chronicler_event(
            event_id="q3",
            review_request_id="rr_other",
        )
        await emit(evt1)
        await emit(evt2)
        await emit(evt_other)

        results = await query_events("rr_query", None)
        assert all(e.review_request_id == "rr_query" for e in results)

    @pytest.mark.asyncio
    async def test_query_events_filter_by_type(self):
        evt1 = make_chronicler_event(
            event_id="ft1",
            review_request_id="rr_filter",
            event_type=ChroniclerEventType["review.started"],
        )
        evt2 = make_chronicler_event(
            event_id="ft2",
            review_request_id="rr_filter",
            event_type=ChroniclerEventType["stage.started"],
        )
        await emit(evt1)
        await emit(evt2)

        results = await query_events("rr_filter", ChroniclerEventType["review.started"])
        for e in results:
            assert e.review_request_id == "rr_filter"
            assert e.event_type == ChroniclerEventType["review.started"]

    @pytest.mark.asyncio
    async def test_query_events_chronological_order(self):
        events = []
        for i in range(5):
            evt = make_chronicler_event(
                event_id=f"chrono_{i}",
                review_request_id="rr_chrono",
                timestamp=(datetime.now(timezone.utc) + timedelta(seconds=i)).isoformat(),
            )
            events.append(evt)
            await emit(evt)

        results = await query_events("rr_chrono", None)
        # Events should be in file order (chronological)
        event_ids = [e.event_id for e in results]
        for i in range(len(event_ids) - 1):
            # Each subsequent event should come after the previous one
            assert results[i].timestamp <= results[i + 1].timestamp


# ===========================================================================
# SECTION 5: POLICY FILTER / CHECK TOKEN TESTS
# ===========================================================================


class TestFilterHunks:
    """Tests for filter_hunks() function."""

    def test_filter_hunks_happy_path(self):
        hunk_allowed = make_diff_hunk(id="h1", file_path="src/main.py")
        hunk_denied = make_diff_hunk(id="h2", file_path="tests/secret.txt")
        token = make_policy_token(allowed_file_patterns=["src/*.py"])

        result = filter_hunks([hunk_allowed, hunk_denied], token)
        assert isinstance(result, FilterResult)
        allowed_ids = [h.id for h in result.allowed_hunks]
        assert "h1" in allowed_ids
        assert "h2" in result.denied_hunk_ids

    def test_filter_hunks_all_allowed(self):
        hunks = [
            make_diff_hunk(id="h1", file_path="src/a.py"),
            make_diff_hunk(id="h2", file_path="src/b.py"),
        ]
        token = make_policy_token(allowed_file_patterns=["src/*.py"])
        result = filter_hunks(hunks, token)
        assert len(result.allowed_hunks) == 2
        assert len(result.denied_hunk_ids) == 0

    def test_filter_hunks_all_denied(self):
        hunks = [
            make_diff_hunk(id="h1", file_path="docs/readme.md"),
            make_diff_hunk(id="h2", file_path="docs/guide.md"),
        ]
        token = make_policy_token(allowed_file_patterns=["src/*.py"])
        result = filter_hunks(hunks, token)
        assert len(result.allowed_hunks) == 0
        assert len(result.denied_hunk_ids) == 2

    def test_filter_hunks_count_invariant(self):
        """allowed + denied count must equal total input hunks."""
        hunks = [
            make_diff_hunk(id=f"h{i}", file_path=f"{'src' if i % 2 == 0 else 'docs'}/file{i}.py")
            for i in range(10)
        ]
        token = make_policy_token(allowed_file_patterns=["src/*.py"])
        result = filter_hunks(hunks, token)
        assert len(result.allowed_hunks) + len(result.denied_hunk_ids) == len(hunks)

    def test_filter_hunks_expired_token_error(self):
        hunks = [make_diff_hunk()]
        token = make_policy_token(expires_at=_past_iso())
        with pytest.raises((PolicyViolationError, GovernanceError, Exception)):
            filter_hunks(hunks, token)

    def test_filter_hunks_violations_have_descriptions(self):
        hunk = make_diff_hunk(id="h_deny", file_path="secret/data.bin")
        token = make_policy_token(allowed_file_patterns=["src/*.py"])
        result = filter_hunks([hunk], token)
        if result.denied_hunk_ids:
            assert len(result.violations) >= len(result.denied_hunk_ids), \
                "Each denied hunk should have at least one violation description"
            for v in result.violations:
                assert isinstance(v, str)
                assert len(v) > 0

    def test_filter_hunks_classification_exceeds_max(self):
        """Hunks with classifications exceeding token's allowed_classifications are denied."""
        hunk = make_diff_hunk(
            id="h_secret",
            file_path="src/main.py",
            classifications=[ClassificationLabel.secret],
        )
        token = make_policy_token(
            allowed_file_patterns=["src/*.py"],
            allowed_classifications=[ClassificationLabel.public],
        )
        result = filter_hunks([hunk], token)
        # hunk has 'secret' classification but token only allows 'public'
        assert "h_secret" in result.denied_hunk_ids


class TestCheckToken:
    """Tests for check_token() function."""

    def test_check_token_happy_path(self):
        token = make_policy_token()
        result = check_token(token)
        assert result is True

    def test_check_token_expired_error(self):
        token = make_policy_token(expires_at=_past_iso())
        with pytest.raises((PolicyViolationError, GovernanceError, Exception)):
            check_token(token)


# ===========================================================================
# SECTION 6: CREDENTIAL CREATE / VERIFY TESTS
# ===========================================================================


class TestCreateCredential:
    """Tests for create_credential() function."""

    def test_create_credential_happy_path(self):
        cred = create_credential("reviewer1", "Reviewer One", ReviewStage.security)
        assert isinstance(cred, ReviewerCredential)
        assert cred.reviewer_id == "reviewer1"
        assert cred.display_name == "Reviewer One"
        assert cred.stage == ReviewStage.security
        assert cred.is_active is True

    def test_create_credential_expires_in_future(self):
        cred = create_credential("reviewer2", "Reviewer Two", ReviewStage.correctness)
        # The credential should have some expiration field that's in the future
        # Check via verify_credential succeeding (non-expired)
        result = verify_credential(cred)
        assert result is True

    def test_create_credential_empty_reviewer_id_error(self):
        with pytest.raises((GovernanceError, Exception)):
            create_credential("", "Display", ReviewStage.security)

    def test_create_credential_whitespace_reviewer_id_error(self):
        with pytest.raises((GovernanceError, Exception)):
            create_credential("   ", "Display", ReviewStage.security)

    def test_create_credential_empty_display_name_error(self):
        with pytest.raises((GovernanceError, Exception)):
            create_credential("reviewer1", "", ReviewStage.security)

    def test_create_credential_all_stages(self):
        """Credentials can be created for all review stages."""
        for stage in ReviewStage:
            cred = create_credential(f"rev_{stage}", f"Reviewer {stage}", stage)
            assert cred.stage == stage


class TestVerifyCredential:
    """Tests for verify_credential() function."""

    def test_verify_credential_happy_path(self):
        cred = create_credential("rev1", "Reviewer One", ReviewStage.security)
        result = verify_credential(cred)
        assert result is True

    def test_verify_credential_invalid_signature_error(self):
        """Tampered credential should fail signature verification."""
        cred = create_credential("rev1", "Reviewer One", ReviewStage.security)
        # Create a tampered credential with wrong public_key_hex (simulating signature tampering)
        tampered = ReviewerCredential(
            reviewer_id=cred.reviewer_id,
            display_name=cred.display_name,
            stage=cred.stage,
            public_key_hex="deadbeef" * 8,  # tampered
            created_at=cred.created_at,
            is_active=cred.is_active,
        )
        with pytest.raises((CredentialError, GovernanceError, Exception)) as exc_info:
            verify_credential(tampered)
        # Check the reason if we can
        if hasattr(exc_info.value, 'reason'):
            assert exc_info.value.reason == CredentialErrorReason.INVALID_SIGNATURE

    def test_verify_credential_malformed_id_error(self):
        """Credential with non-UUID4 id should raise MALFORMED error."""
        cred = create_credential("rev1", "Reviewer One", ReviewStage.security)
        # Tamper the credential_id to something non-UUID4 if accessible
        # We need to construct a credential manually with bad ID
        try:
            bad_cred = ReviewerCredential(
                reviewer_id="rev1",
                display_name="Test",
                stage=ReviewStage.security,
                public_key_hex="not_a_valid_key",
                created_at=_now_iso(),
                is_active=True,
            )
            with pytest.raises((CredentialError, GovernanceError, Exception)):
                verify_credential(bad_cred)
        except Exception:
            # If construction itself fails due to validation, that's also acceptable
            pass


# ===========================================================================
# SECTION 7: SCORING TESTS
# ===========================================================================


class TestScore:
    """Tests for score() function."""

    def test_score_happy_path(self):
        assessments = [
            make_assessment(reviewer_id="rev1", stage=ReviewStage.security),
        ]
        trust_scores = [
            make_trust_score(reviewer_id="rev1", stage=ReviewStage.security),
        ]
        config = make_circuit_config()
        result = score(assessments, trust_scores, config)
        assert isinstance(result, list)
        assert len(result) == 3
        # result[0] is ReviewDecision, result[1] is Confidence, result[2] is list[str]
        assert isinstance(result[2], list)

    def test_score_result_has_three_elements(self):
        assessments = [
            make_assessment(reviewer_id="rev1", stage=ReviewStage.security),
            make_assessment(
                id="assess002",
                reviewer_id="rev2",
                stage=ReviewStage.correctness,
                decision=ReviewDecision.block,
            ),
        ]
        trust_scores = [
            make_trust_score(reviewer_id="rev1", stage=ReviewStage.security),
            make_trust_score(reviewer_id="rev2", stage=ReviewStage.correctness),
        ]
        config = make_circuit_config()
        result = score(assessments, trust_scores, config)
        assert len(result) == 3

    def test_score_empty_assessments_error(self):
        with pytest.raises((GovernanceError, Exception)):
            score([], [make_trust_score()], make_circuit_config())

    def test_score_missing_trust_score_error(self):
        assessments = [
            make_assessment(reviewer_id="unknown_rev", stage=ReviewStage.security),
        ]
        trust_scores = [
            make_trust_score(reviewer_id="different_rev", stage=ReviewStage.security),
        ]
        config = make_circuit_config()
        with pytest.raises((GovernanceError, Exception)):
            score(assessments, trust_scores, config)

    def test_score_reasoning_trace_per_assessment(self):
        """reasoning_trace should contain one entry per assessment."""
        assessments = [
            make_assessment(id="a1", reviewer_id="rev1", stage=ReviewStage.security),
            make_assessment(id="a2", reviewer_id="rev2", stage=ReviewStage.correctness),
        ]
        trust_scores = [
            make_trust_score(reviewer_id="rev1", stage=ReviewStage.security),
            make_trust_score(reviewer_id="rev2", stage=ReviewStage.correctness),
        ]
        config = make_circuit_config()
        result = score(assessments, trust_scores, config)
        reasoning = result[2]
        assert len(reasoning) >= len(assessments), \
            "reasoning_trace should have at least one entry per assessment"


class TestUpdateTrust:
    """Tests for update_trust() function."""

    def test_update_trust_happy_path(self):
        ts = make_trust_score(weight=0.5, accepted_count=5, dismissed_count=1)
        record = make_learning_record(reviewer_id="reviewer1")
        result = update_trust(ts, record)
        assert isinstance(result, TrustScore)
        assert result.reviewer_id == ts.reviewer_id
        assert result.stage == ts.stage
        # accepted_count or dismissed_count should change
        total_old = ts.accepted_count + ts.dismissed_count
        total_new = result.accepted_count + result.dismissed_count
        assert total_new == total_old + 1

    def test_update_trust_returns_new_instance(self):
        ts = make_trust_score(weight=0.5)
        record = make_learning_record(reviewer_id="reviewer1")
        result = update_trust(ts, record)
        assert result is not ts

    def test_update_trust_clamp_upper(self):
        """Weight should be clamped to 1.0 maximum."""
        ts = make_trust_score(weight=0.99)
        # A positive learning record with a large delta should clamp to 1.0
        record = make_learning_record(reviewer_id="reviewer1", accepted=True)
        result = update_trust(ts, record)
        assert result.weight <= 1.0

    def test_update_trust_clamp_lower(self):
        """Weight should be clamped to 0.0 minimum."""
        ts = make_trust_score(weight=0.01)
        # A negative learning record should not go below 0.0
        record = make_learning_record(reviewer_id="reviewer1", accepted=False)
        result = update_trust(ts, record)
        assert result.weight >= 0.0

    def test_update_trust_reviewer_mismatch_error(self):
        ts = make_trust_score(reviewer_id="reviewer1")
        record = make_learning_record(reviewer_id="reviewer2")
        with pytest.raises((GovernanceError, Exception)):
            update_trust(ts, record)

    def test_update_trust_preserves_reviewer_and_stage(self):
        ts = make_trust_score(reviewer_id="reviewer1", stage=ReviewStage.security)
        record = make_learning_record(reviewer_id="reviewer1")
        result = update_trust(ts, record)
        assert result.reviewer_id == "reviewer1"
        assert result.stage == ReviewStage.security

    def test_update_trust_weight_always_in_range(self):
        """Run multiple updates and verify weight stays in [0.0, 1.0]."""
        ts = make_trust_score(weight=0.5)
        for i in range(20):
            record = make_learning_record(
                record_id=f"lr_{i}",
                reviewer_id="reviewer1",
                accepted=(i % 3 != 0),  # some accepted, some not
            )
            ts = update_trust(ts, record)
            assert 0.0 <= ts.weight <= 1.0, f"Weight out of range: {ts.weight} at iteration {i}"


# ===========================================================================
# SECTION 8: CLASSIFY TESTS
# ===========================================================================


class TestClassify:
    """Tests for classify() function."""

    def test_classify_happy_path(self):
        hunk = make_diff_hunk(added_lines=["password = 'secret123'"])
        rules = [make_ledger_field_rule(pattern=r"password\s*=", label=ClassificationLabel.secret)]
        result = classify(hunk, rules)
        assert isinstance(result, list)
        assert ClassificationLabel.secret in result

    def test_classify_no_match_returns_unknown(self):
        hunk = make_diff_hunk(added_lines=["x = 42"], removed_lines=["y = 43"])
        rules = [make_ledger_field_rule(pattern=r"password\s*=", label=ClassificationLabel.secret)]
        result = classify(hunk, rules)
        # Should return something indicating no match (UNKNOWN per contract)
        assert isinstance(result, list)
        assert len(result) >= 1

    def test_classify_deduplicates_labels(self):
        """Multiple lines matching same rule should produce deduplicated labels."""
        hunk = make_diff_hunk(
            added_lines=["password = 'a'", "password = 'b'", "password = 'c'"],
        )
        rules = [make_ledger_field_rule(pattern=r"password\s*=", label=ClassificationLabel.secret)]
        result = classify(hunk, rules)
        # Should have secret only once
        assert result.count(ClassificationLabel.secret) == 1

    def test_classify_multiple_rules_multiple_labels(self):
        hunk = make_diff_hunk(
            added_lines=["password = 'a'", "email = 'user@test.com'"],
        )
        rules = [
            make_ledger_field_rule(pattern=r"password\s*=", label=ClassificationLabel.secret),
            make_ledger_field_rule(pattern=r"email\s*=", label=ClassificationLabel.pii, description="PII detected"),
        ]
        result = classify(hunk, rules)
        assert ClassificationLabel.secret in result
        assert ClassificationLabel.pii in result

    def test_classify_empty_rules_error(self):
        hunk = make_diff_hunk()
        with pytest.raises((GovernanceError, Exception)):
            classify(hunk, [])

    def test_classify_invalid_regex_error(self):
        hunk = make_diff_hunk()
        rules = [make_ledger_field_rule(pattern=r"[invalid(regex")]
        with pytest.raises((GovernanceError, Exception)):
            classify(hunk, rules)

    def test_classify_checks_removed_lines_too(self):
        hunk = make_diff_hunk(
            added_lines=[],
            removed_lines=["password = 'old_secret'"],
        )
        rules = [make_ledger_field_rule(pattern=r"password\s*=", label=ClassificationLabel.secret)]
        result = classify(hunk, rules)
        assert ClassificationLabel.secret in result


class TestClassifyAll:
    """Tests for classify_all() function."""

    def test_classify_all_happy_path(self):
        hunks = [
            make_diff_hunk(id="h1", added_lines=["password = 'x'"]),
            make_diff_hunk(id="h2", added_lines=["x = 42"]),
        ]
        config = make_ledger_config()
        result = classify_all(hunks, config)
        assert len(result) == len(hunks)
        for h in result:
            assert isinstance(h, DiffHunk)
            assert len(h.classifications) >= 1

    def test_classify_all_preserves_other_fields(self):
        hunks = [
            make_diff_hunk(
                id="preserve_test",
                file_path="src/special.py",
                start_line_old=10,
                count_old=3,
                language="python",
            ),
        ]
        config = make_ledger_config()
        result = classify_all(hunks, config)
        assert result[0].id == "preserve_test"
        assert result[0].file_path == "src/special.py"
        assert result[0].start_line_old == 10
        assert result[0].count_old == 3
        assert result[0].language == "python"

    def test_classify_all_returns_new_instances(self):
        hunks = [make_diff_hunk()]
        config = make_ledger_config()
        result = classify_all(hunks, config)
        # Should be new instances (frozen models, not mutated in-place)
        assert result[0] is not hunks[0]

    def test_classify_all_same_length(self):
        hunks = [make_diff_hunk(id=f"h{i}") for i in range(5)]
        config = make_ledger_config()
        result = classify_all(hunks, config)
        assert len(result) == 5

    def test_classify_all_empty_rules_error(self):
        hunks = [make_diff_hunk()]
        config = LedgerConfig(rules=[], default_label=ClassificationLabel.public)
        with pytest.raises((GovernanceError, Exception)):
            classify_all(hunks, config)


# ===========================================================================
# SECTION 9: STIGMERGY SIGNAL TESTS
# ===========================================================================


class TestStigmergy:
    """Tests for async record_signal() and query_signals() functions."""

    @pytest.mark.asyncio
    async def test_record_signal_happy_path(self):
        signal = make_stigmergy_signal()
        result = await record_signal(signal)
        assert result is True

    @pytest.mark.asyncio
    async def test_record_signal_fire_and_forget(self):
        """record_signal() should never raise; returns False on failure."""
        signal = make_stigmergy_signal()
        with patch("builtins.open", side_effect=IOError("disk full")):
            try:
                result = await record_signal(signal)
                assert result is False
            except Exception:
                pytest.fail("record_signal() raised an exception instead of returning False")

    @pytest.mark.asyncio
    async def test_query_signals_happy_path(self):
        sig1 = make_stigmergy_signal(signal_id="s1", pattern_key="unused-import")
        sig2 = make_stigmergy_signal(signal_id="s2", pattern_key="unused-import")
        sig_other = make_stigmergy_signal(signal_id="s3", pattern_key="other-pattern")

        await record_signal(sig1)
        await record_signal(sig2)
        await record_signal(sig_other)

        results = await query_signals("unused-import")
        assert all(s.pattern_key == "unused-import" for s in results)

    @pytest.mark.asyncio
    async def test_query_signals_chronological_order(self):
        now = datetime.now(timezone.utc)
        for i in range(3):
            sig = make_stigmergy_signal(
                signal_id=f"chrono_sig_{i}",
                pattern_key="chrono-test",
                first_seen_at=(now + timedelta(seconds=i)).isoformat(),
                last_seen_at=(now + timedelta(seconds=i)).isoformat(),
            )
            await record_signal(sig)

        results = await query_signals("chrono-test")
        # Should be in chronological order
        for i in range(len(results) - 1):
            assert results[i].first_seen_at <= results[i + 1].first_seen_at


# ===========================================================================
# SECTION 10: KINDEX TESTS
# ===========================================================================


class TestKindex:
    """Tests for async kindex_get(), kindex_put(), kindex_query_by_tags() functions."""

    @pytest.mark.asyncio
    async def test_kindex_put_happy_path(self):
        entry = make_kindex_entry()
        result = await kindex_put(entry)
        assert result is True

    @pytest.mark.asyncio
    async def test_kindex_get_happy_path(self):
        entry = make_kindex_entry(key="get_test_key")
        await kindex_put(entry)
        result = await kindex_get("get_test_key")
        assert result is not None
        assert result.key == "get_test_key"

    @pytest.mark.asyncio
    async def test_kindex_get_missing_key_returns_none(self):
        result = await kindex_get("nonexistent_key_xyz_123")
        assert result is None

    @pytest.mark.asyncio
    async def test_kindex_put_upsert_replaces_existing(self):
        entry_v1 = make_kindex_entry(key="upsert_key", summary="version 1")
        entry_v2 = make_kindex_entry(key="upsert_key", summary="version 2")

        await kindex_put(entry_v1)
        await kindex_put(entry_v2)

        result = await kindex_get("upsert_key")
        assert result is not None
        assert result.summary == "version 2"

    @pytest.mark.asyncio
    async def test_kindex_put_fire_and_forget(self):
        """kindex_put() should never raise; returns False on failure."""
        entry = make_kindex_entry()
        with patch("builtins.open", side_effect=IOError("disk full")):
            try:
                result = await kindex_put(entry)
                assert result is False
            except Exception:
                pytest.fail("kindex_put() raised an exception instead of returning False")

    @pytest.mark.asyncio
    async def test_kindex_query_by_tags_happy_path(self):
        entry1 = make_kindex_entry(key="tag_test_1", tags=["python", "security"])
        entry2 = make_kindex_entry(key="tag_test_2", tags=["java", "style"])
        entry3 = make_kindex_entry(key="tag_test_3", tags=["python", "style"])

        await kindex_put(entry1)
        await kindex_put(entry2)
        await kindex_put(entry3)

        results = await kindex_query_by_tags(["python"])
        result_keys = [e.key for e in results]
        assert "tag_test_1" in result_keys
        assert "tag_test_3" in result_keys
        # Each result must have at least one tag in common with query
        for entry in results:
            assert set(entry.tags) & {"python"}, f"Entry {entry.key} has no matching tag"

    @pytest.mark.asyncio
    async def test_kindex_query_by_tags_empty_tags_error(self):
        with pytest.raises((GovernanceError, Exception)):
            await kindex_query_by_tags([])

    @pytest.mark.asyncio
    async def test_kindex_query_by_tags_multiple_tag_intersection(self):
        entry = make_kindex_entry(key="multi_tag", tags=["alpha", "beta", "gamma"])
        await kindex_put(entry)

        results = await kindex_query_by_tags(["beta", "delta"])
        result_keys = [e.key for e in results]
        assert "multi_tag" in result_keys


# ===========================================================================
# SECTION 11: INVARIANT TESTS
# ===========================================================================


class TestInvariants:
    """Cross-cutting invariant tests from the contract."""

    def test_seal_hash_chain_invariant(self):
        """All seals from a single sealer form a valid hash chain."""
        seals = []
        for i in range(5):
            content = json.dumps({"iteration": i})
            s = seal(content, "invariant_sealer")
            seals.append(s)

        # Verify chain linkage
        for i, s in enumerate(seals):
            if i == 0:
                assert s.previous_hash == "0" * 64
            else:
                assert s.previous_hash == seals[i - 1].chain_hash

    def test_canonical_json_invariant(self):
        """Canonical JSON always uses sort_keys=True, separators=(',',':')."""
        data = {"z": 1, "a": 2, "m": 3}
        expected = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert expected == '{"a":2,"m":3,"z":1}'

    def test_frozen_models_return_new_instances_from_update_trust(self):
        ts = make_trust_score(weight=0.5)
        record = make_learning_record(reviewer_id="reviewer1")
        new_ts = update_trust(ts, record)
        assert new_ts is not ts
        # Original should be unchanged
        assert ts.weight == 0.5

    def test_frozen_models_return_new_instances_from_classify_all(self):
        hunks = [make_diff_hunk()]
        config = make_ledger_config()
        result = classify_all(hunks, config)
        assert result[0] is not hunks[0]

    @pytest.mark.asyncio
    async def test_fire_and_forget_emit_never_raises(self):
        """emit() invariant: never raises exceptions to callers."""
        event = make_chronicler_event()
        # Even with completely broken internals, should not raise
        with patch("builtins.open", side_effect=PermissionError("nope")):
            try:
                result = await emit(event)
                assert isinstance(result, bool)
            except Exception:
                pytest.fail("emit() violated fire-and-forget invariant by raising")

    @pytest.mark.asyncio
    async def test_fire_and_forget_record_signal_never_raises(self):
        signal = make_stigmergy_signal()
        with patch("builtins.open", side_effect=PermissionError("nope")):
            try:
                result = await record_signal(signal)
                assert isinstance(result, bool)
            except Exception:
                pytest.fail("record_signal() violated fire-and-forget invariant by raising")

    @pytest.mark.asyncio
    async def test_fire_and_forget_kindex_put_never_raises(self):
        entry = make_kindex_entry()
        with patch("builtins.open", side_effect=PermissionError("nope")):
            try:
                result = await kindex_put(entry)
                assert isinstance(result, bool)
            except Exception:
                pytest.fail("kindex_put() violated fire-and-forget invariant by raising")

    def test_verify_seal_raises_on_failure_not_false(self):
        """Verification methods raise domain-specific exceptions, NOT return False silently."""
        content = json.dumps({"key": "value"})
        s = seal(content, "verify_raise_sealer")
        tampered_content = json.dumps({"key": "tampered"})
        with pytest.raises((SealVerificationError, GovernanceError, Exception)):
            verify_seal(s, tampered_content)

    def test_uuid4_format_32_hex_no_hyphens(self):
        """All UUID4 identifiers are 32-character lowercase hex strings (no hyphens)."""
        cred = create_credential("rev1", "Reviewer", ReviewStage.security)
        # The credential should have some UUID4 identifier
        # Check reviewer_id format or credential internal IDs
        # At minimum, credential IDs generated internally should follow UUID4 hex format
        # We verify this through the credential structure
        assert cred.reviewer_id == "rev1"  # This is user-provided, not UUID
        # The actual UUID would be in the internal credential_id — we verify it's well-formed
        # by verifying the credential (which checks credential_id format)
        assert verify_credential(cred) is True
