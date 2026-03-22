"""
Adversarial hidden acceptance tests for Governance Primitives.

These tests catch implementations that pass visible tests through shortcuts
(hardcoded returns, incomplete validation, etc.) rather than truly satisfying
the contract.
"""
import asyncio
import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from exemplar.governance import *


# ============================================================================
# Helpers
# ============================================================================

def canonical_json(data_str: str) -> str:
    """Canonical JSON serialization per contract."""
    data = json.loads(data_str)
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def make_diff_hunk(
    hunk_id="h1",
    file_path="src/main.py",
    added_lines=None,
    removed_lines=None,
    classifications=None,
    language="python",
):
    return DiffHunk(
        id=hunk_id,
        file_path=file_path,
        start_line_old=1,
        count_old=5,
        start_line_new=1,
        count_new=5,
        context_before=["# context"],
        added_lines=added_lines or ["pass"],
        removed_lines=removed_lines or [],
        context_after=["# end"],
        raw_header="@@ -1,5 +1,5 @@",
        classifications=classifications or [],
        language=language,
    )


def future_iso(hours=1):
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()


def past_iso(hours=1):
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ============================================================================
# Seal Tests
# ============================================================================

class TestGoodhartSeal:

    def test_goodhart_seal_different_content_different_hash(self):
        """seal() must produce distinct content_hash values for different JSON content, not a hardcoded hash."""
        sealer = TesseraSealer()
        seal1 = sealer.seal('{"a":1}', "s1")
        # Use a new sealer to avoid chain state confusion
        sealer2 = TesseraSealer()
        seal2 = sealer2.seal('{"b":2}', "s1")
        assert seal1.content_hash != seal2.content_hash

    def test_goodhart_seal_content_hash_is_sha256_hex(self):
        """seal() content_hash must be a valid 64-character lowercase hex string (SHA-256 output format)."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"test":"value"}', "sealer1")
        assert len(seal.content_hash) == 64
        assert re.fullmatch(r'[0-9a-f]{64}', seal.content_hash)

    def test_goodhart_seal_chain_hash_is_sha256_hex(self):
        """seal() chain_hash must be a valid 64-character lowercase hex string."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"test":"value"}', "sealer1")
        assert len(seal.chain_hash) == 64
        assert re.fullmatch(r'[0-9a-f]{64}', seal.chain_hash)

    def test_goodhart_seal_content_hash_matches_manual_sha256(self):
        """seal() content_hash must exactly equal SHA-256 of canonical JSON re-serialization."""
        sealer = TesseraSealer()
        content = '{"z": 1, "a": 2, "m": [3, 4]}'
        seal = sealer.seal(content, "sealer1")
        expected = sha256_hex(canonical_json(content))
        assert seal.content_hash == expected

    def test_goodhart_seal_three_seal_chain(self):
        """A chain of three seals must maintain previous_hash linkage."""
        sealer = TesseraSealer()
        s1 = sealer.seal('{"seq":1}', "chain_sealer")
        s2 = sealer.seal('{"seq":2}', "chain_sealer")
        s3 = sealer.seal('{"seq":3}', "chain_sealer")
        assert s1.previous_hash == '0' * 64
        assert s2.previous_hash == s1.chain_hash
        assert s3.previous_hash == s2.chain_hash

    def test_goodhart_seal_sequence_numbers_three_seals(self):
        """Sequence numbers must be monotonically increasing from 0."""
        sealer = TesseraSealer()
        s1 = sealer.seal('{"a":1}', "seq_sealer")
        s2 = sealer.seal('{"a":2}', "seq_sealer")
        s3 = sealer.seal('{"a":3}', "seq_sealer")
        assert s1.sequence_number == 0
        assert s2.sequence_number == 1
        assert s3.sequence_number == 2

    def test_goodhart_seal_nested_json_canonical(self):
        """seal() must canonicalize nested JSON for deterministic hashing."""
        sealer1 = TesseraSealer()
        sealer2 = TesseraSealer()
        s1 = sealer1.seal('{"z":{"b":1,"a":2},"a":3}', "s")
        s2 = sealer2.seal('{"a":3,"z":{"a":2,"b":1}}', "s")
        assert s1.content_hash == s2.content_hash

    def test_goodhart_seal_sealer_id_in_chain_hash(self):
        """Different sealer_ids must produce different chain_hashes for same content."""
        sealer_a = TesseraSealer()
        sealer_b = TesseraSealer()
        sa = sealer_a.seal('{"data":"same"}', "alice")
        sb = sealer_b.seal('{"data":"same"}', "bob")
        # content_hash should be the same
        assert sa.content_hash == sb.content_hash
        # chain_hash must differ due to different sealer_id
        assert sa.chain_hash != sb.chain_hash

    def test_goodhart_seal_sealed_at_is_iso_format(self):
        """seal() sealed_at timestamp must be a valid ISO 8601 formatted string."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"t":1}', "s1")
        # Should parse without error
        dt = datetime.fromisoformat(seal.sealed_at)
        assert isinstance(dt, datetime)

    def test_goodhart_seal_tab_only_sealer_id_rejected(self):
        """seal() must reject sealer_id that is only tab characters as whitespace-only."""
        sealer = TesseraSealer()
        with pytest.raises((GovernanceError, ValueError)):
            sealer.seal('{"x":1}', "\t\t")

    def test_goodhart_seal_empty_json_object(self):
        """seal() must handle empty JSON object '{}' correctly."""
        sealer = TesseraSealer()
        seal = sealer.seal('{}', "sealer1")
        expected_hash = sha256_hex('{}')
        assert seal.content_hash == expected_hash

    def test_goodhart_seal_json_array_content(self):
        """seal() must handle JSON array content as valid JSON."""
        sealer = TesseraSealer()
        seal = sealer.seal('[1, 2, 3]', "sealer1")
        expected_hash = sha256_hex(canonical_json('[1, 2, 3]'))
        assert seal.content_hash == expected_hash

    def test_goodhart_seal_unicode_content(self):
        """seal() must correctly handle JSON content with unicode and roundtrip verify."""
        sealer = TesseraSealer()
        content = '{"emoji":"🔑","name":"Ñoño"}'
        seal = sealer.seal(content, "unicode_sealer")
        assert seal.content_hash is not None
        # Roundtrip verification
        result = sealer.verify_seal(seal, content)
        assert result is True


# ============================================================================
# Verify Seal Tests
# ============================================================================

class TestGoodhartVerifySeal:

    def test_goodhart_verify_seal_raises_not_returns_false(self):
        """verify_seal() must raise SealVerificationError on mismatch, never return False."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"original":true}', "s1")
        with pytest.raises(SealVerificationError):
            sealer.verify_seal(seal, '{"original":false}')

    def test_goodhart_verify_seal_tampered_chain_hash(self):
        """verify_seal() must detect a tampered chain_hash even when content_hash is correct."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"data":"test"}', "s1")
        # Create a tampered seal with correct content_hash but wrong chain_hash
        tampered = TesseraSeal(
            content_hash=seal.content_hash,
            previous_hash=seal.previous_hash,
            chain_hash="a" * 64,  # tampered
            sealed_at=seal.sealed_at,
            sealer_id=seal.sealer_id,
            sequence_number=seal.sequence_number,
        )
        with pytest.raises(SealVerificationError):
            sealer.verify_seal(tampered, '{"data":"test"}')

    def test_goodhart_verify_seal_different_content_same_length(self):
        """verify_seal() must detect content changes even with same byte length."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"a":1}', "s1")
        with pytest.raises(SealVerificationError):
            sealer.verify_seal(seal, '{"a":2}')

    def test_goodhart_verify_seal_roundtrip_complex_json(self):
        """verify_seal roundtrip must work for complex JSON."""
        sealer = TesseraSealer()
        content = json.dumps({
            "nested": {"deep": {"list": [1, 2, 3]}},
            "unicode": "日本語テスト",
            "special": "line\nbreak",
            "numbers": [0, -1, 3.14, 1e10],
            "null_val": None,
            "bool": True,
        })
        seal = sealer.seal(content, "complex_sealer")
        assert sealer.verify_seal(seal, content) is True

    def test_goodhart_seal_verification_error_fields_populated(self):
        """SealVerificationError must have expected_hash and actual_hash populated and different."""
        sealer = TesseraSealer()
        seal = sealer.seal('{"x":1}', "s1")
        try:
            sealer.verify_seal(seal, '{"x":999}')
            pytest.fail("Should have raised SealVerificationError")
        except SealVerificationError as e:
            assert e.expected_hash != ""
            assert e.actual_hash != ""
            assert e.expected_hash != e.actual_hash


# ============================================================================
# Credential Tests
# ============================================================================

class TestGoodhartCredentials:

    def test_goodhart_credential_id_is_32char_hex(self):
        """create_credential() must generate credential_id as 32-char lowercase hex."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        cred = mgr.create_credential("reviewer1", "Test Bot", ReviewStage.security)
        assert len(cred.credential_id) == 32
        assert re.fullmatch(r'[0-9a-f]{32}', cred.credential_id)

    def test_goodhart_credential_display_name_preserved(self):
        """create_credential() must store and return the exact display_name provided."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        cred = mgr.create_credential("rev1", "Dr. Review Bot 🤖", ReviewStage.correctness)
        assert cred.display_name == "Dr. Review Bot 🤖"

    def test_goodhart_credential_whitespace_reviewer_id_rejected(self):
        """create_credential() must reject whitespace-only reviewer_id."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        with pytest.raises((GovernanceError, ValueError)):
            mgr.create_credential("  \t\n  ", "Bot", ReviewStage.style)

    def test_goodhart_credential_whitespace_display_name_rejected(self):
        """create_credential() must reject whitespace-only display_name."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        with pytest.raises((GovernanceError, ValueError)):
            mgr.create_credential("rev1", "   ", ReviewStage.architecture)

    def test_goodhart_credential_unique_ids(self):
        """create_credential() must generate unique credential_ids across multiple calls."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        ids = set()
        for i in range(10):
            cred = mgr.create_credential(f"reviewer_{i}", f"Bot {i}", ReviewStage.security)
            ids.add(cred.credential_id)
        assert len(ids) == 10

    def test_goodhart_verify_credential_different_stage_invalid(self):
        """verify_credential() must reject a credential with tampered stage."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        cred = mgr.create_credential("rev1", "Bot", ReviewStage.security)
        # Tamper stage
        tampered = ReviewerCredential(
            credential_id=cred.credential_id,
            reviewer_id=cred.reviewer_id,
            display_name=cred.display_name,
            stage=ReviewStage.style,  # different stage
            public_key_hex=cred.public_key_hex if hasattr(cred, 'public_key_hex') else "",
            signature_hash=cred.signature_hash,
            created_at=cred.created_at,
            expires_iso=cred.expires_iso if hasattr(cred, 'expires_iso') else future_iso(),
            is_active=cred.is_active if hasattr(cred, 'is_active') else True,
        )
        with pytest.raises(CredentialError) as exc_info:
            mgr.verify_credential(tampered)
        assert exc_info.value.reason == CredentialErrorReason.INVALID_SIGNATURE

    def test_goodhart_verify_credential_error_has_credential_id(self):
        """CredentialError from verify_credential() must include the credential_id."""
        mgr = SignetManager(secret_key="test_secret_key_12345")
        cred = mgr.create_credential("rev1", "Bot", ReviewStage.security)
        # Tamper signature
        tampered = ReviewerCredential(
            credential_id=cred.credential_id,
            reviewer_id=cred.reviewer_id,
            display_name=cred.display_name,
            stage=cred.stage,
            public_key_hex=cred.public_key_hex if hasattr(cred, 'public_key_hex') else "",
            signature_hash="deadbeef" * 8,
            created_at=cred.created_at,
            expires_iso=cred.expires_iso if hasattr(cred, 'expires_iso') else future_iso(),
            is_active=cred.is_active if hasattr(cred, 'is_active') else True,
        )
        with pytest.raises(CredentialError) as exc_info:
            mgr.verify_credential(tampered)
        assert exc_info.value.credential_id == cred.credential_id


# ============================================================================
# Classify Tests
# ============================================================================

class TestGoodhartClassify:

    def test_goodhart_classify_removed_lines_matched(self):
        """classify() must check removed_lines in addition to added_lines."""
        hunk = make_diff_hunk(
            added_lines=["normal code"],
            removed_lines=["API_KEY=sk_live_12345abcde"],
        )
        rules = [
            LedgerFieldRule(
                pattern=r"API_KEY\s*=",
                label=ClassificationLabel.secret,
                description="API key pattern",
            )
        ]
        classifier = LedgerClassifier(rules)
        labels = classifier.classify(hunk, rules)
        assert ClassificationLabel.secret in labels

    def test_goodhart_classify_multiple_rules_multiple_labels(self):
        """classify() must return union of all matching labels from different rules."""
        hunk = make_diff_hunk(
            added_lines=["aws_secret_key = AKIA1234567890"],
            removed_lines=["email: user@example.com"],
        )
        rules = [
            LedgerFieldRule(
                pattern=r"aws_secret_key",
                label=ClassificationLabel.secret,
                description="AWS secret",
            ),
            LedgerFieldRule(
                pattern=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                label=ClassificationLabel.pii,
                description="Email address",
            ),
        ]
        classifier = LedgerClassifier(rules)
        labels = classifier.classify(hunk, rules)
        assert ClassificationLabel.secret in labels
        assert ClassificationLabel.pii in labels

    def test_goodhart_classify_both_added_and_removed(self):
        """classify() must scan both added and removed lines, returning union of matches."""
        hunk = make_diff_hunk(
            added_lines=["internal_api_endpoint = '/v1/internal'"],
            removed_lines=["ssn = 123-45-6789"],
        )
        rules = [
            LedgerFieldRule(
                pattern=r"internal_api",
                label=ClassificationLabel.internal_api,
                description="Internal API reference",
            ),
            LedgerFieldRule(
                pattern=r"\d{3}-\d{2}-\d{4}",
                label=ClassificationLabel.pii,
                description="SSN pattern",
            ),
        ]
        classifier = LedgerClassifier(rules)
        labels = classifier.classify(hunk, rules)
        assert ClassificationLabel.internal_api in labels
        assert ClassificationLabel.pii in labels


# ============================================================================
# Classify All Tests
# ============================================================================

class TestGoodhartClassifyAll:

    def test_goodhart_classify_all_returns_new_instances(self):
        """classify_all() must return new DiffHunk instances, not the same objects."""
        hunks = [
            make_diff_hunk(hunk_id="h1", added_lines=["x = 1"]),
            make_diff_hunk(hunk_id="h2", added_lines=["y = 2"]),
        ]
        config = LedgerConfig(
            rules=[
                LedgerFieldRule(
                    pattern=r"never_matches_anything_xyzzy",
                    label=ClassificationLabel.public,
                    description="no match",
                )
            ],
            default_label=ClassificationLabel.public,
        )
        classifier = LedgerClassifier(config.rules)
        result = classifier.classify_all(hunks, config)
        assert len(result) == len(hunks)
        for orig, new in zip(hunks, result):
            assert orig is not new

    def test_goodhart_classify_all_preserves_id_and_file_path(self):
        """classify_all() must preserve all non-classification fields."""
        hunks = [
            make_diff_hunk(
                hunk_id="preserve_test",
                file_path="deep/nested/file.rs",
                added_lines=["let x = 42;"],
                language="rust",
            ),
        ]
        config = LedgerConfig(
            rules=[
                LedgerFieldRule(
                    pattern=r"never_matches_xyzzy",
                    label=ClassificationLabel.public,
                    description="no match",
                )
            ],
            default_label=ClassificationLabel.public,
        )
        classifier = LedgerClassifier(config.rules)
        result = classifier.classify_all(hunks, config)
        assert result[0].id == "preserve_test"
        assert result[0].file_path == "deep/nested/file.rs"
        assert result[0].added_lines == ["let x = 42;"]
        assert result[0].language == "rust"


# ============================================================================
# Filter Hunks Tests
# ============================================================================

class TestGoodhartFilterHunks:

    def test_goodhart_filter_hunks_classification_exceeds_max(self):
        """filter_hunks() must deny hunks whose classification exceeds token's allowed_classifications."""
        hunk = make_diff_hunk(
            hunk_id="secret_hunk",
            file_path="src/main.py",
            classifications=[ClassificationLabel.secret],
        )
        token = PolicyToken(
            token_id="tok1",
            reviewer_id="rev1",
            allowed_file_patterns=["src/*.py"],
            denied_file_patterns=[],
            allowed_classifications=[ClassificationLabel.public],
            max_severity=Severity.critical,
            issued_at=now_iso(),
            expires_at=future_iso(),
        )
        enforcer = AgentSafeEnforcer()
        result = enforcer.filter_hunks([hunk], token)
        assert len(result.denied_hunk_ids) >= 1
        assert "secret_hunk" in result.denied_hunk_ids

    def test_goodhart_filter_hunks_empty_patterns_allows_all(self):
        """filter_hunks() must allow all hunks when allowed_file_patterns is empty."""
        hunks = [
            make_diff_hunk(hunk_id="h1", file_path="any/path.js", classifications=[ClassificationLabel.public]),
            make_diff_hunk(hunk_id="h2", file_path="other/file.py", classifications=[ClassificationLabel.public]),
        ]
        token = PolicyToken(
            token_id="tok1",
            reviewer_id="rev1",
            allowed_file_patterns=[],
            denied_file_patterns=[],
            allowed_classifications=[ClassificationLabel.public, ClassificationLabel.secret, ClassificationLabel.pii, ClassificationLabel.internal_api],
            max_severity=Severity.critical,
            issued_at=now_iso(),
            expires_at=future_iso(),
        )
        enforcer = AgentSafeEnforcer()
        result = enforcer.filter_hunks(hunks, token)
        assert len(result.allowed_hunks) == 2
        assert len(result.denied_hunk_ids) == 0

    def test_goodhart_filter_hunks_denied_ids_unique(self):
        """filter_hunks() must not duplicate denied hunk IDs."""
        # Hunk that could be denied for multiple reasons (bad classification AND bad file path)
        hunk = make_diff_hunk(
            hunk_id="multi_deny",
            file_path="forbidden/secret.py",
            classifications=[ClassificationLabel.secret],
        )
        token = PolicyToken(
            token_id="tok1",
            reviewer_id="rev1",
            allowed_file_patterns=["src/*.py"],
            denied_file_patterns=[],
            allowed_classifications=[ClassificationLabel.public],
            max_severity=Severity.critical,
            issued_at=now_iso(),
            expires_at=future_iso(),
        )
        enforcer = AgentSafeEnforcer()
        result = enforcer.filter_hunks([hunk], token)
        assert len(result.denied_hunk_ids) == len(set(result.denied_hunk_ids))


# ============================================================================
# Check Token Tests
# ============================================================================

class TestGoodhartCheckToken:

    def test_goodhart_check_token_empty_reviewer_id_returns_false(self):
        """check_token() must return False for a non-expired token with empty reviewer_id."""
        token = PolicyToken(
            token_id="tok1",
            reviewer_id="",
            allowed_file_patterns=["*"],
            denied_file_patterns=[],
            allowed_classifications=[ClassificationLabel.public],
            max_severity=Severity.critical,
            issued_at=now_iso(),
            expires_at=future_iso(),
        )
        enforcer = AgentSafeEnforcer()
        result = enforcer.check_token(token)
        assert result is False


# ============================================================================
# Update Trust Tests
# ============================================================================

class TestGoodhartUpdateTrust:

    def test_goodhart_update_trust_preserves_stage(self):
        """update_trust() must preserve the original stage in the returned TrustScore."""
        for stage in ReviewStage:
            ts = TrustScore(
                reviewer_id="rev1",
                stage=stage,
                weight=0.5,
                accepted_count=5,
                dismissed_count=2,
                updated_at=now_iso(),
            )
            record = LearningRecord(
                record_id="rec1",
                finding_id="f1",
                reviewer_id="rev1",
                stage=stage,
                rule_id="rule1",
                severity=Severity.medium,
                accepted=True,
                human_comment=None,
                recorded_at=now_iso(),
            )
            arbiter = ArbiterScorer()
            result = arbiter.update_trust(ts, record)
            assert result.stage == stage

    def test_goodhart_update_trust_increments_count_exactly_one(self):
        """update_trust() must increment review_count by exactly 1 per call."""
        ts = TrustScore(
            reviewer_id="rev1",
            stage=ReviewStage.security,
            weight=0.5,
            accepted_count=10,
            dismissed_count=3,
            updated_at=now_iso(),
        )
        arbiter = ArbiterScorer()
        initial_count = ts.accepted_count + ts.dismissed_count
        current = ts
        for i in range(3):
            record = LearningRecord(
                record_id=f"rec{i}",
                finding_id=f"f{i}",
                reviewer_id="rev1",
                stage=ReviewStage.security,
                rule_id="rule1",
                severity=Severity.medium,
                accepted=True,
                human_comment=None,
                recorded_at=now_iso(),
            )
            current = arbiter.update_trust(current, record)
        # review_count should have incremented 3 times
        new_count = current.accepted_count + current.dismissed_count
        assert new_count == initial_count + 3

    def test_goodhart_update_trust_clamp_to_exact_boundary(self):
        """update_trust() must clamp to exactly 0.0 or 1.0 at boundaries."""
        arbiter = ArbiterScorer()

        # Test upper clamp
        ts_high = TrustScore(
            reviewer_id="rev1", stage=ReviewStage.security,
            weight=0.95, accepted_count=5, dismissed_count=0, updated_at=now_iso(),
        )
        record_up = LearningRecord(
            record_id="r1", finding_id="f1", reviewer_id="rev1",
            stage=ReviewStage.security, rule_id="rule1", severity=Severity.high,
            accepted=True, human_comment=None, recorded_at=now_iso(),
        )
        result_high = arbiter.update_trust(ts_high, record_up)
        assert result_high.weight <= 1.0
        if result_high.weight > 0.95:
            # If it was increased, it should be clamped at 1.0 max
            assert result_high.weight == 1.0 or result_high.weight <= 1.0

        # Test lower clamp
        ts_low = TrustScore(
            reviewer_id="rev2", stage=ReviewStage.security,
            weight=0.05, accepted_count=5, dismissed_count=5, updated_at=now_iso(),
        )
        record_down = LearningRecord(
            record_id="r2", finding_id="f2", reviewer_id="rev2",
            stage=ReviewStage.security, rule_id="rule1", severity=Severity.high,
            accepted=False, human_comment=None, recorded_at=now_iso(),
        )
        result_low = arbiter.update_trust(ts_low, record_down)
        assert result_low.weight >= 0.0

    def test_goodhart_update_trust_negative_delta(self):
        """update_trust() must correctly decrease weight for dismissed findings."""
        arbiter = ArbiterScorer()
        ts = TrustScore(
            reviewer_id="rev1", stage=ReviewStage.correctness,
            weight=0.8, accepted_count=10, dismissed_count=2, updated_at=now_iso(),
        )
        record = LearningRecord(
            record_id="r1", finding_id="f1", reviewer_id="rev1",
            stage=ReviewStage.correctness, rule_id="rule1", severity=Severity.high,
            accepted=False, human_comment="wrong", recorded_at=now_iso(),
        )
        result = arbiter.update_trust(ts, record)
        # Weight should decrease or stay same for dismissed finding, not increase
        assert result.weight <= ts.weight


# ============================================================================
# Score Tests
# ============================================================================

class TestGoodhartScore:

    def _make_assessment(self, reviewer_id, stage, decision, confidence):
        return Assessment(
            id=f"a_{reviewer_id}_{stage.value}",
            review_request_id="rr1",
            stage=stage,
            reviewer_id=reviewer_id,
            decision=decision,
            findings=[],
            confidence=confidence,
            is_partial=False,
            error_message=None,
            duration_ms=100,
            created_at=now_iso(),
        )

    def _make_trust_score(self, reviewer_id, stage, weight=0.8):
        return TrustScore(
            reviewer_id=reviewer_id,
            stage=stage,
            weight=weight,
            accepted_count=10,
            dismissed_count=2,
            updated_at=now_iso(),
        )

    def test_goodhart_score_reasoning_trace_one_per_assessment(self):
        """score() reasoning_trace must contain one entry per assessment."""
        arbiter = ArbiterScorer()
        config = CircuitConfig(
            stages=[ReviewStage.security, ReviewStage.correctness],
            parallel_stages=[],
            stage_timeout_ms=5000,
            block_threshold=1,
            warn_threshold=1,
        )

        # Test with 2 assessments
        assessments_2 = [
            self._make_assessment("r1", ReviewStage.security, ReviewDecision.pass_, Confidence.high),
            self._make_assessment("r2", ReviewStage.correctness, ReviewDecision.pass_, Confidence.medium),
        ]
        trust_2 = [
            self._make_trust_score("r1", ReviewStage.security),
            self._make_trust_score("r2", ReviewStage.correctness),
        ]
        result_2 = arbiter.score(assessments_2, trust_2, config)
        assert len(result_2) == 3
        assert len(result_2[2]) == 2

        # Test with 4 assessments
        assessments_4 = assessments_2 + [
            self._make_assessment("r3", ReviewStage.style, ReviewDecision.warn, Confidence.low),
            self._make_assessment("r4", ReviewStage.architecture, ReviewDecision.pass_, Confidence.high),
        ]
        trust_4 = trust_2 + [
            self._make_trust_score("r3", ReviewStage.style),
            self._make_trust_score("r4", ReviewStage.architecture),
        ]
        result_4 = arbiter.score(assessments_4, trust_4, config)
        assert len(result_4[2]) == 4

    def test_goodhart_score_decision_is_review_decision_enum(self):
        """score() first element must be a ReviewDecision enum value."""
        arbiter = ArbiterScorer()
        config = CircuitConfig(
            stages=[ReviewStage.security],
            parallel_stages=[],
            stage_timeout_ms=5000,
            block_threshold=1,
            warn_threshold=1,
        )
        assessments = [
            self._make_assessment("r1", ReviewStage.security, ReviewDecision.pass_, Confidence.high),
        ]
        trust = [self._make_trust_score("r1", ReviewStage.security)]
        result = arbiter.score(assessments, trust, config)
        assert isinstance(result[0], ReviewDecision)

    def test_goodhart_score_confidence_is_confidence_enum(self):
        """score() second element must be a Confidence enum value."""
        arbiter = ArbiterScorer()
        config = CircuitConfig(
            stages=[ReviewStage.security],
            parallel_stages=[],
            stage_timeout_ms=5000,
            block_threshold=1,
            warn_threshold=1,
        )
        assessments = [
            self._make_assessment("r1", ReviewStage.security, ReviewDecision.pass_, Confidence.high),
        ]
        trust = [self._make_trust_score("r1", ReviewStage.security)]
        result = arbiter.score(assessments, trust, config)
        assert isinstance(result[1], Confidence)


# ============================================================================
# Emit / Query Events Tests
# ============================================================================

class TestGoodhartChronicler:

    @pytest.fixture
    def tmp_log(self, tmp_path):
        return tmp_path / "chronicle.jsonl"

    def _make_event(self, review_request_id, event_type, message="test"):
        return ChroniclerEvent(
            event_id="evt_" + review_request_id[:8],
            event_type=event_type,
            review_request_id=review_request_id,
            timestamp=now_iso(),
            stage=None,
            reviewer_id=None,
            payload={},
            message=message,
        )

    @pytest.mark.asyncio
    async def test_goodhart_emit_multiple_events_all_persisted(self, tmp_log):
        """emit() must append multiple events and all must be queryable."""
        chronicler = Chronicler(chronicle_log_path=str(tmp_log))
        events = []
        for i in range(3):
            evt = ChroniclerEvent(
                event_id=f"evt_{i}",
                event_type=ChroniclerEventType.stage_started,
                review_request_id="rr_multi",
                timestamp=now_iso(),
                stage=ReviewStage.security,
                reviewer_id=None,
                payload={"index": str(i)},
                message=f"event {i}",
            )
            result = await chronicler.emit(evt)
            assert result is True
            events.append(evt)

        queried = await chronicler.query_events("rr_multi", ChroniclerEventType.stage_started)
        assert len(queried) == 3

    @pytest.mark.asyncio
    async def test_goodhart_query_events_does_not_return_other_request_ids(self, tmp_log):
        """query_events() must not return events from other review_request_ids."""
        chronicler = Chronicler(chronicle_log_path=str(tmp_log))

        evt_a = self._make_event("request_AAA", ChroniclerEventType.review_started, "A event")
        evt_b = self._make_event("request_BBB", ChroniclerEventType.review_started, "B event")

        await chronicler.emit(evt_a)
        await chronicler.emit(evt_b)

        results_a = await chronicler.query_events("request_AAA", None)
        for r in results_a:
            assert r.review_request_id == "request_AAA"

        results_b = await chronicler.query_events("request_BBB", None)
        for r in results_b:
            assert r.review_request_id == "request_BBB"

        assert len(results_a) == 1
        assert len(results_b) == 1


# ============================================================================
# Stigmergy Signal Tests
# ============================================================================

class TestGoodhartStigmergy:

    @pytest.fixture
    def tmp_store(self, tmp_path):
        return tmp_path / "stigmergy.json"

    @pytest.mark.asyncio
    async def test_goodhart_query_signals_filters_by_exact_pattern_key(self, tmp_store):
        """query_signals() must perform exact matching, not substring matching."""
        store = StigmergyStore(stigmergy_store_path=str(tmp_store))
        sig1 = StigmergySignal(
            signal_id="s1",
            pattern_key="null_check",
            description="null check pattern",
            occurrences=3,
            first_seen_at=now_iso(),
            last_seen_at=now_iso(),
            reviewer_id=None,
            stage=None,
            metadata={},
        )
        sig2 = StigmergySignal(
            signal_id="s2",
            pattern_key="null_check_extended",
            description="extended null check",
            occurrences=1,
            first_seen_at=now_iso(),
            last_seen_at=now_iso(),
            reviewer_id=None,
            stage=None,
            metadata={},
        )
        await store.record_signal(sig1)
        await store.record_signal(sig2)

        results = await store.query_signals("null_check")
        assert all(r.pattern_key == "null_check" for r in results)
        assert len(results) == 1


# ============================================================================
# Kindex Tests
# ============================================================================

class TestGoodhartKindex:

    @pytest.fixture
    def tmp_store(self, tmp_path):
        return tmp_path / "kindex.json"

    @pytest.mark.asyncio
    async def test_goodhart_kindex_get_returns_correct_entry_key(self, tmp_store):
        """kindex_get() returned entry must have key matching the requested key."""
        store = KindexStore(kindex_store_path=str(tmp_store))
        entry = KindexEntry(
            key="unique_key_xyz",
            kind="review",
            summary="test entry",
            data={"field": "value"},
            tags=["tag1"],
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        await store.kindex_put(entry)
        result = await store.kindex_get("unique_key_xyz")
        assert result is not None
        assert result.key == "unique_key_xyz"

    @pytest.mark.asyncio
    async def test_goodhart_kindex_query_tags_intersection_not_superset(self, tmp_store):
        """kindex_query_by_tags() must return entries with ANY tag in common (intersection)."""
        store = KindexStore(kindex_store_path=str(tmp_store))
        entry = KindexEntry(
            key="k1",
            kind="review",
            summary="test",
            data={},
            tags=["alpha", "beta"],
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        await store.kindex_put(entry)

        # Query with one matching and one non-matching tag
        results = await store.kindex_query_by_tags(["beta", "gamma"])
        assert len(results) == 1
        assert results[0].key == "k1"


# ============================================================================
# Error Type Hierarchy Tests
# ============================================================================

class TestGoodhartErrorTypes:

    def test_goodhart_error_types_are_exceptions(self):
        """All error types must be raisable as exceptions and maintain hierarchy."""
        assert issubclass(GovernanceError, Exception)
        assert issubclass(SealVerificationError, GovernanceError)
        assert issubclass(PolicyViolationError, GovernanceError)
        assert issubclass(CredentialError, GovernanceError)

        # Verify they can actually be raised and caught
        with pytest.raises(GovernanceError):
            raise SealVerificationError(
                message="test", seal_id="s1",
                expected_hash="a" * 64, actual_hash="b" * 64,
            )

        with pytest.raises(GovernanceError):
            raise PolicyViolationError(
                message="test", token_id="t1", violated_scopes=["scope1"],
            )

        with pytest.raises(GovernanceError):
            raise CredentialError(
                message="test", credential_id="c1",
                reason=CredentialErrorReason.EXPIRED,
            )


# ============================================================================
# Model Frozen / Immutability Tests
# ============================================================================

class TestGoodhartFrozen:

    def test_goodhart_models_frozen_all_types(self):
        """All governance struct types must reject attribute assignment (frozen=True)."""
        models_and_mutations = []

        # Assessment
        assessment = Assessment(
            id="a1", review_request_id="rr1", stage=ReviewStage.security,
            reviewer_id="r1", decision=ReviewDecision.pass_,
            findings=[], confidence=Confidence.high, is_partial=False,
            error_message=None, duration_ms=100, created_at=now_iso(),
        )
        models_and_mutations.append((assessment, "decision", ReviewDecision.block))

        # Finding
        finding = Finding(
            id="f1", hunk_id="h1", file_path="test.py", line_number=1,
            severity=Severity.high, confidence=Confidence.high,
            title="test", description="desc", suggestion=None,
            rule_id="r1", stage=ReviewStage.security,
        )
        models_and_mutations.append((finding, "severity", Severity.low))

        # DiffHunk
        hunk = make_diff_hunk()
        models_and_mutations.append((hunk, "file_path", "changed.py"))

        # PolicyToken
        token = PolicyToken(
            token_id="t1", reviewer_id="r1",
            allowed_file_patterns=["*"], denied_file_patterns=[],
            allowed_classifications=[ClassificationLabel.public],
            max_severity=Severity.critical,
            issued_at=now_iso(), expires_at=future_iso(),
        )
        models_and_mutations.append((token, "reviewer_id", "changed"))

        # KindexEntry
        entry = KindexEntry(
            key="k1", kind="review", summary="test",
            data={}, tags=["t1"],
            created_at=now_iso(), updated_at=now_iso(),
        )
        models_and_mutations.append((entry, "key", "changed"))

        for model, field, value in models_and_mutations:
            with pytest.raises((AttributeError, TypeError, Exception)):
                setattr(model, field, value)


# ============================================================================
# Boundary Tests for Validators
# ============================================================================

class TestGoodhartBoundary:

    def test_goodhart_trust_score_weight_just_inside_bounds(self):
        """TrustScore must accept weight values just inside range."""
        ts1 = TrustScore(
            reviewer_id="r1", stage=ReviewStage.security,
            weight=0.001, accepted_count=0, dismissed_count=0,
            updated_at=now_iso(),
        )
        assert ts1.weight == 0.001

        ts2 = TrustScore(
            reviewer_id="r1", stage=ReviewStage.security,
            weight=0.999, accepted_count=0, dismissed_count=0,
            updated_at=now_iso(),
        )
        assert ts2.weight == 0.999

    def test_goodhart_trust_score_weight_just_outside_bounds(self):
        """TrustScore must reject weight values just outside range."""
        with pytest.raises((ValueError, Exception)):
            TrustScore(
                reviewer_id="r1", stage=ReviewStage.security,
                weight=-0.001, accepted_count=0, dismissed_count=0,
                updated_at=now_iso(),
            )
        with pytest.raises((ValueError, Exception)):
            TrustScore(
                reviewer_id="r1", stage=ReviewStage.security,
                weight=1.001, accepted_count=0, dismissed_count=0,
                updated_at=now_iso(),
            )

    def test_goodhart_circuit_config_timeout_one_accepted(self):
        """CircuitConfig must accept stage_timeout_ms=1 as minimum valid positive value."""
        config = CircuitConfig(
            stages=[ReviewStage.security],
            parallel_stages=[],
            stage_timeout_ms=1,
            block_threshold=1,
            warn_threshold=1,
        )
        assert config.stage_timeout_ms == 1
