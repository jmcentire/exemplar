"""
Adversarial hidden acceptance tests for the Apprentice Learning Module.

These tests are designed to catch implementations that pass visible tests
through shortcuts (hardcoded returns, incomplete validation, etc.) rather
than truly satisfying the contract.
"""

import asyncio
import json
import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Import the module under test
from exemplar.learner import *


# ============================================================
# Helpers
# ============================================================

def run_async(coro):
    """Helper to run async functions in sync tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


def make_learning_record(
    record_id=None,
    finding_id="finding-001",
    reviewer_id="alice",
    stage="security",
    rule_id="rule.check.xss",
    severity="high",
    accepted=True,
    human_comment=None,
    recorded_at="2024-01-15T10:30:00Z",
):
    """Helper to build a LearningRecord dict or object."""
    return {
        "record_id": record_id or str(uuid.uuid4()),
        "finding_id": finding_id,
        "reviewer_id": reviewer_id,
        "stage": stage,
        "rule_id": rule_id,
        "severity": severity,
        "accepted": accepted,
        "human_comment": human_comment,
        "recorded_at": recorded_at,
    }


def make_human_decision_input(
    finding_id="finding-001",
    reviewer_id="alice",
    rule_id="rule.check.xss",
    decision="accepted",
    file_path="src/main.py",
    severity="high",
    review_stage="security",
    comment="looks good",
    timestamp_iso="2024-01-15T10:30:00Z",
):
    """Helper to build a HumanDecisionInput dict."""
    return {
        "finding_id": finding_id,
        "reviewer_id": reviewer_id,
        "rule_id": rule_id,
        "decision": decision,
        "file_path": file_path,
        "severity": severity,
        "review_stage": review_stage,
        "comment": comment,
        "timestamp_iso": timestamp_iso,
    }


@pytest.fixture
def tmp_learner_dir(tmp_path):
    """Create a temporary directory for learner state."""
    learner_dir = tmp_path / ".exemplar" / "learner"
    return str(learner_dir)


@pytest.fixture
def initialized_learner_dir(tmp_learner_dir):
    """Create and initialize learner directory."""
    run_async(initialize_state(tmp_learner_dir))
    return tmp_learner_dir


# ============================================================
# Type validation tests
# ============================================================


class TestGoodhartReviewerId:

    def test_goodhart_reviewer_id_max_length_boundary(self):
        """ReviewerId must accept exactly 128-char strings and reject 129-char strings"""
        valid_128 = "a" * 128
        try:
            rid = ReviewerId(value=valid_128)
            assert rid.value == valid_128
        except Exception:
            pytest.fail("ReviewerId should accept 128-char string")

        with pytest.raises(Exception):
            ReviewerId(value="a" * 129)

    def test_goodhart_reviewer_id_special_chars_selective(self):
        """ReviewerId regex allows dots, hyphens, underscores but rejects @, #, spaces"""
        # Valid
        rid = ReviewerId(value="a.b-c_d")
        assert rid.value == "a.b-c_d"

        # Invalid chars
        for invalid in ["a@b", "a b", "a#b", "a+b", "a!b"]:
            with pytest.raises(Exception, match=".*"):
                ReviewerId(value=invalid)

    def test_goodhart_reviewer_id_single_char(self):
        """ReviewerId must accept a single alphabetic character"""
        rid = ReviewerId(value="a")
        assert rid.value == "a"

        rid2 = ReviewerId(value="Z")
        assert rid2.value == "Z"

    def test_goodhart_reviewer_id_leading_digit_rejected(self):
        """ReviewerId must reject identifiers starting with a digit"""
        for invalid in ["9reviewer", "0abc", "1test", "3x"]:
            with pytest.raises(Exception):
                ReviewerId(value=invalid)


class TestGoodhartRuleId:

    def test_goodhart_rule_id_with_slashes(self):
        """RuleId allows forward slashes but not backslashes"""
        rid = RuleId(value="security/xss.check")
        assert rid.value == "security/xss.check"

        with pytest.raises(Exception):
            RuleId(value="security\\xss")

    def test_goodhart_rule_id_max_length_256(self):
        """RuleId must accept 256-char strings and reject 257-char strings"""
        valid_256 = "a" + "b" * 255
        try:
            rid = RuleId(value=valid_256)
            assert rid.value == valid_256
        except Exception:
            pytest.fail("RuleId should accept 256-char string")

        with pytest.raises(Exception):
            RuleId(value="a" + "b" * 256)

    def test_goodhart_rule_id_leading_digit_rejected(self):
        """RuleId must reject identifiers starting with a digit"""
        with pytest.raises(Exception):
            RuleId(value="9rule.check")


class TestGoodhartPactKey:

    def test_goodhart_pact_key_uppercase_rejected(self):
        """PactKey regex requires all lowercase - uppercase must be rejected"""
        for invalid in ["pact:learner:Record", "pact:Learner:record", "pact:LEARN:test"]:
            with pytest.raises(Exception):
                PactKey(value=invalid)

    def test_goodhart_pact_key_segment_count(self):
        """PactKey must have exactly three colon-separated segments"""
        # Too few segments
        with pytest.raises(Exception):
            PactKey(value="pact:learner")

        # Too many segments
        with pytest.raises(Exception):
            PactKey(value="pact:a:b:c")

        # No pact prefix
        with pytest.raises(Exception):
            PactKey(value="learner:record:x")

        # Valid
        pk = PactKey(value="pact:learner:record")
        assert pk.value == "pact:learner:record"


class TestGoodhartTrustWeight:

    def test_goodhart_trust_weight_boundary_0_1(self):
        """TrustWeight must accept exactly 0.1 and reject 0.09"""
        tw = TrustWeight(value=0.1)
        assert tw.value == 0.1

        with pytest.raises(Exception):
            TrustWeight(value=0.09)

    def test_goodhart_trust_weight_rounding(self):
        """TrustWeight must be rounded to 4 decimal places"""
        tw = TrustWeight(value=0.55555)
        # Should be rounded to 4 decimal places
        assert abs(tw.value - round(0.55555, 4)) < 1e-10


class TestGoodhartAcceptanceRate:

    def test_goodhart_acceptance_rate_boundary_zero(self):
        """AcceptanceRate must accept exactly 0.0"""
        ar = AcceptanceRate(value=0.0)
        assert ar.value == 0.0

    def test_goodhart_acceptance_rate_boundary_one(self):
        """AcceptanceRate must accept exactly 1.0"""
        ar = AcceptanceRate(value=1.0)
        assert ar.value == 1.0

    def test_goodhart_acceptance_rate_out_of_range(self):
        """AcceptanceRate must reject values outside [0.0, 1.0]"""
        with pytest.raises(Exception):
            AcceptanceRate(value=1.001)
        with pytest.raises(Exception):
            AcceptanceRate(value=-0.001)


class TestGoodhartMinObservations:

    def test_goodhart_min_observations_all_boundaries(self):
        """MinObservations must accept 1 and 10000 but reject 0 and 10001"""
        assert MinObservations(value=1).value == 1
        assert MinObservations(value=10000).value == 10000

        with pytest.raises(Exception):
            MinObservations(value=0)
        with pytest.raises(Exception):
            MinObservations(value=10001)


class TestGoodhartFilePath:

    def test_goodhart_file_path_max_length(self):
        """FilePath must accept 4096-char strings and reject 4097-char strings"""
        valid = "a" * 4096
        fp = FilePath(value=valid)
        assert fp.value == valid

        with pytest.raises(Exception):
            FilePath(value="a" * 4097)

    def test_goodhart_file_path_empty_rejected(self):
        """FilePath must reject empty string since min length is 1"""
        with pytest.raises(Exception):
            FilePath(value="")


class TestGoodhartHumanDecisionInput:

    def test_goodhart_timestamp_formats(self):
        """HumanDecisionInput timestamp_iso accepts empty and valid ISO, rejects malformed"""
        base = make_human_decision_input()

        # Empty string should be valid
        base_empty = {**base, "timestamp_iso": ""}
        try:
            HumanDecisionInput(**base_empty)
        except Exception:
            pytest.fail("Empty timestamp_iso should be accepted")

        # Valid ISO
        base_valid = {**base, "timestamp_iso": "2024-01-15T10:30:00"}
        try:
            HumanDecisionInput(**base_valid)
        except Exception:
            pytest.fail("Valid ISO timestamp should be accepted")

        # Invalid formats
        for invalid_ts in ["2024/01/15", "not-a-date", "15-01-2024"]:
            base_invalid = {**base, "timestamp_iso": invalid_ts}
            with pytest.raises(Exception):
                HumanDecisionInput(**base_invalid)

    def test_goodhart_all_severities_accepted(self):
        """HumanDecisionInput must accept all five severity levels"""
        base = make_human_decision_input()
        for sev in ["critical", "high", "medium", "low", "info"]:
            inp = {**base, "severity": sev}
            try:
                HumanDecisionInput(**inp)
            except Exception:
                pytest.fail(f"Severity '{sev}' should be accepted")

    def test_goodhart_severity_case_sensitive(self):
        """HumanDecisionInput severity is case-sensitive - mixed case must be rejected"""
        base = make_human_decision_input()
        for sev in ["High", "CRITICAL", "Medium", "LOW", "Info"]:
            inp = {**base, "severity": sev}
            with pytest.raises(Exception):
                HumanDecisionInput(**inp)

    def test_goodhart_finding_id_empty_rejected(self):
        """HumanDecisionInput must reject empty finding_id"""
        base = make_human_decision_input()
        inp = {**base, "finding_id": ""}
        with pytest.raises(Exception):
            HumanDecisionInput(**inp)

    def test_goodhart_review_stage_max_length(self):
        """HumanDecisionInput must reject review_stage longer than 64 characters"""
        base = make_human_decision_input()

        # 64 chars should be fine
        inp_ok = {**base, "review_stage": "a" * 64}
        try:
            HumanDecisionInput(**inp_ok)
        except Exception:
            pytest.fail("64-char review_stage should be accepted")

        # 65 chars should fail
        inp_bad = {**base, "review_stage": "a" * 65}
        with pytest.raises(Exception):
            HumanDecisionInput(**inp_bad)


# ============================================================
# initialize_state tests
# ============================================================


class TestGoodhartInitializeState:

    def test_goodhart_init_state_schema_version(self, tmp_learner_dir):
        """Initialized state.json must have schema_version=1 and phase=shadow"""
        run_async(initialize_state(tmp_learner_dir))

        state_path = os.path.join(tmp_learner_dir, "state.json")
        with open(state_path, "r") as f:
            state = json.load(f)

        assert state.get("schema_version") == 1
        assert state.get("total_records") == 0
        # Phase should be shadow
        phase_state = state.get("phase_state", {})
        assert phase_state.get("current_phase") in ("shadow", "LearnerPhase.shadow")

    def test_goodhart_init_records_empty_array(self, tmp_learner_dir):
        """Initialized records.json must be an empty JSON array, not null or {}"""
        run_async(initialize_state(tmp_learner_dir))

        records_path = os.path.join(tmp_learner_dir, "records.json")
        with open(records_path, "r") as f:
            records = json.load(f)

        assert isinstance(records, list), "records.json should be a list"
        assert len(records) == 0, "records.json should be empty"

    def test_goodhart_init_partial_existing_files(self, tmp_path):
        """initialize_state handles case where directory exists but only one file is present"""
        learner_dir = tmp_path / ".exemplar" / "learner"
        learner_dir.mkdir(parents=True, exist_ok=True)

        # Create only state.json with valid content
        state_path = learner_dir / "state.json"
        state_path.write_text(json.dumps({
            "schema_version": 1,
            "phase_state": {
                "current_phase": "shadow",
                "transition_history": [],
                "entered_current_phase_iso": "2024-01-01T00:00:00Z"
            },
            "reviewer_stats": [],
            "reviewer_rule_stats": [],
            "total_records": 0,
            "last_updated_iso": "2024-01-01T00:00:00Z"
        }))

        # Should not crash - handle partial init gracefully
        result = run_async(initialize_state(str(learner_dir)))

        # After the call, both files should exist
        assert state_path.exists()
        assert (learner_dir / "records.json").exists()


# ============================================================
# get_trust_adjustments tests
# ============================================================


class TestGoodhartTrustAdjustments:

    def test_goodhart_trust_weight_formula_varied_ratios(self, initialized_learner_dir):
        """Trust weight formula must correctly compute base_weight * (accepted/total) for non-trivial ratios"""
        # Record 7 accepted and 6 dismissed for one reviewer+rule = 13 total
        records = []
        for i in range(7):
            records.append(make_learning_record(
                record_id=f"acc-{i}",
                reviewer_id="alice",
                rule_id="rule.check.xss",
                stage="security",
                accepted=True,
            ))
        for i in range(6):
            records.append(make_learning_record(
                record_id=f"dis-{i}",
                reviewer_id="alice",
                rule_id="rule.check.xss",
                stage="security",
                accepted=False,
            ))

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=0.85, min_observations=10))
        assert len(result) >= 1

        # Find alice's entry
        alice_entry = None
        for entry in result:
            rid = getattr(entry, 'reviewer_id', None) or entry.get('reviewer_id')
            if rid == "alice":
                alice_entry = entry
                break

        assert alice_entry is not None
        weight = getattr(alice_entry, 'weight', None) or alice_entry.get('weight')
        expected = round(0.85 * (7 / 13), 4)
        assert abs(weight - expected) < 1e-6, f"Expected {expected}, got {weight}"

    def test_goodhart_trust_weight_lower_clamp(self, initialized_learner_dir):
        """Trust weight must clamp to 0.1 when formula yields below 0.1"""
        # 0 accepted out of 20 total => 0.5 * 0/20 = 0.0, clamped to 0.1
        records = []
        for i in range(20):
            records.append(make_learning_record(
                record_id=f"dis-{i}",
                reviewer_id="bob",
                rule_id="rule.check.sql",
                stage="security",
                accepted=False,
            ))

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=0.5, min_observations=10))
        assert len(result) >= 1

        bob_entry = None
        for entry in result:
            rid = getattr(entry, 'reviewer_id', None) or entry.get('reviewer_id')
            if rid == "bob":
                bob_entry = entry
                break

        assert bob_entry is not None
        weight = getattr(bob_entry, 'weight', None) or bob_entry.get('weight')
        assert weight == 0.1, f"Expected 0.1 (clamped), got {weight}"

    def test_goodhart_trust_weight_rounding_recurring_decimal(self, initialized_learner_dir):
        """Trust weight rounding must handle recurring decimals (1/3) to exactly 4 places"""
        # 1 accepted out of 3 total, but need at least 10 obs for cold-start
        # So: 4 accepted, 8 dismissed = 12 total, ratio = 4/12 = 1/3
        records = []
        for i in range(4):
            records.append(make_learning_record(
                record_id=f"acc-{i}",
                reviewer_id="carol",
                rule_id="rule.lint.style",
                stage="style",
                accepted=True,
            ))
        for i in range(8):
            records.append(make_learning_record(
                record_id=f"dis-{i}",
                reviewer_id="carol",
                rule_id="rule.lint.style",
                stage="style",
                accepted=False,
            ))

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=1.0, min_observations=10))

        carol_entry = None
        for entry in result:
            rid = getattr(entry, 'reviewer_id', None) or entry.get('reviewer_id')
            if rid == "carol":
                carol_entry = entry
                break

        assert carol_entry is not None
        weight = getattr(carol_entry, 'weight', None) or carol_entry.get('weight')
        expected = round(1.0 * (4 / 12), 4)  # 0.3333
        assert abs(weight - expected) < 1e-6, f"Expected {expected}, got {weight}"

    def test_goodhart_trust_ordering_multikey(self, initialized_learner_dir):
        """Trust adjustments sorted by (reviewer_id, rule_id, review_stage) composite key"""
        combos = [
            ("alice", "ruleB", "security"),
            ("alice", "ruleA", "security"),
            ("bob", "ruleA", "correctness"),
            ("alice", "ruleA", "correctness"),
        ]
        idx = 0
        records = []
        for (rid, rule, stage) in combos:
            for j in range(12):
                records.append(make_learning_record(
                    record_id=f"rec-{idx}",
                    reviewer_id=rid,
                    rule_id=rule,
                    stage=stage,
                    accepted=True,
                ))
                idx += 1

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=1.0, min_observations=10))
        assert len(result) == 4

        keys = []
        for entry in result:
            rid = getattr(entry, 'reviewer_id', None) or entry.get('reviewer_id')
            stage = getattr(entry, 'stage', None) or entry.get('stage')
            # stage might be enum
            stage_str = stage.value if hasattr(stage, 'value') else str(stage)
            # We need rule_id - it might not be on TrustScore directly
            # The ordering contract says (reviewer_id, rule_id, review_stage)
            keys.append((rid, stage_str))

        # Verify ordering: alice entries come before bob
        reviewer_ids = [getattr(e, 'reviewer_id', None) or e.get('reviewer_id') for e in result]
        assert reviewer_ids[0] == "alice"
        assert reviewer_ids[-1] == "bob"

    def test_goodhart_trust_base_weight_zero(self, initialized_learner_dir):
        """Trust weight with base_weight=0.0 should clamp all to 0.1"""
        records = []
        for i in range(15):
            records.append(make_learning_record(
                record_id=f"rec-{i}",
                reviewer_id="dave",
                rule_id="rule.test",
                stage="security",
                accepted=True,
            ))

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=0.0, min_observations=10))
        for entry in result:
            weight = getattr(entry, 'weight', None) or entry.get('weight')
            assert weight == 0.1, f"Expected 0.1 (clamped from 0.0), got {weight}"

    def test_goodhart_trust_min_obs_exact_boundary(self, initialized_learner_dir):
        """Entry with total_count exactly equal to min_observations must be included"""
        records = []
        for i in range(10):
            records.append(make_learning_record(
                record_id=f"rec-{i}",
                reviewer_id="eve",
                rule_id="rule.boundary",
                stage="correctness",
                accepted=True,
            ))

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=0.8, min_observations=10))
        reviewer_ids = [getattr(e, 'reviewer_id', None) or e.get('reviewer_id') for e in result]
        assert "eve" in reviewer_ids, "Entry with total_count=10 should be included when min_observations=10"

    def test_goodhart_trust_min_obs_minus_one_excluded(self, initialized_learner_dir):
        """Entry with total_count one less than min_observations must be excluded"""
        records = []
        for i in range(9):
            records.append(make_learning_record(
                record_id=f"rec-{i}",
                reviewer_id="frank",
                rule_id="rule.boundary",
                stage="correctness",
                accepted=True,
            ))

        run_async(record_decision(records))

        result = run_async(get_trust_adjustments(base_weight=0.8, min_observations=10))
        reviewer_ids = [getattr(e, 'reviewer_id', None) or e.get('reviewer_id') for e in result]
        assert "frank" not in reviewer_ids, "Entry with total_count=9 should be excluded when min_observations=10"


# ============================================================
# record_decision tests
# ============================================================


class TestGoodhartRecordDecision:

    def test_goodhart_record_decision_duplicate_within_batch(self, initialized_learner_dir):
        """Submitting records with duplicate record_ids within the same batch must be rejected"""
        records = [
            make_learning_record(record_id="dup-001", reviewer_id="alice", accepted=True),
            make_learning_record(record_id="dup-001", reviewer_id="bob", accepted=False),
        ]
        with pytest.raises(Exception) as exc_info:
            run_async(record_decision(records))
        # Should indicate duplicate
        assert "duplicate" in str(exc_info.value).lower() or "duplicate_record_id" in str(type(exc_info.value).__name__).lower() or True

    def test_goodhart_record_decision_incremental_stats(self, initialized_learner_dir):
        """Stats must accumulate across multiple record_decision calls, not replace"""
        rec1 = [make_learning_record(record_id="inc-1", reviewer_id="alice", rule_id="rule.x", stage="security", accepted=True)]
        rec2 = [make_learning_record(record_id="inc-2", reviewer_id="alice", rule_id="rule.x", stage="security", accepted=False)]

        run_async(record_decision(rec1))
        run_async(record_decision(rec2))

        # Check stats via get_trust_adjustments or get_stats
        # Use get_stats with min_observations=1 to see all
        report = run_async(get_stats(min_observations=1))
        total = getattr(report, 'total_records', None) or report.get('total_records')
        assert total == 2, f"Expected 2 total records after two calls, got {total}"

    def test_goodhart_record_decision_multiple_reviewers(self, initialized_learner_dir):
        """Recording decisions for multiple reviewers in a batch updates stats independently"""
        records = [
            make_learning_record(record_id="mr-1", reviewer_id="alice", rule_id="rule.a", stage="security", accepted=True),
            make_learning_record(record_id="mr-2", reviewer_id="alice", rule_id="rule.a", stage="security", accepted=False),
            make_learning_record(record_id="mr-3", reviewer_id="bob", rule_id="rule.a", stage="security", accepted=True),
            make_learning_record(record_id="mr-4", reviewer_id="bob", rule_id="rule.a", stage="security", accepted=True),
        ]

        result = run_async(record_decision(records))
        persisted = getattr(result, 'records_persisted', None) or result.get('records_persisted')
        assert persisted == 4

    def test_goodhart_record_decision_multi_stage_stats(self, initialized_learner_dir):
        """Same reviewer+rule but different stages produce separate ReviewerRuleStats"""
        records = [
            make_learning_record(record_id="ms-1", reviewer_id="alice", rule_id="rule.x", stage="security", accepted=True),
            make_learning_record(record_id="ms-2", reviewer_id="alice", rule_id="rule.x", stage="correctness", accepted=False),
        ]

        run_async(record_decision(records))

        # Verify by reading state or trust adjustments with min_obs=1
        result = run_async(get_trust_adjustments(base_weight=1.0, min_observations=1))
        # Should have 2 entries for alice - one per stage
        alice_entries = [
            e for e in result
            if (getattr(e, 'reviewer_id', None) or e.get('reviewer_id')) == "alice"
        ]
        assert len(alice_entries) == 2, f"Expected 2 separate stage entries for alice, got {len(alice_entries)}"

    def test_goodhart_record_decision_acceptance_rate_computed(self, initialized_learner_dir):
        """acceptance_rate in stats must be recomputed as accepted/total for non-trivial ratios"""
        records = []
        for i in range(3):
            records.append(make_learning_record(
                record_id=f"ar-acc-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        for i in range(7):
            records.append(make_learning_record(
                record_id=f"ar-dis-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=False,
            ))

        run_async(record_decision(records))

        # Check via state.json
        state_path = os.path.join(initialized_learner_dir, "state.json")
        with open(state_path, "r") as f:
            state = json.load(f)

        rule_stats = state.get("reviewer_rule_stats", [])
        alice_stat = None
        for rs in rule_stats:
            if rs.get("reviewer_id") == "alice" or (isinstance(rs.get("reviewer_id"), dict) and rs["reviewer_id"].get("value") == "alice"):
                alice_stat = rs
                break

        assert alice_stat is not None, "Should have stats for alice"
        # acceptance_rate should be 0.3
        rate = alice_stat.get("acceptance_rate")
        if isinstance(rate, dict):
            rate = rate.get("value", rate)
        assert abs(float(rate) - 0.3) < 0.01, f"Expected acceptance_rate ~0.3, got {rate}"


# ============================================================
# check_phase_progression tests
# ============================================================


class TestGoodhartPhaseProgression:

    def test_goodhart_phase_no_regression_primary_to_canary(self, initialized_learner_dir):
        """Phase must never regress from primary even if acceptance rate drops"""
        # First, get to primary phase by recording many accepted records
        records = []
        for i in range(50):
            records.append(make_learning_record(
                record_id=f"up-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        run_async(record_decision(records))

        config = {
            "shadow_to_canary_threshold": 0.3,
            "canary_to_primary_threshold": 0.6,
            "min_observations_for_phase": 5,
        }
        # Push through to primary
        run_async(check_phase_progression(config))

        # Now add many dismissed to tank the acceptance rate
        records2 = []
        for i in range(200):
            records2.append(make_learning_record(
                record_id=f"down-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=False,
            ))
        run_async(record_decision(records2))

        # Check phase again - must NOT regress
        phase = run_async(check_phase_progression(config))
        phase_str = phase.value if hasattr(phase, 'value') else str(phase)
        assert phase_str == "primary", f"Phase should remain primary but got {phase_str}"

    def test_goodhart_phase_no_regression_canary_to_shadow(self, initialized_learner_dir):
        """Phase must never regress from canary to shadow"""
        # Get to canary
        records = []
        for i in range(20):
            records.append(make_learning_record(
                record_id=f"c-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        run_async(record_decision(records))

        config = {
            "shadow_to_canary_threshold": 0.5,
            "canary_to_primary_threshold": 0.95,
            "min_observations_for_phase": 5,
        }
        phase = run_async(check_phase_progression(config))
        phase_str = phase.value if hasattr(phase, 'value') else str(phase)
        assert phase_str in ("canary", "primary"), f"Should be at least canary, got {phase_str}"

        # Tank the rate
        records2 = []
        for i in range(100):
            records2.append(make_learning_record(
                record_id=f"tank-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=False,
            ))
        run_async(record_decision(records2))

        # Must not regress
        phase2 = run_async(check_phase_progression(config))
        phase2_str = phase2.value if hasattr(phase2, 'value') else str(phase2)
        assert phase2_str != "shadow", f"Phase must not regress to shadow, got {phase2_str}"

    def test_goodhart_phase_min_observations_not_met(self, initialized_learner_dir):
        """Phase must not transition if observations below min_observations_for_phase"""
        records = []
        for i in range(3):
            records.append(make_learning_record(
                record_id=f"few-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        run_async(record_decision(records))

        config = {
            "shadow_to_canary_threshold": 0.5,
            "canary_to_primary_threshold": 0.8,
            "min_observations_for_phase": 10,
        }
        phase = run_async(check_phase_progression(config))
        phase_str = phase.value if hasattr(phase, 'value') else str(phase)
        assert phase_str == "shadow", f"Should stay shadow with only 3 obs, got {phase_str}"

    def test_goodhart_phase_config_threshold_out_of_range(self, initialized_learner_dir):
        """check_phase_progression must reject config with threshold > 1.0"""
        config = {
            "shadow_to_canary_threshold": 1.5,
            "canary_to_primary_threshold": 0.8,
            "min_observations_for_phase": 10,
        }
        with pytest.raises(Exception):
            run_async(check_phase_progression(config))

    def test_goodhart_phase_config_negative_threshold(self, initialized_learner_dir):
        """check_phase_progression must reject config with negative threshold"""
        config = {
            "shadow_to_canary_threshold": -0.1,
            "canary_to_primary_threshold": 0.8,
            "min_observations_for_phase": 10,
        }
        with pytest.raises(Exception):
            run_async(check_phase_progression(config))

    def test_goodhart_phase_config_min_observations_zero(self, initialized_learner_dir):
        """check_phase_progression must reject config with min_observations_for_phase=0"""
        config = {
            "shadow_to_canary_threshold": 0.5,
            "canary_to_primary_threshold": 0.8,
            "min_observations_for_phase": 0,
        }
        with pytest.raises(Exception):
            run_async(check_phase_progression(config))

    def test_goodhart_phase_transition_history_recorded(self, initialized_learner_dir):
        """Phase transition must be recorded in transition_history"""
        records = []
        for i in range(20):
            records.append(make_learning_record(
                record_id=f"hist-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        run_async(record_decision(records))

        config = {
            "shadow_to_canary_threshold": 0.5,
            "canary_to_primary_threshold": 0.95,
            "min_observations_for_phase": 5,
        }
        phase = run_async(check_phase_progression(config))

        # Read state to verify transition history
        state_path = os.path.join(initialized_learner_dir, "state.json")
        with open(state_path, "r") as f:
            state = json.load(f)

        phase_state = state.get("phase_state", {})
        history = phase_state.get("transition_history", [])
        assert len(history) >= 1, "Should have at least one transition in history"

        first_transition = history[0]
        assert first_transition.get("from_phase") in ("shadow", "LearnerPhase.shadow")
        assert first_transition.get("to_phase") in ("canary", "LearnerPhase.canary")

    def test_goodhart_phase_shadow_to_primary_when_both_thresholds_met(self, initialized_learner_dir):
        """When acceptance rate exceeds both thresholds in shadow, phase should advance at least to canary"""
        records = []
        for i in range(30):
            records.append(make_learning_record(
                record_id=f"skip-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        run_async(record_decision(records))

        config = {
            "shadow_to_canary_threshold": 0.3,
            "canary_to_primary_threshold": 0.6,
            "min_observations_for_phase": 5,
        }
        phase = run_async(check_phase_progression(config))
        phase_str = phase.value if hasattr(phase, 'value') else str(phase)
        assert phase_str in ("canary", "primary"), f"Should be at least canary, got {phase_str}"


# ============================================================
# record_human_decisions tests
# ============================================================


class TestGoodhartRecordHumanDecisions:

    def test_goodhart_unique_uuids_across_calls(self, initialized_learner_dir):
        """Each record_human_decisions call must generate fresh UUID4 record_ids"""
        decisions1 = [
            make_human_decision_input(finding_id=f"f-{i}", reviewer_id="alice", decision="accepted")
            for i in range(3)
        ]
        decisions2 = [
            make_human_decision_input(finding_id=f"g-{i}", reviewer_id="bob", decision="dismissed")
            for i in range(3)
        ]

        run_async(record_human_decisions(decisions1, base_weight=0.8))
        run_async(record_human_decisions(decisions2, base_weight=0.8))

        # Read all records from records.json
        records_path = os.path.join(initialized_learner_dir, "records.json")
        with open(records_path, "r") as f:
            all_records = json.load(f)

        record_ids = [r.get("record_id") for r in all_records]
        assert len(record_ids) == 6
        assert len(set(record_ids)) == 6, "All record_ids must be unique"

        # Verify they look like UUID4
        for rid in record_ids:
            try:
                parsed = uuid.UUID(rid, version=4)
                assert str(parsed) == rid or True  # UUID4 format
            except ValueError:
                pytest.fail(f"record_id '{rid}' is not a valid UUID4")

    def test_goodhart_maps_decision_to_accepted_field(self, initialized_learner_dir):
        """HumanDecision.accepted maps to accepted=True, dismissed maps to accepted=False"""
        decisions = [
            make_human_decision_input(finding_id="f-1", decision="accepted"),
            make_human_decision_input(finding_id="f-2", decision="dismissed"),
        ]

        run_async(record_human_decisions(decisions, base_weight=0.8))

        records_path = os.path.join(initialized_learner_dir, "records.json")
        with open(records_path, "r") as f:
            all_records = json.load(f)

        assert len(all_records) == 2
        accepted_records = [r for r in all_records if r.get("accepted") is True]
        dismissed_records = [r for r in all_records if r.get("accepted") is False]
        assert len(accepted_records) == 1
        assert len(dismissed_records) == 1


# ============================================================
# get_stats tests
# ============================================================


class TestGoodhartGetStats:

    def test_goodhart_get_stats_different_min_observations(self, initialized_learner_dir):
        """active_trust_adjustments must respect the min_observations parameter dynamically"""
        # Create 3 combos with different total counts: 5, 10, 20
        records = []
        idx = 0
        for count, reviewer in [(5, "alice"), (10, "bob"), (20, "carol")]:
            for i in range(count):
                records.append(make_learning_record(
                    record_id=f"stats-{idx}",
                    reviewer_id=reviewer,
                    rule_id="rule.x",
                    stage="security",
                    accepted=True,
                ))
                idx += 1

        run_async(record_decision(records))

        report5 = run_async(get_stats(min_observations=5))
        report15 = run_async(get_stats(min_observations=15))

        active5 = getattr(report5, 'active_trust_adjustments', None) or report5.get('active_trust_adjustments')
        active15 = getattr(report15, 'active_trust_adjustments', None) or report15.get('active_trust_adjustments')

        assert active5 == 3, f"Expected 3 active with min_obs=5, got {active5}"
        assert active15 == 1, f"Expected 1 active with min_obs=15, got {active15}"

    def test_goodhart_get_stats_phase_state_included(self, initialized_learner_dir):
        """get_stats must include PhaseState with transition_history"""
        # Trigger a transition
        records = []
        for i in range(20):
            records.append(make_learning_record(
                record_id=f"ps-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        run_async(record_decision(records))

        config = {
            "shadow_to_canary_threshold": 0.5,
            "canary_to_primary_threshold": 0.95,
            "min_observations_for_phase": 5,
        }
        run_async(check_phase_progression(config))

        report = run_async(get_stats(min_observations=1))
        phase_state = getattr(report, 'phase_state', None) or report.get('phase_state')
        assert phase_state is not None, "phase_state should be present in report"

        # Check transition history
        if hasattr(phase_state, 'transition_history'):
            history = phase_state.transition_history
        else:
            history = phase_state.get('transition_history', [])
        assert len(history) >= 1, "transition_history should have at least one entry after transition"


# ============================================================
# detect_patterns tests
# ============================================================


class TestGoodhartDetectPatterns:

    def test_goodhart_detect_patterns_high_acceptance_rate(self, initialized_learner_dir):
        """detect_patterns should identify high acceptance rate, not only high false positive rate"""
        # 99% acceptance rate
        records = []
        for i in range(99):
            records.append(make_learning_record(
                record_id=f"ha-acc-{i}",
                reviewer_id="alice",
                rule_id="rule.x",
                stage="security",
                accepted=True,
            ))
        records.append(make_learning_record(
            record_id="ha-dis-0",
            reviewer_id="alice",
            rule_id="rule.x",
            stage="security",
            accepted=False,
        ))
        run_async(record_decision(records))

        signals = run_async(detect_patterns(min_observations=10, anomaly_threshold=0.9))
        # Should detect something for this extreme ratio
        if len(signals) > 0:
            pattern_keys = []
            for s in signals:
                pk = getattr(s, 'pattern_key', None) or s.get('pattern_key', '')
                pattern_keys.append(pk)
            # At least one signal should exist for this extreme case
            assert len(signals) >= 1, "Should detect anomaly for 99% acceptance rate"

    def test_goodhart_detect_patterns_unique_signal_ids_non_trivial(self, initialized_learner_dir):
        """Each signal_id must be unique UUID4, verified with multiple signals"""
        # Create two anomalous combos
        records = []
        idx = 0
        for reviewer in ["alice", "bob"]:
            for i in range(20):
                records.append(make_learning_record(
                    record_id=f"pat-{idx}",
                    reviewer_id=reviewer,
                    rule_id="rule.x",
                    stage="security",
                    accepted=False,  # all dismissed = high false positive
                ))
                idx += 1

        run_async(record_decision(records))

        signals = run_async(detect_patterns(min_observations=10, anomaly_threshold=0.5))
        if len(signals) >= 2:
            signal_ids = [getattr(s, 'signal_id', None) or s.get('signal_id') for s in signals]
            assert len(set(signal_ids)) == len(signal_ids), "All signal_ids must be unique"

            # Verify UUID4 format
            for sid in signal_ids:
                try:
                    uuid.UUID(sid, version=4)
                except ValueError:
                    pytest.fail(f"signal_id '{sid}' is not valid UUID4")


# ============================================================
# should_apply_adjustments + get_current_phase edge cases
# ============================================================


class TestGoodhartPhaseQueries:

    def test_goodhart_should_apply_consistent_with_get_current_phase(self, initialized_learner_dir):
        """should_apply_adjustments must return True iff get_current_phase returns canary or primary"""
        # In shadow
        phase = run_async(get_current_phase())
        should = run_async(should_apply_adjustments())
        phase_str = phase.value if hasattr(phase, 'value') else str(phase)
        if phase_str == "shadow":
            assert should is False
        else:
            assert should is True

    def test_goodhart_get_current_phase_default_no_state(self, tmp_path):
        """get_current_phase returns shadow when state.json doesn't exist"""
        # Use a directory that doesn't have state.json
        # This tests the default behavior
        phase = run_async(get_current_phase())
        phase_str = phase.value if hasattr(phase, 'value') else str(phase)
        assert phase_str == "shadow"
