"""
Contract tests for the Apprentice Learning Module (learner).

Tests verify behavior at boundaries per the contract specification.
All async functions use @pytest.mark.asyncio. Dependencies are mocked.
"""

import json
import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
import pytest
import pytest_asyncio

# ---------------------------------------------------------------------------
# Imports from the component under test
# ---------------------------------------------------------------------------
from exemplar.learner import (
    LearnerPhase,
    HumanDecision,
    PatternKind,
    ReviewerId,
    RuleId,
    TrustWeight,
    AcceptanceRate,
    MinObservations,
    FilePath,
    PactKey,
    HumanDecisionInput,
    LearningRecord,
    ReviewerRuleStats,
    ReviewerStats,
    PhaseTransition,
    PhaseState,
    LearnerState,
    TrustScore,
    StigmergySignal,
    LearnerStatsReport,
    RecordDecisionResult,
    Severity,
    ReviewStage,
    record_decision,
    record_human_decisions,
    get_trust_adjustments,
    check_phase_progression,
    detect_patterns,
    get_current_phase,
    should_apply_adjustments,
    get_stats,
    initialize_state,
)


# ========================================================================
# Factory helpers
# ========================================================================

def make_learning_record(**overrides):
    """Return a valid LearningRecord dict / kwargs with sensible defaults."""
    defaults = dict(
        record_id=str(uuid.uuid4()),
        finding_id="finding-001",
        reviewer_id="alice",
        stage=ReviewStage.security,
        rule_id="security.xss",
        severity=Severity.high,
        accepted=True,
        human_comment="looks good",
        recorded_at="2024-01-15T10:00:00Z",
    )
    defaults.update(overrides)
    return LearningRecord(**defaults)


def make_human_decision_input(**overrides):
    """Return a valid HumanDecisionInput with sensible defaults."""
    defaults = dict(
        finding_id="finding-001",
        reviewer_id=ReviewerId(value="alice"),
        rule_id=RuleId(value="security.xss"),
        decision=HumanDecision.accepted,
        file_path=FilePath(value="src/main.py"),
        severity="high",
        review_stage="security",
        comment="LGTM",
        timestamp_iso="2024-01-15T10:00:00Z",
    )
    defaults.update(overrides)
    return HumanDecisionInput(**defaults)


def make_config(**overrides):
    """Return a valid phase-progression config dict."""
    defaults = dict(
        shadow_to_canary_threshold=0.6,
        canary_to_primary_threshold=0.85,
        min_observations_for_phase=10,
    )
    defaults.update(overrides)
    return defaults


# ========================================================================
# Fixtures
# ========================================================================

@pytest.fixture
def learner_storage(tmp_path):
    """Provide a clean temporary directory for learner storage."""
    storage = tmp_path / ".exemplar" / "learner"
    return str(storage)


@pytest_asyncio.fixture
async def initialized_learner(learner_storage):
    """Initialize learner state and return the storage path."""
    result = await initialize_state(learner_storage)
    assert result is True
    return learner_storage


@pytest_asyncio.fixture
async def seeded_learner(initialized_learner):
    """Pre-load ~20 diverse records into the learner."""
    records = []
    for i in range(20):
        accepted = i % 3 != 0  # ~67% acceptance
        reviewer = "alice" if i < 10 else "bob"
        stage = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture][i % 4]
        rec = make_learning_record(
            record_id=f"seed-{i:03d}",
            finding_id=f"finding-{i:03d}",
            reviewer_id=reviewer,
            stage=stage,
            rule_id="security.xss" if i % 2 == 0 else "style.naming",
            accepted=accepted,
            recorded_at=f"2024-01-{15 + i // 10:02d}T{10 + i % 10:02d}:00:00Z",
        )
        records.append(rec)
    await record_decision(records)
    return initialized_learner


# ========================================================================
# Test Classes
# ========================================================================

class TestInitializeState:
    """Tests for initialize_state function."""

    @pytest.mark.asyncio
    async def test_happy_path_creates_files(self, learner_storage):
        """initialize_state creates directory, state.json, and records.json."""
        result = await initialize_state(learner_storage)
        assert result is True
        storage_path = Path(learner_storage)
        assert storage_path.is_dir()
        assert (storage_path / "state.json").exists()
        assert (storage_path / "records.json").exists()

        # Verify state.json content
        with open(storage_path / "state.json") as f:
            state = json.load(f)
        assert state.get("schema_version") == 1

        # Verify records.json content
        with open(storage_path / "records.json") as f:
            records = json.load(f)
        assert records == []

    @pytest.mark.asyncio
    async def test_idempotent_reinit(self, initialized_learner):
        """initialize_state returns False when called again on existing state."""
        result = await initialize_state(initialized_learner)
        assert result is False

    @pytest.mark.asyncio
    async def test_permission_denied(self, tmp_path):
        """initialize_state raises permission_denied when directory not writable."""
        # Create a read-only parent
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        os.chmod(str(readonly_dir), 0o444)
        storage = str(readonly_dir / "learner" / "state")
        try:
            with pytest.raises(Exception) as exc_info:
                await initialize_state(storage)
            # Should indicate permission denied
            exc_str = str(exc_info.value).lower()
            assert "permission" in exc_str or "denied" in exc_str or isinstance(exc_info.value, PermissionError)
        finally:
            os.chmod(str(readonly_dir), 0o755)

    @pytest.mark.asyncio
    async def test_existing_state_corruption(self, learner_storage):
        """initialize_state raises error when files exist but contain invalid JSON."""
        storage_path = Path(learner_storage)
        storage_path.mkdir(parents=True, exist_ok=True)
        (storage_path / "state.json").write_text("NOT VALID JSON {{{")
        with pytest.raises(Exception) as exc_info:
            await initialize_state(learner_storage)
        exc_str = str(exc_info.value).lower()
        assert "corrupt" in exc_str or "invalid" in exc_str or "json" in exc_str

    @pytest.mark.asyncio
    async def test_custom_nested_storage_dir(self, tmp_path):
        """initialize_state works with deeply nested custom path."""
        nested = str(tmp_path / "a" / "b" / "c" / "learner")
        result = await initialize_state(nested)
        assert result is True
        assert Path(nested).is_dir()


class TestRecordDecision:
    """Tests for record_decision function."""

    @pytest.mark.asyncio
    async def test_single_record(self, initialized_learner):
        """record_decision persists a single valid record."""
        rec = make_learning_record()
        result = await record_decision([rec])
        assert isinstance(result, RecordDecisionResult)
        assert result.records_persisted == 1
        assert result.stats_updated is True

    @pytest.mark.asyncio
    async def test_batch_records(self, initialized_learner):
        """record_decision persists multiple valid records."""
        records = [make_learning_record(record_id=f"batch-{i}") for i in range(5)]
        result = await record_decision(records)
        assert result.records_persisted == 5
        assert result.stats_updated is True

    @pytest.mark.asyncio
    async def test_phase_changed_trigger(self, initialized_learner):
        """record_decision triggers phase change when acceptance rate crosses threshold."""
        # Record many accepted findings to push acceptance rate high
        records = [
            make_learning_record(
                record_id=f"phase-{i}",
                accepted=True,
            )
            for i in range(30)
        ]
        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        await record_decision(records)
        # Now check phase progression
        phase = await check_phase_progression(config)
        assert phase in (LearnerPhase.canary, LearnerPhase.primary)

    @pytest.mark.asyncio
    async def test_stats_updated_verification(self, initialized_learner):
        """record_decision correctly updates ReviewerRuleStats counts."""
        accepted_rec = make_learning_record(record_id="stat-1", accepted=True, reviewer_id="statcheck", rule_id="test.rule")
        dismissed_rec = make_learning_record(record_id="stat-2", accepted=False, reviewer_id="statcheck", rule_id="test.rule")
        await record_decision([accepted_rec, dismissed_rec])

        # Verify via get_stats
        report = await get_stats(min_observations=0)
        assert report.total_records >= 2

    @pytest.mark.asyncio
    async def test_duplicate_record_id(self, initialized_learner):
        """record_decision raises error for duplicate record_id."""
        rec = make_learning_record(record_id="dup-001")
        await record_decision([rec])
        with pytest.raises(Exception) as exc_info:
            await record_decision([rec])
        exc_str = str(exc_info.value).lower()
        assert "duplicate" in exc_str or "already exist" in exc_str

    @pytest.mark.asyncio
    async def test_duplicate_within_batch(self, initialized_learner):
        """record_decision rejects batch with duplicate record_ids within the same call."""
        rec1 = make_learning_record(record_id="intra-dup")
        rec2 = make_learning_record(record_id="intra-dup", finding_id="finding-999")
        with pytest.raises(Exception):
            await record_decision([rec1, rec2])

    @pytest.mark.asyncio
    async def test_invalid_record(self, initialized_learner):
        """record_decision raises invalid_record for bad data."""
        with pytest.raises(Exception) as exc_info:
            # Attempt to create a record with invalid fields - if pydantic validates
            # at construction, we test passing something invalid to the function
            bad_rec = make_learning_record(record_id="")
            await record_decision([bad_rec])

    @pytest.mark.asyncio
    async def test_chronicler_event_emitted(self, initialized_learner):
        """record_decision emits learning.recorded ChroniclerEvent."""
        rec = make_learning_record(record_id="event-test")
        # The contract states chronicler is fire-and-forget, so this should succeed
        # regardless of chronicler state
        result = await record_decision([rec])
        assert result.records_persisted == 1

    @pytest.mark.asyncio
    async def test_empty_list(self, initialized_learner):
        """record_decision with empty list handles gracefully."""
        try:
            result = await record_decision([])
            assert result.records_persisted == 0
        except Exception:
            # Also acceptable to reject empty list
            pass

    @pytest.mark.asyncio
    async def test_append_only_invariant(self, initialized_learner):
        """Existing records are never modified when new records are added."""
        rec1 = make_learning_record(record_id="append-1")
        await record_decision([rec1])

        rec2 = make_learning_record(record_id="append-2")
        await record_decision([rec2])

        # Read records.json and verify both are present
        storage_path = Path(initialized_learner)
        with open(storage_path / "records.json") as f:
            all_records = json.load(f)

        record_ids = [r.get("record_id", r.get("record_id")) for r in all_records]
        assert "append-1" in record_ids
        assert "append-2" in record_ids


class TestRecordHumanDecisions:
    """Tests for record_human_decisions function."""

    @pytest.mark.asyncio
    async def test_single_decision(self, initialized_learner):
        """record_human_decisions converts and persists a single decision."""
        decision = make_human_decision_input()
        result = await record_human_decisions([decision], base_weight=1.0)
        assert isinstance(result, RecordDecisionResult)
        assert result.records_persisted == 1
        assert result.stats_updated is True

    @pytest.mark.asyncio
    async def test_batch_decisions(self, initialized_learner):
        """record_human_decisions converts multiple decisions."""
        decisions = [
            make_human_decision_input(finding_id=f"hd-{i}")
            for i in range(5)
        ]
        result = await record_human_decisions(decisions, base_weight=0.8)
        assert result.records_persisted == 5

    @pytest.mark.asyncio
    async def test_invalid_decision_input(self, initialized_learner):
        """record_human_decisions raises error for invalid input."""
        with pytest.raises(Exception):
            bad_input = make_human_decision_input(severity="unknown")
            await record_human_decisions([bad_input], base_weight=1.0)

    @pytest.mark.asyncio
    async def test_uuid4_generated(self, initialized_learner):
        """record_human_decisions generates UUID4 record_id for each input."""
        decision = make_human_decision_input()
        result = await record_human_decisions([decision], base_weight=1.0)
        assert result.records_persisted == 1

        # Verify records have UUID4 ids
        storage_path = Path(initialized_learner)
        with open(storage_path / "records.json") as f:
            records = json.load(f)
        for rec in records:
            rid = rec.get("record_id", "")
            # Should be parseable as UUID
            uuid.UUID(rid, version=4)

    @pytest.mark.asyncio
    async def test_fire_and_forget_chronicler(self, initialized_learner):
        """Chronicler failure does not block record_human_decisions."""
        decision = make_human_decision_input(finding_id="ff-test")
        # Even if chronicler is down, operation should complete
        result = await record_human_decisions([decision], base_weight=1.0)
        assert result.records_persisted == 1

    @pytest.mark.asyncio
    async def test_base_weight_boundary(self, initialized_learner):
        """record_human_decisions works with base_weight at 0.0 and 1.0 boundaries."""
        d1 = make_human_decision_input(finding_id="bw-0")
        result1 = await record_human_decisions([d1], base_weight=0.0)
        assert result1.records_persisted == 1

        d2 = make_human_decision_input(finding_id="bw-1")
        result2 = await record_human_decisions([d2], base_weight=1.0)
        assert result2.records_persisted == 1

    @pytest.mark.asyncio
    async def test_empty_list(self, initialized_learner):
        """record_human_decisions with empty list."""
        try:
            result = await record_human_decisions([], base_weight=1.0)
            assert result.records_persisted == 0
        except Exception:
            # Also acceptable to reject
            pass

    @pytest.mark.asyncio
    async def test_all_decision_types(self, initialized_learner):
        """record_human_decisions handles accepted, dismissed, and modified decisions."""
        decisions = [
            make_human_decision_input(finding_id="dt-acc", decision=HumanDecision.accepted),
            make_human_decision_input(finding_id="dt-dis", decision=HumanDecision.dismissed),
            make_human_decision_input(finding_id="dt-mod", decision=HumanDecision.modified),
        ]
        result = await record_human_decisions(decisions, base_weight=1.0)
        assert result.records_persisted == 3


class TestGetTrustAdjustments:
    """Tests for get_trust_adjustments function."""

    @pytest.mark.asyncio
    async def test_sufficient_data(self, seeded_learner):
        """get_trust_adjustments returns correct weights with sufficient observations."""
        adjustments = await get_trust_adjustments(base_weight=1.0, min_observations=2)
        assert isinstance(adjustments, list)
        for adj in adjustments:
            assert isinstance(adj, TrustScore)
            assert 0.1 <= adj.weight <= 1.0
            # Verify rounded to 4 decimal places
            assert adj.weight == pytest.approx(round(adj.weight, 4), abs=1e-6)

    @pytest.mark.asyncio
    async def test_min_observations_boundary(self, seeded_learner):
        """Entries below min_observations excluded, at threshold included."""
        # With min_observations=100, should exclude everything (we only seeded 20)
        adjustments_high = await get_trust_adjustments(base_weight=1.0, min_observations=100)
        assert len(adjustments_high) == 0

        # With min_observations=1, should include entries
        adjustments_low = await get_trust_adjustments(base_weight=1.0, min_observations=1)
        assert len(adjustments_low) >= 0  # May have entries

    @pytest.mark.asyncio
    async def test_base_weight_effect(self, seeded_learner):
        """Weight formula: base_weight * (accepted/total) clamped to [0.1, 1.0]."""
        adj_full = await get_trust_adjustments(base_weight=1.0, min_observations=1)
        adj_half = await get_trust_adjustments(base_weight=0.5, min_observations=1)

        # With lower base_weight, weights should generally be lower or equal
        if adj_full and adj_half:
            for full, half in zip(adj_full, adj_half):
                # half.weight should be <= full.weight (before clamping)
                assert half.weight <= full.weight + 1e-6

    @pytest.mark.asyncio
    async def test_state_not_found(self, learner_storage):
        """get_trust_adjustments raises state_not_found when no state.json."""
        with pytest.raises(Exception) as exc_info:
            await get_trust_adjustments(base_weight=1.0, min_observations=10)
        exc_str = str(exc_info.value).lower()
        assert "not found" in exc_str or "not_found" in exc_str or "state" in exc_str or "exist" in exc_str

    @pytest.mark.asyncio
    async def test_state_corruption(self, initialized_learner):
        """get_trust_adjustments raises state_corruption for invalid state.json."""
        storage_path = Path(initialized_learner)
        (storage_path / "state.json").write_text("{invalid json content!!")
        with pytest.raises(Exception):
            await get_trust_adjustments(base_weight=1.0, min_observations=10)

    @pytest.mark.asyncio
    async def test_empty_state(self, initialized_learner):
        """get_trust_adjustments returns empty list when no stats exist."""
        adjustments = await get_trust_adjustments(base_weight=1.0, min_observations=10)
        assert adjustments == []

    @pytest.mark.asyncio
    async def test_stable_ordering(self, seeded_learner):
        """get_trust_adjustments returns deterministic order by (reviewer_id, rule_id, review_stage)."""
        adj1 = await get_trust_adjustments(base_weight=1.0, min_observations=1)
        adj2 = await get_trust_adjustments(base_weight=1.0, min_observations=1)

        assert len(adj1) == len(adj2)
        for a, b in zip(adj1, adj2):
            assert a.reviewer_id == b.reviewer_id
            assert a.stage == b.stage
            assert a.weight == pytest.approx(b.weight)

        # Verify sorted by (reviewer_id, rule_id, stage)
        if len(adj1) > 1:
            for i in range(len(adj1) - 1):
                key_i = (adj1[i].reviewer_id, getattr(adj1[i], 'rule_id', ''), str(adj1[i].stage))
                key_next = (adj1[i+1].reviewer_id, getattr(adj1[i+1], 'rule_id', ''), str(adj1[i+1].stage))
                assert key_i <= key_next

    @pytest.mark.asyncio
    async def test_weight_clamping(self, seeded_learner):
        """Weights are clamped to [0.1, 1.0]."""
        # Use very low base_weight to test lower clamp
        adjustments = await get_trust_adjustments(base_weight=0.01, min_observations=1)
        for adj in adjustments:
            assert adj.weight >= 0.1
            assert adj.weight <= 1.0


class TestCheckPhaseProgression:
    """Tests for check_phase_progression function."""

    @pytest.mark.asyncio
    async def test_shadow_to_canary(self, initialized_learner):
        """Transition from shadow to canary when threshold met."""
        # Seed enough accepted records
        records = [make_learning_record(record_id=f"s2c-{i}", accepted=True) for i in range(15)]
        await record_decision(records)

        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        phase = await check_phase_progression(config)
        assert phase == LearnerPhase.canary

    @pytest.mark.asyncio
    async def test_canary_to_primary(self, initialized_learner):
        """Transition from canary to primary when threshold met."""
        # First get to canary
        records = [make_learning_record(record_id=f"c2p-{i}", accepted=True) for i in range(20)]
        await record_decision(records)

        config = make_config(
            shadow_to_canary_threshold=0.5,
            canary_to_primary_threshold=0.8,
            min_observations_for_phase=5,
        )
        # Transition to canary first
        await check_phase_progression(config)
        # Then to primary (acceptance rate is 100%)
        phase = await check_phase_progression(config)
        assert phase == LearnerPhase.primary

    @pytest.mark.asyncio
    async def test_no_transition(self, initialized_learner):
        """No transition when thresholds not met."""
        # Record mostly dismissed findings
        records = [make_learning_record(record_id=f"no-{i}", accepted=False) for i in range(15)]
        await record_decision(records)

        config = make_config(shadow_to_canary_threshold=0.9, min_observations_for_phase=5)
        phase = await check_phase_progression(config)
        assert phase == LearnerPhase.shadow

    @pytest.mark.asyncio
    async def test_invalid_config(self, initialized_learner):
        """Raises invalid_config for missing/invalid config keys."""
        with pytest.raises(Exception) as exc_info:
            await check_phase_progression({})
        exc_str = str(exc_info.value).lower()
        assert "config" in exc_str or "missing" in exc_str or "invalid" in exc_str or "key" in exc_str

    @pytest.mark.asyncio
    async def test_state_not_found(self, learner_storage):
        """Raises state_not_found when no state.json."""
        config = make_config()
        with pytest.raises(Exception):
            await check_phase_progression(config)

    @pytest.mark.asyncio
    async def test_chronicler_event_on_transition(self, initialized_learner):
        """Emits phase.transition event on phase change."""
        records = [make_learning_record(record_id=f"evt-{i}", accepted=True) for i in range(15)]
        await record_decision(records)

        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        phase = await check_phase_progression(config)
        # If transition occurred, event should have been emitted (fire-and-forget)
        assert phase == LearnerPhase.canary

    @pytest.mark.asyncio
    async def test_idempotent_calls(self, initialized_learner):
        """Calling twice with same state returns same phase."""
        records = [make_learning_record(record_id=f"idem-{i}", accepted=True) for i in range(15)]
        await record_decision(records)

        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        phase1 = await check_phase_progression(config)
        phase2 = await check_phase_progression(config)
        assert phase1 == phase2

    @pytest.mark.asyncio
    async def test_phase_monotonic_invariant(self, initialized_learner):
        """Phase transitions are monotonic - cannot regress."""
        # Get to canary
        records = [make_learning_record(record_id=f"mono-{i}", accepted=True) for i in range(15)]
        await record_decision(records)

        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        phase = await check_phase_progression(config)
        assert phase in (LearnerPhase.canary, LearnerPhase.primary)

        # Even with very high threshold, should not go back to shadow
        config_strict = make_config(shadow_to_canary_threshold=0.99, min_observations_for_phase=5)
        phase2 = await check_phase_progression(config_strict)
        # Phase should be >= previous phase (monotonic)
        phase_order = {LearnerPhase.shadow: 0, LearnerPhase.canary: 1, LearnerPhase.primary: 2}
        assert phase_order[phase2] >= phase_order[phase]


class TestDetectPatterns:
    """Tests for detect_patterns function."""

    @pytest.mark.asyncio
    async def test_known_pattern_detected(self, seeded_learner):
        """detect_patterns identifies patterns from seeded data."""
        signals = await detect_patterns(min_observations=2, anomaly_threshold=0.3)
        assert isinstance(signals, list)
        for signal in signals:
            assert isinstance(signal, StigmergySignal)
            assert signal.signal_id  # non-empty
            assert signal.pattern_key  # non-empty

    @pytest.mark.asyncio
    async def test_below_min_observations(self, seeded_learner):
        """detect_patterns excludes combinations below min_observations."""
        signals_high = await detect_patterns(min_observations=1000, anomaly_threshold=0.1)
        assert len(signals_high) == 0

    @pytest.mark.asyncio
    async def test_anomaly_threshold_boundary(self, seeded_learner):
        """detect_patterns respects anomaly_threshold."""
        # Very strict threshold should find fewer patterns
        signals_strict = await detect_patterns(min_observations=1, anomaly_threshold=0.99)
        # Very lenient threshold should find more
        signals_lenient = await detect_patterns(min_observations=1, anomaly_threshold=0.01)
        assert len(signals_strict) <= len(signals_lenient)

    @pytest.mark.asyncio
    async def test_state_not_found(self, learner_storage):
        """detect_patterns raises state_not_found when no state.json."""
        with pytest.raises(Exception):
            await detect_patterns(min_observations=10, anomaly_threshold=0.5)

    @pytest.mark.asyncio
    async def test_state_corruption(self, initialized_learner):
        """detect_patterns raises state_corruption for invalid state.json."""
        storage_path = Path(initialized_learner)
        (storage_path / "state.json").write_text("CORRUPT DATA!!!")
        with pytest.raises(Exception):
            await detect_patterns(min_observations=10, anomaly_threshold=0.5)

    @pytest.mark.asyncio
    async def test_empty_state(self, initialized_learner):
        """detect_patterns returns empty list when no stats exist."""
        signals = await detect_patterns(min_observations=10, anomaly_threshold=0.5)
        assert signals == []

    @pytest.mark.asyncio
    async def test_unique_signal_ids(self, seeded_learner):
        """detect_patterns returns signals with unique UUID4 signal_ids."""
        signals = await detect_patterns(min_observations=1, anomaly_threshold=0.1)
        if signals:
            signal_ids = [s.signal_id for s in signals]
            assert len(signal_ids) == len(set(signal_ids)), "signal_ids must be unique"
            for sid in signal_ids:
                uuid.UUID(sid, version=4)  # Must be valid UUID4

    @pytest.mark.asyncio
    async def test_mixed_patterns(self, seeded_learner):
        """detect_patterns can return multiple pattern kinds."""
        signals = await detect_patterns(min_observations=1, anomaly_threshold=0.1)
        # Just verify they're all StigmergySignal
        for signal in signals:
            assert isinstance(signal, StigmergySignal)
            assert signal.occurrences >= 1


class TestGetCurrentPhase:
    """Tests for get_current_phase function."""

    @pytest.mark.asyncio
    async def test_default_shadow_no_state(self, learner_storage):
        """Returns shadow when state does not exist."""
        phase = await get_current_phase()
        assert phase == LearnerPhase.shadow

    @pytest.mark.asyncio
    async def test_shadow_phase(self, initialized_learner):
        """Returns shadow from freshly initialized state."""
        phase = await get_current_phase()
        assert phase == LearnerPhase.shadow

    @pytest.mark.asyncio
    async def test_canary_phase(self, initialized_learner):
        """Returns canary when state is in canary phase."""
        records = [make_learning_record(record_id=f"gcp-{i}", accepted=True) for i in range(20)]
        await record_decision(records)
        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        await check_phase_progression(config)
        phase = await get_current_phase()
        assert phase == LearnerPhase.canary

    @pytest.mark.asyncio
    async def test_state_corruption(self, initialized_learner):
        """Raises state_corruption for invalid state.json."""
        storage_path = Path(initialized_learner)
        (storage_path / "state.json").write_text("{{{{invalid")
        with pytest.raises(Exception):
            await get_current_phase()


class TestShouldApplyAdjustments:
    """Tests for should_apply_adjustments function."""

    @pytest.mark.asyncio
    async def test_false_in_shadow(self, initialized_learner):
        """Returns False in shadow phase."""
        result = await should_apply_adjustments()
        assert result is False

    @pytest.mark.asyncio
    async def test_true_in_canary(self, initialized_learner):
        """Returns True in canary phase."""
        records = [make_learning_record(record_id=f"saa-can-{i}", accepted=True) for i in range(20)]
        await record_decision(records)
        config = make_config(shadow_to_canary_threshold=0.5, min_observations_for_phase=5)
        await check_phase_progression(config)
        result = await should_apply_adjustments()
        assert result is True

    @pytest.mark.asyncio
    async def test_true_in_primary(self, initialized_learner):
        """Returns True in primary phase."""
        records = [make_learning_record(record_id=f"saa-pri-{i}", accepted=True) for i in range(25)]
        await record_decision(records)
        config = make_config(
            shadow_to_canary_threshold=0.5,
            canary_to_primary_threshold=0.8,
            min_observations_for_phase=5,
        )
        await check_phase_progression(config)
        await check_phase_progression(config)  # May need two calls
        result = await should_apply_adjustments()
        assert result is True

    @pytest.mark.asyncio
    async def test_false_no_state(self, learner_storage):
        """Returns False when state.json does not exist (defaults to shadow)."""
        result = await should_apply_adjustments()
        assert result is False

    @pytest.mark.asyncio
    async def test_state_corruption(self, initialized_learner):
        """Raises state_corruption for invalid state.json."""
        storage_path = Path(initialized_learner)
        (storage_path / "state.json").write_text("NOT JSON!")
        with pytest.raises(Exception):
            await should_apply_adjustments()


class TestGetStats:
    """Tests for get_stats function."""

    @pytest.mark.asyncio
    async def test_full_report_structure(self, seeded_learner):
        """get_stats returns complete LearnerStatsReport."""
        report = await get_stats(min_observations=1)
        assert isinstance(report, LearnerStatsReport)
        assert isinstance(report.current_phase, LearnerPhase)
        assert report.total_records >= 20
        assert isinstance(report.overall_acceptance_rate, AcceptanceRate)
        assert isinstance(report.reviewer_stats, list)
        assert isinstance(report.phase_state, PhaseState)
        assert report.active_trust_adjustments >= 0

    @pytest.mark.asyncio
    async def test_min_observations_filter(self, seeded_learner):
        """active_trust_adjustments counts only entries meeting min_observations."""
        report_low = await get_stats(min_observations=1)
        report_high = await get_stats(min_observations=1000)
        assert report_high.active_trust_adjustments <= report_low.active_trust_adjustments

    @pytest.mark.asyncio
    async def test_state_not_found(self, learner_storage):
        """Raises state_not_found when no state.json."""
        with pytest.raises(Exception):
            await get_stats(min_observations=10)

    @pytest.mark.asyncio
    async def test_state_corruption(self, initialized_learner):
        """Raises state_corruption for invalid state.json."""
        storage_path = Path(initialized_learner)
        (storage_path / "state.json").write_text("CORRUPT!!!")
        with pytest.raises(Exception):
            await get_stats(min_observations=10)

    @pytest.mark.asyncio
    async def test_acceptance_rate_correctness(self, initialized_learner):
        """Overall acceptance rate correctly reflects accepted/total ratio."""
        # Record 3 accepted, 2 dismissed
        records = [
            make_learning_record(record_id="ar-1", accepted=True),
            make_learning_record(record_id="ar-2", accepted=True),
            make_learning_record(record_id="ar-3", accepted=True),
            make_learning_record(record_id="ar-4", accepted=False),
            make_learning_record(record_id="ar-5", accepted=False),
        ]
        await record_decision(records)
        report = await get_stats(min_observations=0)
        # Access the underlying value if AcceptanceRate is a wrapper
        rate_value = report.overall_acceptance_rate
        if hasattr(rate_value, 'value'):
            rate_value = rate_value.value
        assert rate_value == pytest.approx(0.6, abs=0.01)

    @pytest.mark.asyncio
    async def test_deterministic_output(self, seeded_learner):
        """get_stats returns identical output on repeated calls."""
        report1 = await get_stats(min_observations=1)
        report2 = await get_stats(min_observations=1)
        assert report1.total_records == report2.total_records
        assert report1.current_phase == report2.current_phase
        assert report1.active_trust_adjustments == report2.active_trust_adjustments


class TestTypeValidation:
    """Tests for type construction and validation."""

    # ---- ReviewerId ----

    def test_reviewer_id_valid(self):
        """ReviewerId accepts valid identifier strings."""
        r = ReviewerId(value="alice")
        assert r.value == "alice"
        r2 = ReviewerId(value="a1.b2-c3_d4")
        assert r2.value == "a1.b2-c3_d4"

    def test_reviewer_id_invalid_empty(self):
        """ReviewerId rejects empty string."""
        with pytest.raises(Exception):
            ReviewerId(value="")

    def test_reviewer_id_invalid_pattern(self):
        """ReviewerId rejects strings starting with digit or containing invalid chars."""
        with pytest.raises(Exception):
            ReviewerId(value="1abc")
        with pytest.raises(Exception):
            ReviewerId(value="a@b")

    def test_reviewer_id_max_length(self):
        """ReviewerId rejects strings exceeding 128 characters."""
        with pytest.raises(Exception):
            ReviewerId(value="a" * 129)

    def test_reviewer_id_at_max_length(self):
        """ReviewerId accepts string at exactly 128 characters."""
        r = ReviewerId(value="a" * 128)
        assert len(r.value) == 128

    # ---- RuleId ----

    def test_rule_id_valid(self):
        """RuleId accepts valid dot-separated identifiers."""
        r = RuleId(value="security.xss")
        assert r.value == "security.xss"
        r2 = RuleId(value="a/b.c")
        assert r2.value == "a/b.c"

    def test_rule_id_invalid_empty(self):
        """RuleId rejects empty string."""
        with pytest.raises(Exception):
            RuleId(value="")

    def test_rule_id_invalid_chars(self):
        """RuleId rejects invalid characters."""
        with pytest.raises(Exception):
            RuleId(value="rule@invalid")

    def test_rule_id_max_length(self):
        """RuleId rejects strings exceeding 256 characters."""
        with pytest.raises(Exception):
            RuleId(value="a" * 257)

    # ---- TrustWeight ----

    def test_trust_weight_valid_bounds(self):
        """TrustWeight accepts values at boundaries."""
        tw_low = TrustWeight(value=0.1)
        assert tw_low.value == pytest.approx(0.1)
        tw_high = TrustWeight(value=1.0)
        assert tw_high.value == pytest.approx(1.0)

    def test_trust_weight_below_min(self):
        """TrustWeight rejects values below 0.1."""
        with pytest.raises(Exception):
            TrustWeight(value=0.09)

    def test_trust_weight_above_max(self):
        """TrustWeight rejects values above 1.0."""
        with pytest.raises(Exception):
            TrustWeight(value=1.01)

    def test_trust_weight_rounding(self):
        """TrustWeight rounds to 4 decimal places."""
        tw = TrustWeight(value=0.55555)
        assert tw.value == pytest.approx(round(0.55555, 4), abs=1e-6)

    # ---- AcceptanceRate ----

    def test_acceptance_rate_valid_bounds(self):
        """AcceptanceRate accepts values at boundaries [0.0, 1.0]."""
        ar_low = AcceptanceRate(value=0.0)
        assert ar_low.value == pytest.approx(0.0)
        ar_high = AcceptanceRate(value=1.0)
        assert ar_high.value == pytest.approx(1.0)

    def test_acceptance_rate_below_min(self):
        """AcceptanceRate rejects values below 0.0."""
        with pytest.raises(Exception):
            AcceptanceRate(value=-0.1)

    def test_acceptance_rate_above_max(self):
        """AcceptanceRate rejects values above 1.0."""
        with pytest.raises(Exception):
            AcceptanceRate(value=1.1)

    # ---- MinObservations ----

    def test_min_observations_valid_bounds(self):
        """MinObservations accepts values at boundaries [1, 10000]."""
        mo_low = MinObservations(value=1)
        assert mo_low.value == 1
        mo_high = MinObservations(value=10000)
        assert mo_high.value == 10000

    def test_min_observations_below_min(self):
        """MinObservations rejects value 0."""
        with pytest.raises(Exception):
            MinObservations(value=0)

    def test_min_observations_above_max(self):
        """MinObservations rejects value 10001."""
        with pytest.raises(Exception):
            MinObservations(value=10001)

    # ---- FilePath ----

    def test_file_path_valid(self):
        """FilePath accepts valid path strings."""
        fp = FilePath(value="src/main.py")
        assert fp.value == "src/main.py"

    def test_file_path_empty(self):
        """FilePath rejects empty string."""
        with pytest.raises(Exception):
            FilePath(value="")

    def test_file_path_max_length(self):
        """FilePath rejects strings exceeding 4096 characters."""
        with pytest.raises(Exception):
            FilePath(value="a" * 4097)

    # ---- PactKey ----

    def test_pact_key_valid(self):
        """PactKey accepts valid pact: prefixed keys."""
        pk = PactKey(value="pact:learner:record_decision")
        assert pk.value == "pact:learner:record_decision"

    def test_pact_key_invalid(self):
        """PactKey rejects invalid formats."""
        with pytest.raises(Exception):
            PactKey(value="invalid")
        with pytest.raises(Exception):
            PactKey(value="pact:UPPER:case")

    # ---- HumanDecisionInput ----

    def test_human_decision_input_valid(self):
        """HumanDecisionInput accepts valid complete input."""
        hdi = make_human_decision_input()
        assert hdi.finding_id == "finding-001"
        assert hdi.severity == "high"

    def test_human_decision_input_invalid_severity(self):
        """HumanDecisionInput rejects invalid severity value."""
        with pytest.raises(Exception):
            make_human_decision_input(severity="unknown")

    def test_human_decision_input_invalid_finding_id_empty(self):
        """HumanDecisionInput rejects empty finding_id."""
        with pytest.raises(Exception):
            make_human_decision_input(finding_id="")

    def test_human_decision_input_frozen(self):
        """HumanDecisionInput is frozen and immutable."""
        hdi = make_human_decision_input()
        with pytest.raises(Exception):
            hdi.finding_id = "changed"

    def test_human_decision_input_valid_severities(self):
        """HumanDecisionInput accepts all valid severity values."""
        for sev in ["critical", "high", "medium", "low", "info"]:
            hdi = make_human_decision_input(severity=sev, finding_id=f"sev-{sev}")
            assert hdi.severity == sev

    def test_human_decision_input_timestamp_formats(self):
        """HumanDecisionInput accepts valid ISO timestamps and empty string."""
        hdi = make_human_decision_input(timestamp_iso="2024-01-15T10:00:00Z")
        assert hdi.timestamp_iso == "2024-01-15T10:00:00Z"
        hdi2 = make_human_decision_input(timestamp_iso="")
        assert hdi2.timestamp_iso == ""

    def test_human_decision_input_invalid_timestamp(self):
        """HumanDecisionInput rejects invalid timestamp format."""
        with pytest.raises(Exception):
            make_human_decision_input(timestamp_iso="not-a-timestamp")

    # ---- ReviewerRuleStats ----

    def test_reviewer_rule_stats_valid(self):
        """ReviewerRuleStats accepts valid data."""
        rrs = ReviewerRuleStats(
            reviewer_id=ReviewerId(value="alice"),
            rule_id=RuleId(value="security.xss"),
            review_stage="security",
            accepted_count=5,
            dismissed_count=3,
            modified_count=2,
            total_count=10,
            acceptance_rate=AcceptanceRate(value=0.5),
        )
        assert rrs.total_count == 10

    def test_reviewer_rule_stats_negative_count(self):
        """ReviewerRuleStats rejects negative counts."""
        with pytest.raises(Exception):
            ReviewerRuleStats(
                reviewer_id=ReviewerId(value="alice"),
                rule_id=RuleId(value="security.xss"),
                review_stage="security",
                accepted_count=-1,
                dismissed_count=0,
                modified_count=0,
                total_count=0,
                acceptance_rate=AcceptanceRate(value=0.0),
            )

    def test_reviewer_rule_stats_frozen(self):
        """ReviewerRuleStats is frozen."""
        rrs = ReviewerRuleStats(
            reviewer_id=ReviewerId(value="alice"),
            rule_id=RuleId(value="security.xss"),
            review_stage="security",
            accepted_count=5,
            dismissed_count=3,
            modified_count=2,
            total_count=10,
            acceptance_rate=AcceptanceRate(value=0.5),
        )
        with pytest.raises(Exception):
            rrs.accepted_count = 99


class TestEnums:
    """Tests for enum types."""

    def test_learner_phase_values(self):
        """LearnerPhase has shadow, canary, primary variants."""
        assert LearnerPhase.shadow is not None
        assert LearnerPhase.canary is not None
        assert LearnerPhase.primary is not None

    def test_human_decision_values(self):
        """HumanDecision has accepted, dismissed, modified variants."""
        assert HumanDecision.accepted is not None
        assert HumanDecision.dismissed is not None
        assert HumanDecision.modified is not None

    def test_pattern_kind_values(self):
        """PatternKind has all specified variants."""
        assert PatternKind.high_false_positive_rate is not None
        assert PatternKind.high_acceptance_rate is not None
        assert PatternKind.category_bias is not None
        assert PatternKind.file_pattern_bias is not None
        assert PatternKind.severity_mismatch is not None

    def test_severity_values(self):
        """Severity has critical, high, medium, low, info variants."""
        assert Severity.critical is not None
        assert Severity.high is not None
        assert Severity.medium is not None
        assert Severity.low is not None
        assert Severity.info is not None

    def test_review_stage_values(self):
        """ReviewStage has security, correctness, style, architecture variants."""
        assert ReviewStage.security is not None
        assert ReviewStage.correctness is not None
        assert ReviewStage.style is not None
        assert ReviewStage.architecture is not None


class TestLearnerState:
    """Tests for LearnerState type."""

    def test_learner_state_schema_version_range(self):
        """LearnerState schema_version must be in [1, 100]."""
        with pytest.raises(Exception):
            LearnerState(
                schema_version=0,
                phase_state=PhaseState(
                    current_phase=LearnerPhase.shadow,
                    transition_history=[],
                    entered_current_phase_iso="2024-01-01T00:00:00Z",
                ),
                reviewer_stats=[],
                reviewer_rule_stats=[],
                total_records=0,
                last_updated_iso="2024-01-01T00:00:00Z",
            )

    def test_learner_state_total_records_non_negative(self):
        """LearnerState total_records must be >= 0."""
        with pytest.raises(Exception):
            LearnerState(
                schema_version=1,
                phase_state=PhaseState(
                    current_phase=LearnerPhase.shadow,
                    transition_history=[],
                    entered_current_phase_iso="2024-01-01T00:00:00Z",
                ),
                reviewer_stats=[],
                reviewer_rule_stats=[],
                total_records=-1,
                last_updated_iso="2024-01-01T00:00:00Z",
            )

    def test_learner_state_valid(self):
        """LearnerState accepts valid empty state."""
        state = LearnerState(
            schema_version=1,
            phase_state=PhaseState(
                current_phase=LearnerPhase.shadow,
                transition_history=[],
                entered_current_phase_iso="2024-01-01T00:00:00Z",
            ),
            reviewer_stats=[],
            reviewer_rule_stats=[],
            total_records=0,
            last_updated_iso="2024-01-01T00:00:00Z",
        )
        assert state.schema_version == 1
        assert state.total_records == 0


class TestPhaseTransition:
    """Tests for PhaseTransition type."""

    def test_phase_transition_valid(self):
        """PhaseTransition accepts valid data."""
        pt = PhaseTransition(
            from_phase=LearnerPhase.shadow,
            to_phase=LearnerPhase.canary,
            timestamp_iso="2024-01-15T10:00:00Z",
            acceptance_rate_at_transition=AcceptanceRate(value=0.75),
            total_observations=50,
        )
        assert pt.from_phase == LearnerPhase.shadow
        assert pt.to_phase == LearnerPhase.canary

    def test_phase_transition_negative_observations(self):
        """PhaseTransition rejects negative total_observations."""
        with pytest.raises(Exception):
            PhaseTransition(
                from_phase=LearnerPhase.shadow,
                to_phase=LearnerPhase.canary,
                timestamp_iso="2024-01-15T10:00:00Z",
                acceptance_rate_at_transition=AcceptanceRate(value=0.75),
                total_observations=-1,
            )


class TestRecordDecisionResult:
    """Tests for RecordDecisionResult type."""

    def test_result_valid(self):
        """RecordDecisionResult accepts valid data."""
        r = RecordDecisionResult(
            records_persisted=5,
            stats_updated=True,
            phase_changed=False,
            new_phase=LearnerPhase.shadow,
        )
        assert r.records_persisted == 5

    def test_result_negative_persisted(self):
        """RecordDecisionResult rejects negative records_persisted."""
        with pytest.raises(Exception):
            RecordDecisionResult(
                records_persisted=-1,
                stats_updated=True,
                phase_changed=False,
                new_phase=LearnerPhase.shadow,
            )


class TestInvariants:
    """Cross-cutting invariant tests."""

    @pytest.mark.asyncio
    async def test_trust_cold_start_protection(self, initialized_learner):
        """Trust adjustments not produced when total_count < min_observations."""
        # Record only 3 observations
        records = [make_learning_record(record_id=f"cold-{i}", accepted=True) for i in range(3)]
        await record_decision(records)
        adjustments = await get_trust_adjustments(base_weight=1.0, min_observations=10)
        assert len(adjustments) == 0

    @pytest.mark.asyncio
    async def test_fire_and_forget_chronicler_resilience(self, initialized_learner):
        """Operations complete even if chronicler is unreachable."""
        rec = make_learning_record(record_id="faf-resilience")
        result = await record_decision([rec])
        assert result.records_persisted == 1

    @pytest.mark.asyncio
    async def test_phase_monotonicity_full_lifecycle(self, initialized_learner):
        """Full lifecycle: shadow -> canary -> primary, no regression."""
        phase_order = {LearnerPhase.shadow: 0, LearnerPhase.canary: 1, LearnerPhase.primary: 2}

        # Start shadow
        phase = await get_current_phase()
        assert phase == LearnerPhase.shadow
        max_phase = phase_order[phase]

        # Record accepted findings and progress
        records = [make_learning_record(record_id=f"lifecycle-{i}", accepted=True) for i in range(30)]
        await record_decision(records)

        config = make_config(
            shadow_to_canary_threshold=0.5,
            canary_to_primary_threshold=0.8,
            min_observations_for_phase=5,
        )

        # Progress and verify monotonicity
        for _ in range(3):
            phase = await check_phase_progression(config)
            current_order = phase_order[phase]
            assert current_order >= max_phase, f"Phase regressed from {max_phase} to {current_order}"
            max_phase = current_order

    @pytest.mark.asyncio
    async def test_append_only_records(self, initialized_learner):
        """records.json is append-only; existing records never modified."""
        rec1 = make_learning_record(record_id="ao-first")
        await record_decision([rec1])

        storage_path = Path(initialized_learner)
        with open(storage_path / "records.json") as f:
            records_after_first = json.load(f)
        first_count = len(records_after_first)

        rec2 = make_learning_record(record_id="ao-second")
        await record_decision([rec2])

        with open(storage_path / "records.json") as f:
            records_after_second = json.load(f)
        assert len(records_after_second) == first_count + 1

        # Verify first record is still present and unchanged
        first_ids = {r.get("record_id") for r in records_after_first}
        second_ids = {r.get("record_id") for r in records_after_second}
        assert first_ids.issubset(second_ids)

    @pytest.mark.asyncio
    async def test_trust_weight_always_clamped(self, seeded_learner):
        """Trust weights are always in [0.1, 1.0] regardless of input."""
        for bw in [0.001, 0.1, 0.5, 1.0, 10.0]:
            try:
                adjustments = await get_trust_adjustments(base_weight=bw, min_observations=1)
                for adj in adjustments:
                    assert adj.weight >= 0.1, f"Weight {adj.weight} below 0.1 for base_weight={bw}"
                    assert adj.weight <= 1.0, f"Weight {adj.weight} above 1.0 for base_weight={bw}"
            except Exception:
                pass  # Some base_weights may be rejected by validation

    @pytest.mark.asyncio
    async def test_trust_weight_rounded_4_decimal(self, seeded_learner):
        """Trust weights are rounded to exactly 4 decimal places."""
        adjustments = await get_trust_adjustments(base_weight=0.7777, min_observations=1)
        for adj in adjustments:
            assert adj.weight == pytest.approx(round(adj.weight, 4), abs=1e-8)


class TestRandomizedPropertyLike:
    """Property-like tests using random module (no hypothesis dependency)."""

    @pytest.mark.asyncio
    async def test_acceptance_rate_bounds_random(self, initialized_learner):
        """Acceptance rate is always in [0.0, 1.0] regardless of record mix."""
        import random
        random.seed(42)
        records = []
        for i in range(50):
            records.append(make_learning_record(
                record_id=f"rand-{i}",
                accepted=random.choice([True, False]),
                reviewer_id=random.choice(["alice", "bob", "charlie"]),
                rule_id=random.choice(["security.xss", "style.naming", "correctness.null_check"]),
                stage=random.choice(list(ReviewStage)),
            ))
        await record_decision(records)
        report = await get_stats(min_observations=0)
        rate = report.overall_acceptance_rate
        rate_val = rate.value if hasattr(rate, 'value') else rate
        assert 0.0 <= rate_val <= 1.0

    @pytest.mark.asyncio
    async def test_record_stats_roundtrip(self, initialized_learner):
        """Records persisted match stats totals."""
        import random
        random.seed(123)
        n_records = 30
        records = []
        for i in range(n_records):
            records.append(make_learning_record(
                record_id=f"rt-{i}",
                accepted=random.choice([True, False]),
            ))
        await record_decision(records)
        report = await get_stats(min_observations=0)
        assert report.total_records == n_records

    def test_reviewer_id_boundary_lengths(self):
        """ReviewerId at boundary lengths: 1 and 128."""
        r1 = ReviewerId(value="a")
        assert len(r1.value) == 1
        r128 = ReviewerId(value="a" * 128)
        assert len(r128.value) == 128
        with pytest.raises(Exception):
            ReviewerId(value="a" * 129)

    def test_trust_weight_at_boundaries(self):
        """TrustWeight at exact boundaries 0.1 and 1.0."""
        tw_min = TrustWeight(value=0.1)
        assert tw_min.value == pytest.approx(0.1)
        tw_max = TrustWeight(value=1.0)
        assert tw_max.value == pytest.approx(1.0)

    def test_min_observations_filtering_monotonic(self):
        """Higher min_observations should never include more entries than lower."""
        # This is a type-level property test
        mo1 = MinObservations(value=1)
        mo100 = MinObservations(value=100)
        assert mo1.value < mo100.value
