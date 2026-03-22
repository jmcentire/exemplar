"""
Contract tests for exemplar.circuit (BatonCircuitRouter and associated types).

Tests verify behavior at contract boundaries using typed fakes for all
dependencies. No unittest.mock.Mock objects — only structured fakes.
"""
import asyncio
import pytest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Optional, List, Dict, Any

# ---------------------------------------------------------------------------
# Imports from the component under test
# ---------------------------------------------------------------------------
from exemplar.circuit import (
    BatonCircuitRouter,
    ReviewStage,
    StageTimeoutMs,
    ParallelGroup,
    CircuitConfig,
    ExecutionStep,
    ExecutionPlan,
    ChroniclerEventType,
    ChroniclerEvent,
    ChroniclerEmitter,
    ClockProvider,
    CircuitConfigError,
    PACTKey,
)

# Import domain types that are referenced
try:
    from exemplar.circuit import (
        ReviewRequest,
        DiffHunk,
        Severity,
        FindingCategory,
        Finding,
        Assessment,
        Confidence,
        ReviewDecision,
        ClassificationLabel,
        ReviewerProtocol,
    )
except ImportError:
    # Fall back to schemas if not re-exported from circuit
    from exemplar.schemas import (
        ReviewRequest,
        DiffHunk,
        Severity,
        FindingCategory,
        Finding,
        Assessment,
        Confidence,
        ReviewDecision,
        ClassificationLabel,
    )
    from exemplar.circuit import ReviewerProtocol


# ---------------------------------------------------------------------------
# PACT keys — try to import module-level constants
# ---------------------------------------------------------------------------
try:
    from exemplar.circuit import (
        PACT_CIRCUIT_INIT,
        PACT_CIRCUIT_RUN,
        PACT_CIRCUIT_RESOLVE_PLAN,
        PACT_CIRCUIT_INVOKE_REVIEWER,
        PACT_CIRCUIT_GET_TIMEOUT,
        PACT_CIRCUIT_GET_PLAN,
    )
except ImportError:
    PACT_CIRCUIT_INIT = None
    PACT_CIRCUIT_RUN = None
    PACT_CIRCUIT_RESOLVE_PLAN = None
    PACT_CIRCUIT_INVOKE_REVIEWER = None
    PACT_CIRCUIT_GET_TIMEOUT = None
    PACT_CIRCUIT_GET_PLAN = None


# ===========================================================================
# Typed Fakes
# ===========================================================================


class FakeReviewer:
    """Typed fake satisfying ReviewerProtocol.

    Records calls and returns a configurable Assessment. Supports optional
    delay (async sleep) and optional exception raising.
    """

    def __init__(
        self,
        stage: "ReviewStage",
        *,
        delay_ms: int = 0,
        raise_exc: Optional[Exception] = None,
        findings: Optional[list] = None,
    ):
        self.stage = stage
        self.delay_ms = delay_ms
        self.raise_exc = raise_exc
        self.findings = findings or []
        self.calls: list = []

    async def review(self, request: "ReviewRequest") -> "Assessment":
        self.calls.append(request)
        if self.delay_ms > 0:
            await asyncio.sleep(self.delay_ms / 1000.0)
        if self.raise_exc is not None:
            raise self.raise_exc
        return _make_assessment(
            review_request_id=request.id,
            stage=self.stage,
            reviewer_id=f"fake-{self.stage.value}",
            findings=self.findings,
        )


class RecordingChronicler:
    """Typed fake satisfying ChroniclerEmitter protocol.

    Appends all emitted events to self.events for assertion.
    Optionally raises on emit if raise_exc is set.
    """

    def __init__(self, *, raise_exc: Optional[Exception] = None):
        self.events: list = []
        self.raise_exc = raise_exc

    async def emit(self, event: "ChroniclerEvent") -> None:
        if self.raise_exc is not None:
            raise self.raise_exc
        self.events.append(event)


class FakeClock:
    """Typed fake satisfying ClockProvider protocol.

    Returns deterministic values; monotonic_ms increments by step_ms each call.
    """

    def __init__(self, *, start_iso: str = "2024-01-01T00:00:00Z", start_ms: int = 0, step_ms: int = 100):
        self._iso = start_iso
        self._ms = start_ms
        self._step = step_ms

    def now_utc(self) -> str:
        return self._iso

    def monotonic_ms(self) -> int:
        val = self._ms
        self._ms += self._step
        return val


# ===========================================================================
# Factory helpers
# ===========================================================================

def _make_diff_hunk(**overrides) -> "DiffHunk":
    defaults = dict(
        id=str(uuid.uuid4()),
        file_path="src/main.py",
        start_line_old=1,
        count_old=5,
        start_line_new=1,
        count_new=7,
        context_before=["# context"],
        added_lines=["+ new line"],
        removed_lines=["- old line"],
        context_after=["# after"],
        raw_header="@@ -1,5 +1,7 @@",
        classifications=[ClassificationLabel.public],
        language="python",
    )
    defaults.update(overrides)
    return DiffHunk(**defaults)


def _make_review_request(**overrides) -> "ReviewRequest":
    defaults = dict(
        id=str(uuid.uuid4()),
        source="test",
        hunks=[_make_diff_hunk()],
        file_paths=["src/main.py"],
        created_at="2024-01-01T00:00:00Z",
        metadata={},
    )
    defaults.update(overrides)
    return ReviewRequest(**defaults)


def _make_assessment(
    *,
    review_request_id: str = "req-1",
    stage: "ReviewStage" = None,
    reviewer_id: str = "reviewer-1",
    findings: Optional[list] = None,
    is_partial: bool = False,
    error_message: Optional[str] = None,
    duration_ms: int = 50,
) -> "Assessment":
    if stage is None:
        stage = ReviewStage.security
    return Assessment(
        id=str(uuid.uuid4()),
        review_request_id=review_request_id,
        stage=stage,
        reviewer_id=reviewer_id,
        decision=ReviewDecision.pass_ if hasattr(ReviewDecision, "pass_") else getattr(ReviewDecision, "pass"),
        findings=findings or [],
        confidence=Confidence.high,
        is_partial=is_partial,
        error_message=error_message,
        duration_ms=duration_ms,
        created_at="2024-01-01T00:00:00Z",
    )


def _make_circuit_config(
    *,
    stages: Optional[list] = None,
    parallel_stages: Optional[list] = None,
    stage_timeout_ms: int = 5000,
    block_threshold: int = 1,
    warn_threshold: int = 2,
) -> "CircuitConfig":
    if stages is None:
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
    if parallel_stages is None:
        parallel_stages = []
    return CircuitConfig(
        stages=stages,
        parallel_stages=parallel_stages,
        stage_timeout_ms=stage_timeout_ms,
        block_threshold=block_threshold,
        warn_threshold=warn_threshold,
    )


def _make_reviewers(stages: list) -> dict:
    """Build a dict mapping each stage to a FakeReviewer."""
    return {stage: FakeReviewer(stage) for stage in stages}


def _make_router(
    *,
    stages: Optional[list] = None,
    parallel_stages: Optional[list] = None,
    stage_timeout_ms: int = 5000,
    reviewers: Optional[dict] = None,
    chronicler: Optional["RecordingChronicler"] = None,
    clock: Optional["FakeClock"] = None,
    reviewer_overrides: Optional[dict] = None,
) -> "BatonCircuitRouter":
    if stages is None:
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
    config = _make_circuit_config(stages=stages, parallel_stages=parallel_stages or [], stage_timeout_ms=stage_timeout_ms)
    if reviewers is None:
        reviewers = _make_reviewers(stages)
    if reviewer_overrides:
        reviewers.update(reviewer_overrides)
    if chronicler is None:
        chronicler = RecordingChronicler()
    if clock is None:
        clock = FakeClock()
    return BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=chronicler, clock=clock)


# ===========================================================================
# Type / Validator Tests
# ===========================================================================


class TestReviewStageEnum:
    """ReviewStage enum has the four defined variants."""

    def test_review_stage_enum_values(self):
        assert ReviewStage.security is not None
        assert ReviewStage.correctness is not None
        assert ReviewStage.style is not None
        assert ReviewStage.architecture is not None
        # Exactly four members
        members = list(ReviewStage)
        assert len(members) == 4


class TestStageTimeoutMs:
    """StageTimeoutMs validator: 100 <= value <= 300000."""

    def test_valid_value(self):
        t = StageTimeoutMs(value=1000)
        assert t.value == 1000

    def test_boundary_min(self):
        t = StageTimeoutMs(value=100)
        assert t.value == 100

    def test_boundary_max(self):
        t = StageTimeoutMs(value=300000)
        assert t.value == 300000

    def test_below_min_rejected(self):
        with pytest.raises((ValueError, Exception)):
            StageTimeoutMs(value=99)

    def test_above_max_rejected(self):
        with pytest.raises((ValueError, Exception)):
            StageTimeoutMs(value=300001)

    def test_zero_rejected(self):
        with pytest.raises((ValueError, Exception)):
            StageTimeoutMs(value=0)

    def test_negative_rejected(self):
        with pytest.raises((ValueError, Exception)):
            StageTimeoutMs(value=-1)


class TestParallelGroup:
    """ParallelGroup stages validator: len(stages) >= 2."""

    def test_valid_two_stages(self):
        pg = ParallelGroup(stages=[ReviewStage.security, ReviewStage.correctness])
        assert len(pg.stages) == 2

    def test_valid_three_stages(self):
        pg = ParallelGroup(stages=[ReviewStage.security, ReviewStage.correctness, ReviewStage.style])
        assert len(pg.stages) == 3

    def test_single_stage_rejected(self):
        with pytest.raises((ValueError, Exception)):
            ParallelGroup(stages=[ReviewStage.security])

    def test_empty_stages_rejected(self):
        with pytest.raises((ValueError, Exception)):
            ParallelGroup(stages=[])


class TestExecutionStep:
    """ExecutionStep stages validator: len(stages) >= 1."""

    def test_valid_single_stage(self):
        step = ExecutionStep(stages=[ReviewStage.security], is_parallel=False)
        assert len(step.stages) == 1

    def test_valid_multiple_stages(self):
        step = ExecutionStep(stages=[ReviewStage.security, ReviewStage.correctness], is_parallel=True)
        assert len(step.stages) == 2

    def test_empty_stages_rejected(self):
        with pytest.raises((ValueError, Exception)):
            ExecutionStep(stages=[], is_parallel=False)


class TestExecutionPlan:
    """ExecutionPlan steps validator: len(steps) >= 1."""

    def test_valid_plan(self):
        step = ExecutionStep(stages=[ReviewStage.security], is_parallel=False)
        plan = ExecutionPlan(steps=[step], stage_order=[ReviewStage.security])
        assert len(plan.steps) == 1

    def test_empty_steps_rejected(self):
        with pytest.raises((ValueError, Exception)):
            ExecutionPlan(steps=[], stage_order=[])


class TestPACTKey:
    """PACTKey regex validator."""

    def test_valid_key(self):
        key = PACTKey(value="exemplar.circuit.BatonCircuitRouter.run")
        assert key.value == "exemplar.circuit.BatonCircuitRouter.run"

    def test_valid_key_with_underscore(self):
        key = PACTKey(value="exemplar.circuit.BatonCircuitRouter.resolve_execution_plan")
        assert "resolve_execution_plan" in key.value

    def test_invalid_key_rejected(self):
        with pytest.raises((ValueError, Exception)):
            PACTKey(value="invalid.key")

    def test_empty_string_rejected(self):
        with pytest.raises((ValueError, Exception)):
            PACTKey(value="")

    def test_missing_exemplar_prefix_rejected(self):
        with pytest.raises((ValueError, Exception)):
            PACTKey(value="other.circuit.BatonCircuitRouter.run")


# ===========================================================================
# Constructor Tests
# ===========================================================================


class TestCircuitInit:
    """BatonCircuitRouter.__init__ validation."""

    def test_happy_path_all_four_stages(self):
        """Constructor succeeds with valid config and all reviewers present."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        router = _make_router(stages=stages)
        plan = router.get_execution_plan()
        assert plan is not None
        assert plan.stage_order == stages

    def test_happy_path_single_stage(self):
        """Constructor succeeds with a single stage."""
        stages = [ReviewStage.security]
        router = _make_router(stages=stages)
        plan = router.get_execution_plan()
        assert len(plan.stage_order) == 1

    def test_happy_path_with_parallel_group(self):
        """Constructor succeeds with parallel stages."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [[ReviewStage.security, ReviewStage.correctness]]
        router = _make_router(stages=stages, parallel_stages=parallel)
        plan = router.get_execution_plan()
        assert plan is not None

    def test_error_missing_reviewers(self):
        """Raises CircuitConfigError when reviewers dict is missing stages."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        # Only provide reviewer for 'security', missing 'correctness'
        reviewers = {ReviewStage.security: FakeReviewer(ReviewStage.security)}
        config = _make_circuit_config(stages=stages)
        chronicler = RecordingChronicler()
        clock = FakeClock()
        with pytest.raises(CircuitConfigError) as exc_info:
            BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=chronicler, clock=clock)
        err = exc_info.value
        assert ReviewStage.correctness in err.missing_reviewers

    def test_error_invalid_parallel_subset(self):
        """Raises CircuitConfigError when parallel group has stages not in config."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        # architecture is not in stages
        parallel = [[ReviewStage.security, ReviewStage.architecture]]
        reviewers = _make_reviewers(stages)
        config = _make_circuit_config(stages=stages, parallel_stages=parallel)
        chronicler = RecordingChronicler()
        clock = FakeClock()
        with pytest.raises(CircuitConfigError) as exc_info:
            BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=chronicler, clock=clock)
        err = exc_info.value
        assert ReviewStage.architecture in err.invalid_parallel_stages

    def test_error_duplicate_parallel_membership(self):
        """Raises CircuitConfigError when a stage is in multiple parallel groups."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        # security appears in two groups
        parallel = [
            [ReviewStage.security, ReviewStage.correctness],
            [ReviewStage.security, ReviewStage.style],
        ]
        reviewers = _make_reviewers(stages)
        config = _make_circuit_config(stages=stages, parallel_stages=parallel)
        chronicler = RecordingChronicler()
        clock = FakeClock()
        with pytest.raises(CircuitConfigError):
            BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=chronicler, clock=clock)

    def test_error_empty_reviewers(self):
        """Raises CircuitConfigError when reviewers dict is empty."""
        stages = [ReviewStage.security]
        config = _make_circuit_config(stages=stages)
        chronicler = RecordingChronicler()
        clock = FakeClock()
        with pytest.raises(CircuitConfigError):
            BatonCircuitRouter(config=config, reviewers={}, chronicler=chronicler, clock=clock)

    def test_construction_is_synchronous_no_io(self):
        """Construction completes without awaiting — it's synchronous."""
        # If this were async, calling it outside an event loop would fail.
        stages = [ReviewStage.security]
        router = _make_router(stages=stages)
        assert router is not None


# ===========================================================================
# resolve_execution_plan Tests
# ===========================================================================


class TestResolveExecutionPlan:
    """resolve_execution_plan: pure config → plan resolution."""

    def test_sequential_only(self):
        """All stages become individual sequential steps."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        router = _make_router(stages=stages, parallel_stages=[])
        plan = router.get_execution_plan()

        assert plan.stage_order == stages
        for step in plan.steps:
            assert step.is_parallel is False
            assert len(step.stages) == 1

    def test_one_parallel_group(self):
        """Parallel group creates one multi-stage step; others stay sequential."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [[ReviewStage.security, ReviewStage.correctness]]
        router = _make_router(stages=stages, parallel_stages=parallel)
        plan = router.get_execution_plan()

        parallel_steps = [s for s in plan.steps if s.is_parallel]
        sequential_steps = [s for s in plan.steps if not s.is_parallel]
        assert len(parallel_steps) == 1
        assert set(parallel_steps[0].stages) == {ReviewStage.security, ReviewStage.correctness}
        assert len(sequential_steps) == 2  # style, architecture

    def test_all_in_one_parallel_group(self):
        """All four stages in a single parallel group → one parallel step."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [stages]
        router = _make_router(stages=stages, parallel_stages=parallel)
        plan = router.get_execution_plan()

        assert len(plan.steps) == 1
        assert plan.steps[0].is_parallel is True
        assert set(plan.steps[0].stages) == set(stages)

    def test_two_parallel_groups(self):
        """Two separate parallel groups."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [
            [ReviewStage.security, ReviewStage.correctness],
            [ReviewStage.style, ReviewStage.architecture],
        ]
        router = _make_router(stages=stages, parallel_stages=parallel)
        plan = router.get_execution_plan()

        parallel_steps = [s for s in plan.steps if s.is_parallel]
        assert len(parallel_steps) == 2

    def test_stage_order_matches_config_stages(self):
        """stage_order exactly equals config.stages."""
        stages = [ReviewStage.architecture, ReviewStage.style, ReviewStage.correctness, ReviewStage.security]
        router = _make_router(stages=stages)
        plan = router.get_execution_plan()
        assert plan.stage_order == stages

    def test_every_stage_appears_exactly_once(self):
        """Every stage in config.stages appears in exactly one step."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [[ReviewStage.correctness, ReviewStage.style]]
        router = _make_router(stages=stages, parallel_stages=parallel)
        plan = router.get_execution_plan()

        all_plan_stages = []
        for step in plan.steps:
            all_plan_stages.extend(step.stages)
        assert sorted(all_plan_stages, key=lambda s: s.value) == sorted(stages, key=lambda s: s.value)
        assert len(all_plan_stages) == len(set(all_plan_stages))  # no duplicates

    def test_parallel_group_ordering_respects_earliest_stage(self):
        """Step ordering respects position of the earliest stage in each group."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        # correctness, style group — earliest is correctness at index 1
        parallel = [[ReviewStage.correctness, ReviewStage.style]]
        router = _make_router(stages=stages, parallel_stages=parallel)
        plan = router.get_execution_plan()

        # security (seq) should come before the parallel group since security is index 0
        first_step = plan.steps[0]
        assert ReviewStage.security in first_step.stages


# ===========================================================================
# get_stage_timeout Tests
# ===========================================================================


class TestGetStageTimeout:
    """get_stage_timeout: default and per-stage override behavior."""

    def test_returns_default_timeout(self):
        """Returns config.stage_timeout_ms when no per-stage override exists."""
        router = _make_router(stage_timeout_ms=5000)
        timeout = router.get_stage_timeout(ReviewStage.security)
        # Should return a StageTimeoutMs-like value
        if isinstance(timeout, StageTimeoutMs):
            assert timeout.value == 5000
        else:
            assert timeout == 5000 or getattr(timeout, "value", timeout) == 5000

    def test_timeout_satisfies_range(self):
        """Returned timeout is within valid StageTimeoutMs range."""
        router = _make_router(stage_timeout_ms=100)
        timeout = router.get_stage_timeout(ReviewStage.security)
        val = timeout.value if isinstance(timeout, StageTimeoutMs) else timeout
        assert 100 <= val <= 300000


# ===========================================================================
# get_execution_plan Tests
# ===========================================================================


class TestGetExecutionPlan:
    """get_execution_plan: read-only accessor."""

    def test_returns_resolved_plan(self):
        """Returns the plan resolved at construction time."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        router = _make_router(stages=stages)
        plan = router.get_execution_plan()
        assert isinstance(plan, ExecutionPlan)
        assert plan.stage_order == stages

    def test_returns_same_instance_on_repeated_calls(self):
        """Plan is immutable; repeated calls return consistent data."""
        router = _make_router()
        plan1 = router.get_execution_plan()
        plan2 = router.get_execution_plan()
        assert plan1.stage_order == plan2.stage_order
        assert len(plan1.steps) == len(plan2.steps)


# ===========================================================================
# invoke_reviewer Tests
# ===========================================================================


class TestInvokeReviewer:
    """invoke_reviewer: single reviewer invocation with circuit-breaker."""

    @pytest.mark.asyncio
    async def test_success_returns_full_assessment(self):
        """Successful reviewer returns Assessment with is_partial=False."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        router = _make_router(stages=stages, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        assessment = await router.invoke_reviewer(ReviewStage.security, request, timeout)

        assert assessment is not None
        assert assessment.stage == ReviewStage.security
        assert assessment.is_partial is False

    @pytest.mark.asyncio
    async def test_timeout_returns_degraded_assessment(self):
        """Reviewer exceeding timeout returns Assessment with is_partial=True."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        slow_reviewer = FakeReviewer(ReviewStage.security, delay_ms=10000)  # 10s delay
        reviewers = {ReviewStage.security: slow_reviewer}
        router = _make_router(stages=stages, reviewers=reviewers, chronicler=chronicler, stage_timeout_ms=200)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=200)  # 200ms timeout
        assessment = await router.invoke_reviewer(ReviewStage.security, request, timeout)

        assert assessment.is_partial is True
        assert assessment.error_message is not None
        assert assessment.stage == ReviewStage.security

    @pytest.mark.asyncio
    async def test_exception_returns_degraded_assessment(self):
        """Reviewer raising an exception returns Assessment with is_partial=True."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        bad_reviewer = FakeReviewer(ReviewStage.security, raise_exc=RuntimeError("boom"))
        reviewers = {ReviewStage.security: bad_reviewer}
        router = _make_router(stages=stages, reviewers=reviewers, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        assessment = await router.invoke_reviewer(ReviewStage.security, request, timeout)

        assert assessment.is_partial is True
        assert assessment.error_message is not None
        assert "boom" in assessment.error_message.lower() or len(assessment.error_message) > 0

    @pytest.mark.asyncio
    async def test_emits_chronicler_events(self):
        """Emits stage.started and stage.complete events."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        router = _make_router(stages=stages, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        await router.invoke_reviewer(ReviewStage.security, request, timeout)

        # Allow a small delay for fire-and-forget
        await asyncio.sleep(0.05)

        event_types = [e.event_type for e in chronicler.events]
        assert ChroniclerEventType("stage.started") in event_types or any(
            "started" in str(et) for et in event_types
        )
        assert ChroniclerEventType("stage.complete") in event_types or any(
            "complete" in str(et) for et in event_types
        )

    @pytest.mark.asyncio
    async def test_no_exception_propagated_on_reviewer_error(self):
        """No exception is ever propagated from invoke_reviewer."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        bad_reviewer = FakeReviewer(ReviewStage.security, raise_exc=ValueError("crash"))
        reviewers = {ReviewStage.security: bad_reviewer}
        router = _make_router(stages=stages, reviewers=reviewers, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        # Should NOT raise
        assessment = await router.invoke_reviewer(ReviewStage.security, request, timeout)
        assert assessment is not None
        assert assessment.is_partial is True

    @pytest.mark.asyncio
    async def test_chronicler_failure_absorbed(self):
        """Chronicler emit failure does not prevent assessment return."""
        failing_chronicler = RecordingChronicler(raise_exc=RuntimeError("chronicler down"))
        stages = [ReviewStage.security]
        router = _make_router(stages=stages, chronicler=failing_chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        # Should NOT raise despite chronicler failure
        assessment = await router.invoke_reviewer(ReviewStage.security, request, timeout)
        assert assessment is not None
        assert assessment.stage == ReviewStage.security

    @pytest.mark.asyncio
    async def test_assessment_stage_matches_input_stage(self):
        """Assessment.stage always matches the stage argument."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.correctness]
        router = _make_router(stages=stages, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        assessment = await router.invoke_reviewer(ReviewStage.correctness, request, timeout)
        assert assessment.stage == ReviewStage.correctness

    @pytest.mark.asyncio
    async def test_assessment_has_duration_ms(self):
        """Assessment.duration_ms reflects invocation time."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        router = _make_router(stages=stages, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        assessment = await router.invoke_reviewer(ReviewStage.security, request, timeout)
        assert hasattr(assessment, "duration_ms")
        assert isinstance(assessment.duration_ms, int)
        assert assessment.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_chronicler_events_on_failure(self):
        """Chronicler events are emitted even when reviewer fails."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        bad_reviewer = FakeReviewer(ReviewStage.security, raise_exc=RuntimeError("fail"))
        reviewers = {ReviewStage.security: bad_reviewer}
        router = _make_router(stages=stages, reviewers=reviewers, chronicler=chronicler)
        request = _make_review_request()

        timeout = StageTimeoutMs(value=5000)
        await router.invoke_reviewer(ReviewStage.security, request, timeout)
        await asyncio.sleep(0.05)

        # Should still have events
        assert len(chronicler.events) >= 2  # started + complete


# ===========================================================================
# run() Tests
# ===========================================================================


class TestRun:
    """BatonCircuitRouter.run: full pipeline execution."""

    @pytest.mark.asyncio
    async def test_happy_path_sequential(self):
        """All sequential stages, all succeed."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        chronicler = RecordingChronicler()
        router = _make_router(stages=stages, parallel_stages=[], chronicler=chronicler)
        request = _make_review_request()

        assessments = await router.run(request)

        assert len(assessments) == 4
        for i, stage in enumerate(stages):
            assert assessments[i].stage == stage
            assert assessments[i].is_partial is False

    @pytest.mark.asyncio
    async def test_happy_path_parallel(self):
        """Parallel stages execute and return assessments in config order."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [stages]  # All parallel
        chronicler = RecordingChronicler()
        router = _make_router(stages=stages, parallel_stages=parallel, chronicler=chronicler)
        request = _make_review_request()

        assessments = await router.run(request)

        assert len(assessments) == 4
        for i, stage in enumerate(stages):
            assert assessments[i].stage == stage

    @pytest.mark.asyncio
    async def test_mixed_sequential_parallel(self):
        """Mixed sequential and parallel stages, all in correct order."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        parallel = [[ReviewStage.correctness, ReviewStage.style]]
        chronicler = RecordingChronicler()
        router = _make_router(stages=stages, parallel_stages=parallel, chronicler=chronicler)
        request = _make_review_request()

        assessments = await router.run(request)

        assert len(assessments) == 4
        for i, stage in enumerate(stages):
            assert assessments[i].stage == stage

    @pytest.mark.asyncio
    async def test_returns_exact_stage_count(self):
        """Exactly len(config.stages) assessments returned."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        router = _make_router(stages=stages)
        request = _make_review_request()

        assessments = await router.run(request)
        assert len(assessments) == len(stages)

    @pytest.mark.asyncio
    async def test_assessments_ordered_by_config_stages(self):
        """Assessments are in config.stages order."""
        stages = [ReviewStage.architecture, ReviewStage.style, ReviewStage.correctness, ReviewStage.security]
        router = _make_router(stages=stages)
        request = _make_review_request()

        assessments = await router.run(request)

        for i, stage in enumerate(stages):
            assert assessments[i].stage == stage

    @pytest.mark.asyncio
    async def test_partial_failure_does_not_block_others(self):
        """One failing reviewer produces partial; others still complete."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        good_reviewer = FakeReviewer(ReviewStage.security)
        bad_reviewer = FakeReviewer(ReviewStage.correctness, raise_exc=RuntimeError("fail"))
        reviewers = {
            ReviewStage.security: good_reviewer,
            ReviewStage.correctness: bad_reviewer,
        }
        router = _make_router(stages=stages, reviewers=reviewers)
        request = _make_review_request()

        assessments = await router.run(request)

        assert len(assessments) == 2
        assert assessments[0].is_partial is False  # security succeeded
        assert assessments[1].is_partial is True  # correctness failed

    @pytest.mark.asyncio
    async def test_all_reviewers_fail(self):
        """All reviewers fail; all assessments are partial, no exception propagated."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        reviewers = {
            ReviewStage.security: FakeReviewer(ReviewStage.security, raise_exc=RuntimeError("err1")),
            ReviewStage.correctness: FakeReviewer(ReviewStage.correctness, raise_exc=RuntimeError("err2")),
        }
        router = _make_router(stages=stages, reviewers=reviewers)
        request = _make_review_request()

        assessments = await router.run(request)

        assert len(assessments) == 2
        assert all(a.is_partial is True for a in assessments)

    @pytest.mark.asyncio
    async def test_chronicler_failure_does_not_block_run(self):
        """Chronicler failure doesn't prevent assessments from being returned."""
        failing_chronicler = RecordingChronicler(raise_exc=RuntimeError("chronicle down"))
        stages = [ReviewStage.security, ReviewStage.correctness]
        router = _make_router(stages=stages, chronicler=failing_chronicler)
        request = _make_review_request()

        # Should NOT raise
        assessments = await router.run(request)
        assert len(assessments) == 2

    @pytest.mark.asyncio
    async def test_every_assessment_has_valid_stage(self):
        """Every Assessment has a ReviewStage matching a configured stage."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style]
        router = _make_router(stages=stages)
        request = _make_review_request()

        assessments = await router.run(request)

        stage_set = set(stages)
        for a in assessments:
            assert a.stage in stage_set

    @pytest.mark.asyncio
    async def test_single_stage_run(self):
        """Run with only one configured stage."""
        stages = [ReviewStage.security]
        router = _make_router(stages=stages)
        request = _make_review_request()

        assessments = await router.run(request)
        assert len(assessments) == 1
        assert assessments[0].stage == ReviewStage.security


# ===========================================================================
# Chronicler Integration Tests
# ===========================================================================


class TestChroniclerIntegration:
    """Chronicler events at review lifecycle boundaries."""

    @pytest.mark.asyncio
    async def test_events_for_each_stage_on_success(self):
        """stage.started and stage.complete emitted for each stage."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security, ReviewStage.correctness]
        router = _make_router(stages=stages, chronicler=chronicler)
        request = _make_review_request()

        await router.run(request)
        await asyncio.sleep(0.1)  # Allow fire-and-forget events

        # Expect at least 2 events per stage (started + complete)
        started_events = [e for e in chronicler.events if "started" in str(e.event_type)]
        complete_events = [e for e in chronicler.events if "complete" in str(e.event_type)]
        assert len(started_events) >= len(stages)
        assert len(complete_events) >= len(stages)

    @pytest.mark.asyncio
    async def test_events_emitted_on_reviewer_failure(self):
        """Chronicler events emitted even when reviewer fails."""
        chronicler = RecordingChronicler()
        stages = [ReviewStage.security]
        bad_reviewer = FakeReviewer(ReviewStage.security, raise_exc=RuntimeError("fail"))
        reviewers = {ReviewStage.security: bad_reviewer}
        router = _make_router(stages=stages, reviewers=reviewers, chronicler=chronicler)
        request = _make_review_request()

        await router.run(request)
        await asyncio.sleep(0.1)

        # Should still have events for the stage
        assert len(chronicler.events) >= 2

    @pytest.mark.asyncio
    async def test_fire_and_forget_chronicler_exception(self):
        """Chronicler exception doesn't prevent run from completing."""
        failing_chronicler = RecordingChronicler(raise_exc=RuntimeError("emit failed"))
        stages = [ReviewStage.security, ReviewStage.correctness]
        router = _make_router(stages=stages, chronicler=failing_chronicler)
        request = _make_review_request()

        # run() should complete normally
        assessments = await router.run(request)
        assert len(assessments) == 2
        for a in assessments:
            assert a.stage in {ReviewStage.security, ReviewStage.correctness}


# ===========================================================================
# PACT Key Tests
# ===========================================================================


class TestPACTKeys:
    """PACT key module-level constants follow the correct pattern."""

    def test_pact_circuit_run_defined(self):
        """PACT_CIRCUIT_RUN constant exists and matches expected pattern."""
        if PACT_CIRCUIT_RUN is not None:
            assert "exemplar" in PACT_CIRCUIT_RUN
            assert "circuit" in PACT_CIRCUIT_RUN.lower() or "Circuit" in PACT_CIRCUIT_RUN
        else:
            pytest.skip("PACT_CIRCUIT_RUN not importable")

    def test_pact_circuit_invoke_reviewer_defined(self):
        """PACT_CIRCUIT_INVOKE_REVIEWER constant exists."""
        if PACT_CIRCUIT_INVOKE_REVIEWER is not None:
            assert "exemplar" in PACT_CIRCUIT_INVOKE_REVIEWER
        else:
            pytest.skip("PACT_CIRCUIT_INVOKE_REVIEWER not importable")

    def test_pact_circuit_resolve_plan_defined(self):
        """PACT_CIRCUIT_RESOLVE_PLAN constant exists."""
        if PACT_CIRCUIT_RESOLVE_PLAN is not None:
            assert "exemplar" in PACT_CIRCUIT_RESOLVE_PLAN
        else:
            pytest.skip("PACT_CIRCUIT_RESOLVE_PLAN not importable")

    def test_pact_circuit_get_timeout_defined(self):
        """PACT_CIRCUIT_GET_TIMEOUT constant exists."""
        if PACT_CIRCUIT_GET_TIMEOUT is not None:
            assert "exemplar" in PACT_CIRCUIT_GET_TIMEOUT
        else:
            pytest.skip("PACT_CIRCUIT_GET_TIMEOUT not importable")

    def test_pact_circuit_get_plan_defined(self):
        """PACT_CIRCUIT_GET_PLAN constant exists."""
        if PACT_CIRCUIT_GET_PLAN is not None:
            assert "exemplar" in PACT_CIRCUIT_GET_PLAN
        else:
            pytest.skip("PACT_CIRCUIT_GET_PLAN not importable")

    def test_pact_keys_are_valid_pact_key_strings(self):
        """All PACT keys that exist should be valid PACTKey values."""
        pact_keys = [
            PACT_CIRCUIT_INIT,
            PACT_CIRCUIT_RUN,
            PACT_CIRCUIT_RESOLVE_PLAN,
            PACT_CIRCUIT_INVOKE_REVIEWER,
            PACT_CIRCUIT_GET_TIMEOUT,
            PACT_CIRCUIT_GET_PLAN,
        ]
        for key in pact_keys:
            if key is not None:
                # Should not raise
                PACTKey(value=key)


# ===========================================================================
# Invariant Tests
# ===========================================================================


class TestInvariants:
    """Cross-cutting invariants from the contract."""

    @pytest.mark.asyncio
    async def test_no_exception_propagation_from_reviewers(self):
        """BatonCircuitRouter never propagates exceptions from reviewer invocations."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style]
        reviewers = {
            ReviewStage.security: FakeReviewer(ReviewStage.security, raise_exc=TypeError("type error")),
            ReviewStage.correctness: FakeReviewer(ReviewStage.correctness, raise_exc=ValueError("value error")),
            ReviewStage.style: FakeReviewer(ReviewStage.style, raise_exc=OSError("os error")),
        }
        router = _make_router(stages=stages, reviewers=reviewers)
        request = _make_review_request()

        # Should NOT raise any exception
        assessments = await router.run(request)
        assert len(assessments) == 3
        assert all(a.is_partial is True for a in assessments)

    @pytest.mark.asyncio
    async def test_no_exception_propagation_from_chronicler(self):
        """BatonCircuitRouter never propagates exceptions from ChroniclerEmitter.emit."""
        failing_chronicler = RecordingChronicler(raise_exc=ConnectionError("network error"))
        stages = [ReviewStage.security]
        router = _make_router(stages=stages, chronicler=failing_chronicler)
        request = _make_review_request()

        # Should NOT raise
        assessments = await router.run(request)
        assert len(assessments) == 1

    @pytest.mark.asyncio
    async def test_assessment_count_equals_stage_count(self):
        """Returned list always has exactly len(config.stages) elements."""
        for n_stages in [1, 2, 3, 4]:
            all_stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
            stages = all_stages[:n_stages]
            router = _make_router(stages=stages)
            request = _make_review_request()
            assessments = await router.run(request)
            assert len(assessments) == n_stages, f"Expected {n_stages} assessments, got {len(assessments)}"

    def test_execution_plan_immutable_after_construction(self):
        """ExecutionPlan is frozen/immutable after construction."""
        router = _make_router()
        plan = router.get_execution_plan()
        # Attempting to mutate should raise
        with pytest.raises((AttributeError, TypeError, Exception)):
            plan.stage_order = [ReviewStage.security]

    def test_every_stage_has_registered_reviewer(self):
        """Every stage in config.stages must have a registered reviewer (enforced at construction)."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        # Missing correctness reviewer
        reviewers = {ReviewStage.security: FakeReviewer(ReviewStage.security)}
        config = _make_circuit_config(stages=stages)
        with pytest.raises(CircuitConfigError) as exc_info:
            BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=RecordingChronicler(), clock=FakeClock())
        assert ReviewStage.correctness in exc_info.value.missing_reviewers

    def test_every_parallel_stage_must_be_in_config_stages(self):
        """Every stage in ParallelGroup must be in config.stages."""
        stages = [ReviewStage.security]
        parallel = [[ReviewStage.security, ReviewStage.correctness]]  # correctness not in stages
        reviewers = _make_reviewers(stages)
        config = _make_circuit_config(stages=stages, parallel_stages=parallel)
        with pytest.raises(CircuitConfigError) as exc_info:
            BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=RecordingChronicler(), clock=FakeClock())
        assert ReviewStage.correctness in exc_info.value.invalid_parallel_stages

    def test_no_duplicate_parallel_membership(self):
        """No stage appears in more than one ParallelGroup."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style]
        parallel = [
            [ReviewStage.security, ReviewStage.correctness],
            [ReviewStage.correctness, ReviewStage.style],  # correctness is duplicate
        ]
        reviewers = _make_reviewers(stages)
        config = _make_circuit_config(stages=stages, parallel_stages=parallel)
        with pytest.raises(CircuitConfigError):
            BatonCircuitRouter(config=config, reviewers=reviewers, chronicler=RecordingChronicler(), clock=FakeClock())

    @pytest.mark.asyncio
    async def test_timeout_enforces_cancellation(self):
        """No reviewer invocation exceeds its configured timeout."""
        stages = [ReviewStage.security]
        slow_reviewer = FakeReviewer(ReviewStage.security, delay_ms=5000)
        reviewers = {ReviewStage.security: slow_reviewer}
        router = _make_router(stages=stages, reviewers=reviewers, stage_timeout_ms=200)
        request = _make_review_request()

        import time
        start = time.monotonic()
        assessments = await router.run(request)
        elapsed_ms = (time.monotonic() - start) * 1000

        # Should complete well under 5000ms (the reviewer's delay)
        assert elapsed_ms < 3000, f"Run took {elapsed_ms}ms, expected < 3000ms"
        assert assessments[0].is_partial is True
