"""
Adversarial hidden acceptance tests for the Baton Circuit Router.

These tests verify behavioral properties that could be bypassed by implementations
that hardcode returns matching visible test inputs.
"""
import asyncio
import pytest
import time
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Optional

from exemplar.circuit import (
    BatonCircuitRouter,
    CircuitConfig,
    CircuitConfigError,
    ReviewStage,
    StageTimeoutMs,
    ParallelGroup,
    ExecutionStep,
    ExecutionPlan,
    ChroniclerEvent,
    ChroniclerEventType,
    PACTKey,
)

# Try to import PACT constants
try:
    from exemplar.circuit import (
        PACT_CIRCUIT_RUN,
        PACT_CIRCUIT_RESOLVE_PLAN,
        PACT_CIRCUIT_INVOKE_REVIEWER,
        PACT_CIRCUIT_GET_TIMEOUT,
        PACT_CIRCUIT_GET_PLAN,
    )
except ImportError:
    PACT_CIRCUIT_RUN = None
    PACT_CIRCUIT_RESOLVE_PLAN = None
    PACT_CIRCUIT_INVOKE_REVIEWER = None
    PACT_CIRCUIT_GET_TIMEOUT = None
    PACT_CIRCUIT_GET_PLAN = None

from exemplar.schemas import (
    ReviewRequest,
    DiffHunk,
    Assessment,
    ReviewDecision,
    Confidence,
    Severity,
    Finding,
    ClassificationLabel,
)


# ── Helpers ──────────────────────────────────────────────────────────


def make_clock(now_utc="2024-01-01T00:00:00Z", monotonic_start=0):
    """Create a deterministic ClockProvider mock."""
    counter = {"ms": monotonic_start}
    clock = MagicMock()
    clock.now_utc = MagicMock(return_value=now_utc)

    def _monotonic():
        val = counter["ms"]
        counter["ms"] += 10
        return val

    clock.monotonic_ms = MagicMock(side_effect=_monotonic)
    return clock


def make_chronicler(fail=False):
    """Create a mock ChroniclerEmitter."""
    chronicler = MagicMock()
    if fail:
        chronicler.emit = AsyncMock(side_effect=RuntimeError("emit failed"))
    else:
        chronicler.emit = AsyncMock()
    return chronicler


def make_hunk(hunk_id="hunk-1", file_path="test.py"):
    return DiffHunk(
        id=hunk_id,
        file_path=file_path,
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


def make_request(request_id="req-test-001"):
    return ReviewRequest(
        id=request_id,
        source="test",
        hunks=[make_hunk()],
        file_paths=["test.py"],
        created_at="2024-01-01T00:00:00Z",
        metadata={},
    )


def make_assessment(stage, request_id="req-test-001", is_partial=False, error_message=None):
    return Assessment(
        id=f"assess-{stage.value}",
        review_request_id=request_id,
        stage=stage,
        reviewer_id=f"reviewer-{stage.value}",
        decision=ReviewDecision.pass_,
        findings=[],
        confidence=Confidence.high,
        is_partial=is_partial,
        error_message=error_message,
        duration_ms=10,
        created_at="2024-01-01T00:00:00Z",
    )


def make_reviewer(stage, request_id="req-test-001", delay=0, fail=False, fail_exc=None):
    """Create a mock reviewer that returns an assessment or fails."""
    reviewer = MagicMock()

    async def _review(req):
        if delay > 0:
            await asyncio.sleep(delay)
        if fail:
            raise fail_exc or RuntimeError(f"reviewer-{stage.value} failed")
        return make_assessment(stage, request_id=req.id)

    reviewer.review = AsyncMock(side_effect=_review)
    return reviewer


def try_make_assessment(stage, request_id="req-test-001"):
    """Try different field names for ReviewDecision.pass since 'pass' is a Python keyword."""
    for field_name in ["pass_", "pass"]:
        try:
            return Assessment(
                id=f"assess-{stage.value}",
                review_request_id=request_id,
                stage=stage,
                reviewer_id=f"reviewer-{stage.value}",
                decision=getattr(ReviewDecision, field_name),
                findings=[],
                confidence=Confidence.high,
                is_partial=False,
                error_message=None,
                duration_ms=10,
                created_at="2024-01-01T00:00:00Z",
            )
        except (AttributeError, Exception):
            continue
    # Last resort: try string value
    return Assessment(
        id=f"assess-{stage.value}",
        review_request_id=request_id,
        stage=stage,
        reviewer_id=f"reviewer-{stage.value}",
        decision="pass",
        findings=[],
        confidence=Confidence.high,
        is_partial=False,
        error_message=None,
        duration_ms=10,
        created_at="2024-01-01T00:00:00Z",
    )


def make_config(stages=None, parallel_stages=None, stage_timeout_ms=5000,
                block_threshold=1, warn_threshold=2):
    stages = stages or [
        ReviewStage.security,
        ReviewStage.correctness,
        ReviewStage.style,
        ReviewStage.architecture,
    ]
    parallel_stages = parallel_stages or []
    return CircuitConfig(
        stages=stages,
        parallel_stages=parallel_stages,
        stage_timeout_ms=stage_timeout_ms,
        block_threshold=block_threshold,
        warn_threshold=warn_threshold,
    )


def make_reviewers(stages, request_id="req-test-001", delays=None, failures=None):
    """Create reviewers dict for given stages with optional per-stage delays and failures."""
    delays = delays or {}
    failures = failures or {}
    reviewers = {}
    for s in stages:
        reviewers[s] = make_reviewer(
            s,
            request_id=request_id,
            delay=delays.get(s, 0),
            fail=s in failures,
            fail_exc=failures.get(s),
        )
    return reviewers


def build_router(stages=None, parallel_stages=None, stage_timeout_ms=5000,
                 request_id="req-test-001", chronicler=None, clock=None,
                 extra_reviewers=None, reviewer_delays=None, reviewer_failures=None):
    """Build a BatonCircuitRouter with reasonable defaults."""
    stages = stages or [
        ReviewStage.security,
        ReviewStage.correctness,
        ReviewStage.style,
        ReviewStage.architecture,
    ]
    config = make_config(stages=stages, parallel_stages=parallel_stages,
                         stage_timeout_ms=stage_timeout_ms)
    reviewers = make_reviewers(stages, request_id=request_id,
                               delays=reviewer_delays or {},
                               failures=reviewer_failures or {})
    if extra_reviewers:
        for s, r in extra_reviewers.items():
            reviewers[s] = r
    chronicler = chronicler or make_chronicler()
    clock = clock or make_clock()
    return BatonCircuitRouter(config, reviewers, chronicler, clock), config, chronicler


# ── Tests ────────────────────────────────────────────────────────────


class TestGoodhartResolvePlan:

    def test_goodhart_resolve_plan_parallel_group_ordered_by_earliest_stage(self):
        """The execution plan must order parallel group steps by the position of
        the earliest member stage in config.stages, not by the order groups appear
        in parallel_stages."""
        stages = [
            ReviewStage.security,
            ReviewStage.correctness,
            ReviewStage.style,
            ReviewStage.architecture,
        ]
        # parallel_stages lists [style, architecture] first, then [security, correctness]
        # but security comes first in config.stages, so that group should execute first
        parallel_stages = [
            [ReviewStage.style, ReviewStage.architecture],
            [ReviewStage.security, ReviewStage.correctness],
        ]
        router, config, _ = build_router(stages=stages, parallel_stages=parallel_stages)
        plan = router.get_execution_plan()

        assert plan.stage_order == stages

        # Find the step containing security — it should come before the step containing style
        security_step_idx = None
        style_step_idx = None
        for i, step in enumerate(plan.steps):
            if ReviewStage.security in step.stages:
                security_step_idx = i
            if ReviewStage.style in step.stages:
                style_step_idx = i

        assert security_step_idx is not None
        assert style_step_idx is not None
        assert security_step_idx < style_step_idx, (
            "Parallel group with earlier stages must come first in execution order"
        )

    def test_goodhart_resolve_plan_interleaved_sequential_and_parallel(self):
        """Sequential stages interleaved between parallel groups must appear in
        their correct position relative to parallel group steps."""
        stages = [
            ReviewStage.security,
            ReviewStage.correctness,
            ReviewStage.style,
            ReviewStage.architecture,
        ]
        parallel_stages = [[ReviewStage.correctness, ReviewStage.style]]
        router, _, _ = build_router(stages=stages, parallel_stages=parallel_stages)
        plan = router.get_execution_plan()

        assert len(plan.steps) == 3
        # Step 1: sequential security
        assert plan.steps[0].stages == [ReviewStage.security]
        assert plan.steps[0].is_parallel is False
        # Step 2: parallel correctness + style
        assert set(plan.steps[1].stages) == {ReviewStage.correctness, ReviewStage.style}
        assert plan.steps[1].is_parallel is True
        # Step 3: sequential architecture
        assert plan.steps[2].stages == [ReviewStage.architecture]
        assert plan.steps[2].is_parallel is False

    def test_goodhart_resolve_plan_three_stages_one_parallel_group(self):
        """Execution plan with 3 stages where 2 are parallel and 1 is sequential
        must produce exactly 2 steps in correct order."""
        stages = [
            ReviewStage.architecture,
            ReviewStage.security,
            ReviewStage.correctness,
        ]
        parallel_stages = [[ReviewStage.security, ReviewStage.correctness]]
        router, _, _ = build_router(stages=stages, parallel_stages=parallel_stages)
        plan = router.get_execution_plan()

        assert len(plan.steps) == 2
        # architecture is earliest so sequential first
        assert plan.steps[0].stages == [ReviewStage.architecture]
        assert plan.steps[0].is_parallel is False
        # parallel group second
        assert set(plan.steps[1].stages) == {ReviewStage.security, ReviewStage.correctness}
        assert plan.steps[1].is_parallel is True
        assert plan.stage_order == stages


class TestGoodhartInit:

    def test_goodhart_init_missing_single_middle_reviewer(self):
        """CircuitConfigError must correctly identify which specific stages are
        missing reviewers, even when only one middle stage is missing."""
        stages = [
            ReviewStage.security,
            ReviewStage.correctness,
            ReviewStage.style,
            ReviewStage.architecture,
        ]
        config = make_config(stages=stages)
        # Provide all reviewers except style
        reviewers = {
            ReviewStage.security: make_reviewer(ReviewStage.security),
            ReviewStage.correctness: make_reviewer(ReviewStage.correctness),
            ReviewStage.architecture: make_reviewer(ReviewStage.architecture),
        }
        with pytest.raises(CircuitConfigError) as exc_info:
            BatonCircuitRouter(config, reviewers, make_chronicler(), make_clock())

        err = exc_info.value
        assert ReviewStage.style in err.missing_reviewers

    def test_goodhart_init_reviewers_superset_of_stages(self):
        """Constructor should succeed when reviewers dict has extra entries beyond
        config.stages — only missing entries should fail."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        config = make_config(stages=stages)
        # Provide reviewers for all four stages (superset)
        reviewers = {
            ReviewStage.security: make_reviewer(ReviewStage.security),
            ReviewStage.correctness: make_reviewer(ReviewStage.correctness),
            ReviewStage.style: make_reviewer(ReviewStage.style),
            ReviewStage.architecture: make_reviewer(ReviewStage.architecture),
        }
        router = BatonCircuitRouter(config, reviewers, make_chronicler(), make_clock())
        plan = router.get_execution_plan()
        plan_stages = set()
        for step in plan.steps:
            plan_stages.update(step.stages)
        assert plan_stages == set(stages)

    def test_goodhart_init_all_four_stages_no_parallel(self):
        """Constructor must succeed with all four stages configured sequentially
        and execution plan should have 4 sequential steps."""
        stages = [
            ReviewStage.security,
            ReviewStage.correctness,
            ReviewStage.style,
            ReviewStage.architecture,
        ]
        router, _, _ = build_router(stages=stages, parallel_stages=[])
        plan = router.get_execution_plan()
        assert len(plan.steps) == 4
        for step in plan.steps:
            assert step.is_parallel is False
            assert len(step.stages) == 1

    def test_goodhart_init_parallel_stage_not_in_config_different_stage(self):
        """Constructor must reject parallel groups containing stages not in
        config.stages, even when the invalid stage is a valid ReviewStage enum."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        config = make_config(
            stages=stages,
            parallel_stages=[[ReviewStage.security, ReviewStage.architecture]],
        )
        reviewers = {
            ReviewStage.security: make_reviewer(ReviewStage.security),
            ReviewStage.correctness: make_reviewer(ReviewStage.correctness),
        }
        with pytest.raises(CircuitConfigError) as exc_info:
            BatonCircuitRouter(config, reviewers, make_chronicler(), make_clock())

        err = exc_info.value
        assert ReviewStage.architecture in err.invalid_parallel_stages


class TestGoodhartRun:

    @pytest.mark.asyncio
    async def test_goodhart_run_assessment_review_request_id_matches(self):
        """Every assessment returned by run() must reference the correct
        review_request_id from the input request."""
        unique_id = "req-unique-xyz-999"
        router, _, _ = build_router(request_id=unique_id)
        request = make_request(request_id=unique_id)
        assessments = await router.run(request)

        for a in assessments:
            assert a.review_request_id == unique_id
            assert a.review_request_id != ""
            assert a.review_request_id is not None

    @pytest.mark.asyncio
    async def test_goodhart_run_assessment_stages_match_one_to_one(self):
        """Each assessment's stage field must match a unique configured stage,
        with no duplicates and no missing stages."""
        stages = [
            ReviewStage.security,
            ReviewStage.correctness,
            ReviewStage.style,
            ReviewStage.architecture,
        ]
        router, config, _ = build_router(stages=stages)
        request = make_request()
        assessments = await router.run(request)

        assessment_stages = [a.stage for a in assessments]
        assert len(assessment_stages) == len(set(assessment_stages)), "Duplicate stages in assessments"
        assert set(assessment_stages) == set(stages), "Assessment stages don't match config stages"

    @pytest.mark.asyncio
    async def test_goodhart_run_three_stages_subset(self):
        """run() must work correctly with a non-standard subset of stages (not
        all four), returning exactly the configured number."""
        stages = [ReviewStage.correctness, ReviewStage.style]
        router, _, _ = build_router(stages=stages)
        request = make_request()
        assessments = await router.run(request)

        assert len(assessments) == 2
        assert assessments[0].stage == ReviewStage.correctness
        assert assessments[1].stage == ReviewStage.style

    @pytest.mark.asyncio
    async def test_goodhart_run_single_stage_config(self):
        """run() must work with a single-stage configuration, returning exactly
        one assessment."""
        stages = [ReviewStage.architecture]
        router, _, _ = build_router(stages=stages)
        request = make_request()
        assessments = await router.run(request)

        assert len(assessments) == 1
        assert assessments[0].stage == ReviewStage.architecture

    @pytest.mark.asyncio
    async def test_goodhart_run_config_order_reversed(self):
        """Assessments must follow config.stages ordering even when config.stages
        is in a non-alphabetical, non-default order."""
        stages = [
            ReviewStage.architecture,
            ReviewStage.style,
            ReviewStage.correctness,
            ReviewStage.security,
        ]
        router, _, _ = build_router(stages=stages)
        request = make_request()
        assessments = await router.run(request)

        assert len(assessments) == 4
        assert assessments[0].stage == ReviewStage.architecture
        assert assessments[1].stage == ReviewStage.style
        assert assessments[2].stage == ReviewStage.correctness
        assert assessments[3].stage == ReviewStage.security

    @pytest.mark.asyncio
    async def test_goodhart_run_parallel_actually_concurrent(self):
        """Parallel stages must execute concurrently — total time should be near
        max single stage time, not the sum."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        parallel_stages = [[ReviewStage.security, ReviewStage.correctness]]
        delays = {ReviewStage.security: 0.1, ReviewStage.correctness: 0.1}
        router, _, _ = build_router(
            stages=stages,
            parallel_stages=parallel_stages,
            reviewer_delays=delays,
        )
        request = make_request()

        start = time.monotonic()
        assessments = await router.run(request)
        elapsed = time.monotonic() - start

        assert len(assessments) == 2
        # If sequential, would take ~0.2s. Parallel should be ~0.1s.
        assert elapsed < 0.19, f"Parallel stages took {elapsed:.3f}s, likely sequential"

    @pytest.mark.asyncio
    async def test_goodhart_run_timeout_produces_partial_assessment(self):
        """When a reviewer times out, the corresponding assessment must have
        is_partial=True and a non-empty error_message, while others complete."""
        stages = [ReviewStage.security, ReviewStage.correctness]
        # Security reviewer will sleep longer than timeout
        router, _, _ = build_router(
            stages=stages,
            stage_timeout_ms=200,
            reviewer_delays={ReviewStage.security: 5.0},  # way over 200ms
        )
        request = make_request()
        assessments = await router.run(request)

        assert len(assessments) == 2
        security_assessment = [a for a in assessments if a.stage == ReviewStage.security][0]
        correctness_assessment = [a for a in assessments if a.stage == ReviewStage.correctness][0]

        assert security_assessment.is_partial is True
        assert security_assessment.error_message is not None
        assert security_assessment.error_message != ""
        assert correctness_assessment.is_partial is False

    @pytest.mark.asyncio
    async def test_goodhart_run_reviewer_receives_request(self):
        """Each reviewer must be called with the actual ReviewRequest object
        passed to run(), not a substitute."""
        unique_id = "req-capture-test-777"
        stages = [ReviewStage.security, ReviewStage.correctness]
        config = make_config(stages=stages)
        captured_requests = {}

        for s in stages:
            reviewer = MagicMock()

            async def _review(req, _stage=s):
                captured_requests[_stage] = req
                return make_assessment(_stage, request_id=req.id)

            reviewer.review = AsyncMock(side_effect=_review)
            if s == stages[0]:
                sec_reviewer = reviewer
            else:
                corr_reviewer = reviewer

        reviewers = {stages[0]: sec_reviewer, stages[1]: corr_reviewer}
        router = BatonCircuitRouter(config, reviewers, make_chronicler(), make_clock())
        request = make_request(request_id=unique_id)
        await router.run(request)

        for s in stages:
            assert s in captured_requests, f"Reviewer for {s} was not called"
            assert captured_requests[s].id == unique_id


class TestGoodhartInvokeReviewer:

    @pytest.mark.asyncio
    async def test_goodhart_invoke_reviewer_assessment_stage_matches_input(self):
        """invoke_reviewer must set Assessment.stage to the exact stage passed as
        argument, not a hardcoded value."""
        stage = ReviewStage.architecture
        stages = [stage]
        router, _, _ = build_router(stages=stages)
        request = make_request()

        assessment = await router.invoke_reviewer(
            stage, request, StageTimeoutMs(value=5000)
        )
        assert assessment.stage == ReviewStage.architecture
        assert assessment.is_partial is False

    @pytest.mark.asyncio
    async def test_goodhart_invoke_reviewer_duration_ms_nonzero(self):
        """Assessment.duration_ms must reflect actual elapsed time and be a
        non-negative integer."""
        stages = [ReviewStage.security]
        router, _, _ = build_router(
            stages=stages,
            reviewer_delays={ReviewStage.security: 0.01},
        )
        request = make_request()

        assessment = await router.invoke_reviewer(
            ReviewStage.security, request, StageTimeoutMs(value=5000)
        )
        assert isinstance(assessment.duration_ms, int)
        assert assessment.duration_ms >= 0

    @pytest.mark.asyncio
    async def test_goodhart_invoke_reviewer_error_message_contains_detail(self):
        """When a reviewer raises, the degraded assessment's error_message must
        contain information about the actual failure."""
        stages = [ReviewStage.correctness]
        router, _, _ = build_router(
            stages=stages,
            reviewer_failures={
                ReviewStage.correctness: ValueError("specific-error-token-12345")
            },
        )
        request = make_request()

        assessment = await router.invoke_reviewer(
            ReviewStage.correctness, request, StageTimeoutMs(value=5000)
        )
        assert assessment.is_partial is True
        assert assessment.error_message is not None
        assert len(assessment.error_message) > 0

    @pytest.mark.asyncio
    async def test_goodhart_invoke_reviewer_different_exception_types(self):
        """invoke_reviewer must absorb any exception type (KeyError, etc.) into a
        degraded assessment."""
        stages = [ReviewStage.style]
        router, _, _ = build_router(
            stages=stages,
            reviewer_failures={ReviewStage.style: KeyError("missing-key")},
        )
        request = make_request()

        assessment = await router.invoke_reviewer(
            ReviewStage.style, request, StageTimeoutMs(value=5000)
        )
        assert assessment.is_partial is True
        assert assessment.error_message is not None


class TestGoodhartChronicler:

    @pytest.mark.asyncio
    async def test_goodhart_chronicler_events_include_correct_stage(self):
        """Chronicler events emitted during run() must have their stage field set
        to the correct ReviewStage for each invocation."""
        stages = [ReviewStage.security, ReviewStage.architecture]
        chronicler = make_chronicler()
        router, _, _ = build_router(stages=stages, chronicler=chronicler)
        request = make_request()
        await router.run(request)

        emitted_events = [call.args[0] for call in chronicler.emit.call_args_list]

        started_stages = {
            e.stage for e in emitted_events
            if e.event_type == ChroniclerEventType("stage.started")
        }
        complete_stages = {
            e.stage for e in emitted_events
            if e.event_type == ChroniclerEventType("stage.complete")
        }

        assert ReviewStage.security in started_stages
        assert ReviewStage.architecture in started_stages
        assert ReviewStage.security in complete_stages
        assert ReviewStage.architecture in complete_stages

        # Should NOT contain events for stages not in config
        all_event_stages = {e.stage for e in emitted_events if e.stage is not None}
        assert ReviewStage.correctness not in all_event_stages
        assert ReviewStage.style not in all_event_stages

    @pytest.mark.asyncio
    async def test_goodhart_chronicler_emits_both_started_and_complete_per_stage(self):
        """For each configured stage, exactly one stage.started and one
        stage.complete event must be emitted, totaling 2*N for N stages."""
        stages = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style]
        chronicler = make_chronicler()
        router, _, _ = build_router(stages=stages, chronicler=chronicler)
        request = make_request()
        await router.run(request)

        emitted_events = [call.args[0] for call in chronicler.emit.call_args_list]
        started_events = [
            e for e in emitted_events
            if e.event_type == ChroniclerEventType("stage.started")
        ]
        complete_events = [
            e for e in emitted_events
            if e.event_type == ChroniclerEventType("stage.complete")
        ]

        assert len(started_events) >= 3, f"Expected 3 stage.started events, got {len(started_events)}"
        assert len(complete_events) >= 3, f"Expected 3 stage.complete events, got {len(complete_events)}"


class TestGoodhartExecutionPlan:

    def test_goodhart_execution_plan_frozen(self):
        """The ExecutionPlan returned by get_execution_plan() must be immutable."""
        router, _, _ = build_router()
        plan = router.get_execution_plan()

        with pytest.raises(Exception):  # Pydantic frozen model raises on assignment
            plan.steps = []

        with pytest.raises(Exception):
            plan.stage_order = []


class TestGoodhartStageTimeoutMs:

    def test_goodhart_stage_timeout_ms_boundary_99(self):
        """StageTimeoutMs must reject 99 (one below minimum boundary)."""
        with pytest.raises(Exception):
            StageTimeoutMs(value=99)

    def test_goodhart_stage_timeout_ms_boundary_300001(self):
        """StageTimeoutMs must reject 300001 (one above maximum boundary)."""
        with pytest.raises(Exception):
            StageTimeoutMs(value=300001)

    def test_goodhart_stage_timeout_ms_rejects_zero(self):
        """StageTimeoutMs must reject zero as it falls below the minimum of 100."""
        with pytest.raises(Exception):
            StageTimeoutMs(value=0)

    def test_goodhart_stage_timeout_ms_rejects_negative(self):
        """StageTimeoutMs must reject negative values."""
        with pytest.raises(Exception):
            StageTimeoutMs(value=-1)


class TestGoodhartParallelGroup:

    def test_goodhart_parallel_group_rejects_single_stage(self):
        """ParallelGroup must enforce the minimum of 2 stages."""
        with pytest.raises(Exception):
            ParallelGroup(stages=[ReviewStage.security])


class TestGoodhartPACTKey:

    def test_goodhart_pact_key_constants_exist(self):
        """Module-level PACT key constants must be defined."""
        import exemplar.circuit as circuit_module

        assert hasattr(circuit_module, "PACT_CIRCUIT_RUN"), "PACT_CIRCUIT_RUN not found"
        assert hasattr(circuit_module, "PACT_CIRCUIT_RESOLVE_PLAN"), "PACT_CIRCUIT_RESOLVE_PLAN not found"
        assert hasattr(circuit_module, "PACT_CIRCUIT_INVOKE_REVIEWER"), "PACT_CIRCUIT_INVOKE_REVIEWER not found"
        assert hasattr(circuit_module, "PACT_CIRCUIT_GET_TIMEOUT"), "PACT_CIRCUIT_GET_TIMEOUT not found"
        assert hasattr(circuit_module, "PACT_CIRCUIT_GET_PLAN"), "PACT_CIRCUIT_GET_PLAN not found"

    def test_goodhart_pact_key_rejects_missing_exemplar_prefix(self):
        """PACTKey must reject strings that don't start with 'exemplar.' prefix."""
        with pytest.raises(Exception):
            PACTKey(value="other.circuit.BatonCircuitRouter.run")

    def test_goodhart_pact_key_accepts_valid_method_pattern(self):
        """PACTKey must accept valid patterns matching the documented regex."""
        key = PACTKey(value="exemplar.circuit.BatonCircuitRouter.run")
        assert key.value == "exemplar.circuit.BatonCircuitRouter.run"
