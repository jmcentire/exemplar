"""
Adversarial hidden acceptance tests for Root component.
These tests catch implementations that pass visible tests through shortcuts
rather than truly satisfying the contract.
"""
import pytest
import asyncio
import re
from unittest.mock import MagicMock, AsyncMock, patch, PropertyMock
from typing import Any

# Import from the root module
from exemplar.root import (
    PipelineStage,
    ErrorSeverity,
    ExemplarError,
    PipelineStageError,
    PactKeyConstants,
    RootConfig,
    PipelineEvent,
    ExitCodeMapping,
    map_decision_to_exit_code,
)

# Try importing Root and create_root - they may be in different locations
try:
    from exemplar.root import Root, create_root
except ImportError:
    Root = None
    create_root = None


# ============================================================
# PACT KEY REGEX for validation
# ============================================================
PACT_KEY_REGEX = re.compile(r'^exemplar\.root\.[a-z_]+$')


# ============================================================
# map_decision_to_exit_code tests
# ============================================================

class TestGoodhartMapDecision:

    def test_goodhart_map_decision_case_sensitivity(self):
        """map_decision_to_exit_code should reject case variants — only lowercase variants are valid"""
        for bad in ['Pass', 'PASS', 'Warn', 'WARN', 'Block', 'BLOCK']:
            with pytest.raises((ValueError, KeyError, TypeError, Exception)):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_near_miss_strings(self):
        """map_decision_to_exit_code should reject strings similar to but not exactly valid decisions"""
        for bad in ['passed', 'passing', 'warning', 'blocked', 'fail', 'error', 'none']:
            with pytest.raises((ValueError, KeyError, TypeError, Exception)):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_whitespace(self):
        """map_decision_to_exit_code should reject decision strings with leading/trailing whitespace"""
        for bad in [' pass', 'warn ', ' block ', '\tpass', 'warn\n']:
            with pytest.raises((ValueError, KeyError, TypeError, Exception)):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_none_input(self):
        """map_decision_to_exit_code should raise an error when given None"""
        with pytest.raises((ValueError, KeyError, TypeError, AttributeError, Exception)):
            map_decision_to_exit_code(None)

    def test_goodhart_map_decision_numeric_input(self):
        """map_decision_to_exit_code should reject numeric inputs"""
        for bad in [0, 1, 2, 3]:
            with pytest.raises((ValueError, KeyError, TypeError, Exception)):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_return_type(self):
        """map_decision_to_exit_code should return int type for all valid decisions"""
        for decision in ['pass', 'warn', 'block']:
            result = map_decision_to_exit_code(decision)
            assert type(result) is int, f"Expected int, got {type(result)} for '{decision}'"

    def test_goodhart_map_decision_exact_values(self):
        """map_decision_to_exit_code should return exactly 0, 1, 2 — not other integers"""
        assert map_decision_to_exit_code('pass') == 0
        assert map_decision_to_exit_code('warn') == 1
        assert map_decision_to_exit_code('block') == 2


# ============================================================
# ExemplarError pact_key validation tests
# ============================================================

class TestGoodhartPactKeyValidation:

    def _make_error_kwargs(self, pact_key):
        """Helper to create ExemplarError kwargs with a specific pact_key."""
        return dict(
            stage=PipelineStage.intake,
            message="test error",
            pact_key=pact_key,
            cause="",
            error_severity=ErrorSeverity.fatal,
            context={},
        )

    def test_goodhart_pact_key_trailing_dot_rejected(self):
        """ExemplarError should reject pact_key ending with a dot"""
        with pytest.raises((ValueError, Exception)):
            ExemplarError(**self._make_error_kwargs('exemplar.root.'))

    def test_goodhart_pact_key_hyphen_rejected(self):
        """ExemplarError should reject pact_key containing hyphens"""
        with pytest.raises((ValueError, Exception)):
            ExemplarError(**self._make_error_kwargs('exemplar.root.run-pipeline'))

    def test_goodhart_pact_key_extra_dots_rejected(self):
        """ExemplarError should reject pact_key with extra dot-separated segments"""
        with pytest.raises((ValueError, Exception)):
            ExemplarError(**self._make_error_kwargs('exemplar.root.run.pipeline'))

    def test_goodhart_pact_key_space_rejected(self):
        """ExemplarError should reject pact_key containing spaces"""
        with pytest.raises((ValueError, Exception)):
            ExemplarError(**self._make_error_kwargs('exemplar.root.run pipeline'))

    def test_goodhart_pact_key_wrong_prefix_rejected(self):
        """ExemplarError should reject pact_keys that don't start with exemplar.root."""
        for bad in ['exemplar.cli.run', 'root.init', 'exemplar.root', 'other.root.init']:
            with pytest.raises((ValueError, Exception)):
                ExemplarError(**self._make_error_kwargs(bad))

    def test_goodhart_pact_key_multiple_underscores_accepted(self):
        """ExemplarError should accept pact_key with multiple/consecutive underscores"""
        e1 = ExemplarError(**self._make_error_kwargs('exemplar.root.__init__'))
        assert e1.pact_key == 'exemplar.root.__init__'
        e2 = ExemplarError(**self._make_error_kwargs('exemplar.root.a_b_c'))
        assert e2.pact_key == 'exemplar.root.a_b_c'

    def test_goodhart_pact_key_only_underscores_accepted(self):
        """ExemplarError should accept pact_key where suffix is only underscores"""
        e = ExemplarError(**self._make_error_kwargs('exemplar.root.___'))
        assert e.pact_key == 'exemplar.root.___'

    def test_goodhart_pact_key_long_accepted(self):
        """ExemplarError should accept long pact_key with many lowercase letters/underscores"""
        long_key = 'exemplar.root.this_is_a_very_long_method_name_with_many_underscores'
        e = ExemplarError(**self._make_error_kwargs(long_key))
        assert e.pact_key == long_key

    def test_goodhart_pact_key_digits_in_various_positions_rejected(self):
        """ExemplarError should reject pact_key with digits anywhere in the suffix"""
        for bad in ['exemplar.root.init1', 'exemplar.root.1init', 'exemplar.root.in1t']:
            with pytest.raises((ValueError, Exception)):
                ExemplarError(**self._make_error_kwargs(bad))


# ============================================================
# ExemplarError general tests
# ============================================================

class TestGoodhartExemplarError:

    def _make_error_kwargs(self, **overrides):
        defaults = dict(
            stage=PipelineStage.intake,
            message="test message",
            pact_key="exemplar.root.test",
            cause="",
            error_severity=ErrorSeverity.fatal,
            context={},
        )
        defaults.update(overrides)
        return defaults

    def test_goodhart_exemplar_error_is_exception(self):
        """ExemplarError should be a subclass of Exception"""
        assert issubclass(ExemplarError, Exception)

    def test_goodhart_pipeline_stage_error_is_exemplar_error(self):
        """PipelineStageError should be a subclass of ExemplarError"""
        assert issubclass(PipelineStageError, ExemplarError)

    def test_goodhart_exemplar_error_all_stages(self):
        """ExemplarError should accept any PipelineStage variant as the stage field"""
        for stage in PipelineStage:
            e = ExemplarError(**self._make_error_kwargs(stage=stage))
            assert e.stage == stage

    def test_goodhart_exemplar_error_all_severities(self):
        """ExemplarError should correctly store all ErrorSeverity variants"""
        for severity in ErrorSeverity:
            e = ExemplarError(**self._make_error_kwargs(error_severity=severity))
            assert e.error_severity == severity

    def test_goodhart_exemplar_error_message_whitespace_only(self):
        """ExemplarError should accept whitespace-only message since len(' ') >= 1"""
        e = ExemplarError(**self._make_error_kwargs(message=' '))
        assert e.message == ' '

    def test_goodhart_exemplar_error_cause_empty_string(self):
        """ExemplarError should accept an empty string as cause"""
        e = ExemplarError(**self._make_error_kwargs(cause=''))
        assert e.cause == ''

    def test_goodhart_exemplar_error_context_various_dicts(self):
        """ExemplarError context should accept empty and nested dicts"""
        e1 = ExemplarError(**self._make_error_kwargs(context={}))
        assert e1.context == {}
        e2 = ExemplarError(**self._make_error_kwargs(context={'key': 'value', 'nested': {'a': 1}}))
        assert e2.context == {'key': 'value', 'nested': {'a': 1}}


# ============================================================
# PipelineStageError tests
# ============================================================

class TestGoodhartPipelineStageError:

    def test_goodhart_pipeline_stage_error_all_stages(self):
        """PipelineStageError should correctly store each PipelineStage variant"""
        for stage in PipelineStage:
            kwargs = dict(
                stage=stage,
                message="stage error",
                pact_key="exemplar.root.run_pipeline",
                cause="underlying error",
                error_severity=ErrorSeverity.fatal,
                context={},
                component_id="test_component",
            )
            e = PipelineStageError(**kwargs)
            assert e.stage == stage
            assert e.component_id == "test_component"


# ============================================================
# Enum tests
# ============================================================

class TestGoodhartEnums:

    def test_goodhart_pipeline_stage_is_strenum(self):
        """PipelineStage variants should be usable as strings (StrEnum behavior)"""
        for stage in PipelineStage:
            assert isinstance(stage, str), f"{stage} is not a str instance"
            assert stage == stage.value
        assert PipelineStage.intake == 'intake'
        assert PipelineStage.circuit == 'circuit'
        assert PipelineStage.assess == 'assess'
        assert PipelineStage.format == 'format'
        assert PipelineStage.seal == 'seal'

    def test_goodhart_error_severity_is_strenum(self):
        """ErrorSeverity variants should behave as strings with values matching names"""
        for sev in ErrorSeverity:
            assert isinstance(sev, str), f"{sev} is not a str instance"
            assert sev == sev.value
        assert ErrorSeverity.fatal == 'fatal'
        assert ErrorSeverity.recoverable == 'recoverable'
        assert ErrorSeverity.ignorable == 'ignorable'

    def test_goodhart_pipeline_stage_exact_membership(self):
        """PipelineStage should have exactly 5 members"""
        assert len(PipelineStage) == 5
        member_names = {m.name for m in PipelineStage}
        assert member_names == {'intake', 'circuit', 'assess', 'format', 'seal'}

    def test_goodhart_error_severity_exact_membership(self):
        """ErrorSeverity should have exactly 3 members"""
        assert len(ErrorSeverity) == 3
        member_names = {m.name for m in ErrorSeverity}
        assert member_names == {'fatal', 'recoverable', 'ignorable'}


# ============================================================
# PactKeyConstants tests
# ============================================================

class TestGoodhartPactKeyConstants:

    def test_goodhart_pact_key_constants_match_regex(self):
        """All PactKeyConstants values should match the pact_key regex pattern"""
        constant_names = ['ROOT_INIT', 'ROOT_RUN_PIPELINE', 'ROOT_AENTER', 'ROOT_AEXIT',
                          'ROOT_CREATE', 'ROOT_BUILD_PIPELINE_RESULT']
        for name in constant_names:
            value = getattr(PactKeyConstants, name)
            assert isinstance(value, str), f"PactKeyConstants.{name} is not a string"
            assert PACT_KEY_REGEX.match(value), \
                f"PactKeyConstants.{name}='{value}' doesn't match regex ^exemplar\\.root\\.[a-z_]+$"

    def test_goodhart_pact_key_constants_distinct(self):
        """All PactKeyConstants values should be distinct"""
        constant_names = ['ROOT_INIT', 'ROOT_RUN_PIPELINE', 'ROOT_AENTER', 'ROOT_AEXIT',
                          'ROOT_CREATE', 'ROOT_BUILD_PIPELINE_RESULT']
        values = [getattr(PactKeyConstants, name) for name in constant_names]
        assert len(set(values)) == len(values), \
            f"PactKeyConstants has duplicate values: {values}"

    def test_goodhart_pact_key_constants_start_with_prefix(self):
        """All PactKeyConstants values should start with 'exemplar.root.'"""
        constant_names = ['ROOT_INIT', 'ROOT_RUN_PIPELINE', 'ROOT_AENTER', 'ROOT_AEXIT',
                          'ROOT_CREATE', 'ROOT_BUILD_PIPELINE_RESULT']
        for name in constant_names:
            value = getattr(PactKeyConstants, name)
            assert value.startswith('exemplar.root.'), \
                f"PactKeyConstants.{name}='{value}' doesn't start with 'exemplar.root.'"


# ============================================================
# RootConfig tests
# ============================================================

class TestGoodhartRootConfig:

    def test_goodhart_root_config_frozen(self):
        """RootConfig should be frozen — mutation should raise an error"""
        config = RootConfig(
            chronicle_log_path="/tmp/chronicle",
            seal_chain_path="/tmp/seal",
            kindex_store_path="/tmp/kindex",
            stigmergy_store_path="/tmp/stigmergy",
        )
        with pytest.raises((AttributeError, TypeError, Exception)):
            config.chronicle_log_path = "/new/path"

    def test_goodhart_root_config_each_path_validated_independently(self):
        """RootConfig should reject empty string in each individual path field"""
        valid_paths = dict(
            chronicle_log_path="/tmp/c",
            seal_chain_path="/tmp/s",
            kindex_store_path="/tmp/k",
            stigmergy_store_path="/tmp/st",
        )
        for field in valid_paths:
            kwargs = dict(valid_paths)
            kwargs[field] = ""
            with pytest.raises((ValueError, Exception)):
                RootConfig(**kwargs)


# ============================================================
# ExitCodeMapping tests
# ============================================================

class TestGoodhartExitCodeMapping:

    def test_goodhart_exit_code_mapping_has_error_code(self):
        """ExitCodeMapping should have an error_code field (for the invariant pass→0, warn→1, block→2, error→3)"""
        m = ExitCodeMapping(pass_code=0, warn_code=1, block_code=2, error_code=3)
        assert m.pass_code == 0
        assert m.warn_code == 1
        assert m.block_code == 2
        assert m.error_code == 3

    def test_goodhart_exit_code_mapping_stores_values_not_defaults(self):
        """ExitCodeMapping should store the exact values passed, not hardcoded defaults"""
        m = ExitCodeMapping(pass_code=10, warn_code=20, block_code=30, error_code=40)
        assert m.pass_code == 10
        assert m.warn_code == 20
        assert m.block_code == 30
        assert m.error_code == 40


# ============================================================
# PipelineEvent tests
# ============================================================

class TestGoodhartPipelineEvent:

    def test_goodhart_pipeline_event_stores_all_fields(self):
        """PipelineEvent should store all four fields correctly with various values"""
        e = PipelineEvent(
            event_type="stage.started",
            stage="circuit",
            message="starting circuit stage",
            payload={"pact_key": "exemplar.root.run_pipeline", "extra": 42},
        )
        assert e.event_type == "stage.started"
        assert e.stage == "circuit"
        assert e.message == "starting circuit stage"
        assert e.payload == {"pact_key": "exemplar.root.run_pipeline", "extra": 42}

    def test_goodhart_pipeline_event_various_stages(self):
        """PipelineEvent stage field should accept all pipeline stage name strings"""
        for stage_name in ['intake', 'circuit', 'assess', 'format', 'seal']:
            e = PipelineEvent(
                event_type="stage.started",
                stage=stage_name,
                message="test",
                payload={},
            )
            assert e.stage == stage_name
