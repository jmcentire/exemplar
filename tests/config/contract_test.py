"""
Contract tests for the exemplar.config module.
Tests verify behavior at boundaries based on the contract specification.
"""

import os
import re
import stat
import sys
import pytest
import yaml
from pathlib import Path
from unittest.mock import patch, MagicMock

from exemplar.config import (
    ConfigSource,
    ConfigError,
    ConfigFileNotFoundError,
    ConfigValidationError,
    ConfigParseError,
    LedgerFieldRule,
    LedgerConfig,
    ReviewerConfig,
    ReviewerConfigMap,
    CircuitConfig,
    ApprenticeConfig,
    ExemplarConfig,
    ResolvedConfigPath,
    Severity,
    ReviewStage,
    LearnerPhase,
    ClassificationLabel,
    default_config,
    resolve_config_path,
    load_config,
    config_to_yaml,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_config():
    """Returns the canonical default config for reuse across tests."""
    return default_config()


@pytest.fixture
def write_yaml(tmp_path):
    """Factory fixture that writes YAML content to a temp file and returns the path."""
    def _write(content, filename="config.yaml"):
        p = tmp_path / filename
        p.write_text(content, encoding="utf-8")
        return p
    return _write


@pytest.fixture
def minimal_yaml():
    """Minimal valid YAML that overrides a single field."""
    return "chronicle_log_path: /tmp/test_chronicle.log\n"


@pytest.fixture
def full_yaml(sample_config):
    """Full YAML generated from default config for complete override testing."""
    return config_to_yaml(sample_config)


# ---------------------------------------------------------------------------
# TestDefaultConfig
# ---------------------------------------------------------------------------

class TestDefaultConfig:
    """Verify default_config() returns a valid ExemplarConfig with all expected defaults."""

    def test_default_config_returns_valid(self):
        """default_config() returns a valid ExemplarConfig instance."""
        config = default_config()
        assert isinstance(config, ExemplarConfig)

    def test_default_config_all_reviewers_enabled(self):
        """All four reviewers are enabled with trust_weight=1.0."""
        config = default_config()
        for name in ("security", "correctness", "style", "architecture"):
            reviewer = config.reviewers[name]
            assert reviewer.enabled is True, f"Reviewer {name} should be enabled"
            assert reviewer.default_trust_weight == 1.0, f"Reviewer {name} trust_weight should be 1.0"

    def test_default_config_circuit_stages(self):
        """CircuitConfig.stages contains the required stages."""
        config = default_config()
        stage_values = [s.value if hasattr(s, 'value') else str(s) for s in config.circuit.stages]
        for required in ("intake", "security", "correctness", "style", "architecture", "assess", "report"):
            # Check either as string value or as the stage name
            found = any(required in str(s) for s in config.circuit.stages) or required in stage_values
            assert found, f"Stage '{required}' missing from circuit stages: {config.circuit.stages}"

    def test_default_config_parallel_subset(self):
        """parallel_stages elements are all within stages."""
        config = default_config()
        stages_set = set(config.circuit.stages)
        for group in config.circuit.parallel_stages:
            for stage in group:
                assert stage in stages_set, f"Parallel stage {stage} not in stages"

    def test_default_config_threshold_ordering(self):
        """warn_threshold <= block_threshold."""
        config = default_config()
        assert config.circuit.warn_threshold <= config.circuit.block_threshold

    def test_default_config_ledger_secret_rule(self):
        """LedgerConfig contains at least one SECRET detection rule."""
        config = default_config()
        labels = [r.label for r in config.ledger.rules]
        label_values = [l.value if hasattr(l, 'value') else str(l) for l in labels]
        assert any("secret" in str(l).lower() for l in labels) or any("secret" in v.lower() for v in label_values), \
            f"No SECRET rule found in ledger rules. Labels: {labels}"

    def test_default_config_ledger_pii_rule(self):
        """LedgerConfig contains at least one PII detection rule."""
        config = default_config()
        labels = [r.label for r in config.ledger.rules]
        label_values = [l.value if hasattr(l, 'value') else str(l) for l in labels]
        assert any("pii" in str(l).lower() for l in labels) or any("pii" in v.lower() for v in label_values), \
            f"No PII rule found in ledger rules. Labels: {labels}"

    def test_default_config_apprentice_shadow(self):
        """ApprenticeConfig.phase is shadow mode."""
        config = default_config()
        phase = config.apprentice.phase
        assert str(phase).lower().endswith("shadow") or (hasattr(phase, 'value') and phase.value == "shadow"), \
            f"Apprentice phase should be shadow, got {phase}"

    def test_default_config_ledger_regex_valid(self):
        """All LedgerFieldRule patterns compile as valid regex."""
        config = default_config()
        for rule in config.ledger.rules:
            try:
                re.compile(rule.pattern)
            except re.error as e:
                pytest.fail(f"Invalid regex pattern '{rule.pattern}': {e}")

    def test_default_config_immutable(self):
        """ExemplarConfig is frozen and rejects mutation at top level."""
        config = default_config()
        with pytest.raises((AttributeError, TypeError, Exception)):
            config.chronicle_log_path = "/changed"

    def test_default_config_idempotent(self):
        """Calling default_config() multiple times returns equivalent configs."""
        c1 = default_config()
        c2 = default_config()
        assert c1 == c2


# ---------------------------------------------------------------------------
# TestResolveConfigPath
# ---------------------------------------------------------------------------

class TestResolveConfigPath:
    """Test config path resolution across all cascade levels."""

    def test_resolve_explicit_path(self):
        """When explicit path is provided, returns (explicit, ConfigSource.explicit)."""
        explicit = Path("/some/config.yaml")
        result = resolve_config_path(explicit)
        assert isinstance(result, ResolvedConfigPath)
        assert result.path == explicit
        assert result.source == ConfigSource.explicit

    def test_resolve_env_var(self, monkeypatch, tmp_path):
        """When explicit is None and EXEMPLAR_CONFIG env var is set, returns env_var source."""
        env_path = str(tmp_path / "env_config.yaml")
        monkeypatch.setenv("EXEMPLAR_CONFIG", env_path)
        result = resolve_config_path(None)
        assert result.path == Path(env_path)
        assert result.source == ConfigSource.env_var

    def test_resolve_conventional(self, monkeypatch, tmp_path):
        """When no explicit/env var, .exemplar/config.yaml in CWD returns conventional source."""
        monkeypatch.delenv("EXEMPLAR_CONFIG", raising=False)
        conv_dir = tmp_path / ".exemplar"
        conv_dir.mkdir()
        conv_file = conv_dir / "config.yaml"
        conv_file.write_text("# conventional config\n")
        monkeypatch.chdir(tmp_path)
        result = resolve_config_path(None)
        assert result.path == conv_file
        assert result.source == ConfigSource.conventional

    def test_resolve_builtin_fallback(self, monkeypatch, tmp_path):
        """When no path found by any method, returns (None, ConfigSource.builtin)."""
        monkeypatch.delenv("EXEMPLAR_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        result = resolve_config_path(None)
        assert result.path is None
        assert result.source == ConfigSource.builtin

    def test_resolve_env_var_empty_string(self, monkeypatch, tmp_path):
        """Empty EXEMPLAR_CONFIG env var is treated as unset."""
        monkeypatch.setenv("EXEMPLAR_CONFIG", "")
        monkeypatch.chdir(tmp_path)
        result = resolve_config_path(None)
        # Should fall through to conventional or builtin
        assert result.source in (ConfigSource.conventional, ConfigSource.builtin)

    def test_resolve_explicit_takes_priority_over_env(self, monkeypatch):
        """Explicit path takes priority over env var."""
        monkeypatch.setenv("EXEMPLAR_CONFIG", "/env/config.yaml")
        explicit = Path("/explicit/config.yaml")
        result = resolve_config_path(explicit)
        assert result.path == explicit
        assert result.source == ConfigSource.explicit

    def test_resolve_source_never_none(self, monkeypatch, tmp_path):
        """source field is never None in any resolution scenario."""
        monkeypatch.delenv("EXEMPLAR_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        # Test all scenarios
        for explicit in [Path("/test"), None]:
            result = resolve_config_path(explicit)
            assert result.source is not None


# ---------------------------------------------------------------------------
# TestLoadConfig
# ---------------------------------------------------------------------------

class TestLoadConfig:
    """Test load_config() happy paths and error cases."""

    def test_load_config_no_file_returns_default(self, monkeypatch, tmp_path):
        """load_config() with no config file returns default_config()."""
        monkeypatch.delenv("EXEMPLAR_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        result = load_config(None)
        expected = default_config()
        assert result == expected

    def test_load_config_valid_partial_yaml(self, write_yaml):
        """load_config with partial YAML returns merged config with defaults."""
        yaml_content = "chronicle_log_path: /custom/chronicle.log\n"
        path = write_yaml(yaml_content)
        result = load_config(path)
        assert isinstance(result, ExemplarConfig)
        assert result.chronicle_log_path == "/custom/chronicle.log"
        # Other fields should be defaults
        defaults = default_config()
        assert result.kindex_store_path == defaults.kindex_store_path

    def test_load_config_empty_yaml(self, write_yaml):
        """An empty YAML file (null document) returns default_config()."""
        path = write_yaml("")
        result = load_config(path)
        expected = default_config()
        assert result == expected

    def test_load_config_null_document(self, write_yaml):
        """A YAML file containing only 'null' returns default_config()."""
        path = write_yaml("null\n")
        result = load_config(path)
        expected = default_config()
        assert result == expected

    def test_load_config_file_not_found(self, tmp_path):
        """Raises ConfigFileNotFoundError when explicit path does not exist."""
        missing = tmp_path / "nonexistent.yaml"
        with pytest.raises((ConfigFileNotFoundError, ConfigError)) as exc_info:
            load_config(missing)
        err = exc_info.value
        assert hasattr(err, 'message') or hasattr(err, 'args')
        # Verify path is recorded
        if hasattr(err, 'path'):
            assert err.path is not None

    def test_load_config_yaml_parse_error(self, write_yaml):
        """Raises ConfigParseError when YAML file has invalid syntax."""
        invalid_yaml = "{\n  bad: yaml: content: [\n"
        path = write_yaml(invalid_yaml)
        with pytest.raises((ConfigParseError, ConfigError)):
            load_config(path)

    def test_load_config_validation_error(self, write_yaml):
        """Raises ConfigValidationError when parsed YAML fails validation."""
        # stage_timeout_ms must be > 0
        invalid_config = "circuit:\n  stage_timeout_ms: -1\n"
        path = write_yaml(invalid_config)
        with pytest.raises((ConfigValidationError, ConfigError)):
            load_config(path)

    @pytest.mark.skipif(sys.platform == "win32", reason="Permission tests unreliable on Windows")
    def test_load_config_permission_denied(self, tmp_path):
        """Raises error when config file is not readable."""
        path = tmp_path / "unreadable.yaml"
        path.write_text("chronicle_log_path: /test\n")
        path.chmod(0o000)
        try:
            with pytest.raises((ConfigError, PermissionError, OSError)):
                load_config(path)
        finally:
            # Restore permissions for cleanup
            path.chmod(0o644)

    def test_load_config_passes_all_validators(self, write_yaml):
        """Returned config passes all model validators and field constraints."""
        yaml_content = "chronicle_log_path: /custom/path\n"
        path = write_yaml(yaml_content)
        result = load_config(path)
        assert isinstance(result, ExemplarConfig)
        # Should not raise
        assert result.circuit.stage_timeout_ms > 0

    def test_load_config_ledger_regex_valid(self, write_yaml):
        """All LedgerFieldRule patterns in returned config compile as valid regex."""
        yaml_content = "chronicle_log_path: /test\n"
        path = write_yaml(yaml_content)
        result = load_config(path)
        for rule in result.ledger.rules:
            re.compile(rule.pattern)  # Should not raise

    def test_load_config_full_yaml_override(self, sample_config, write_yaml):
        """load_config with full YAML overrides all fields correctly."""
        full = config_to_yaml(sample_config)
        path = write_yaml(full)
        result = load_config(path)
        assert isinstance(result, ExemplarConfig)
        # Should be equivalent to the original
        assert result == sample_config


# ---------------------------------------------------------------------------
# TestConfigToYaml
# ---------------------------------------------------------------------------

class TestConfigToYaml:
    """Test config_to_yaml() serialization."""

    def test_config_to_yaml_valid_output(self, sample_config):
        """config_to_yaml returns valid YAML parseable by yaml.safe_load."""
        output = config_to_yaml(sample_config)
        assert isinstance(output, str)
        parsed = yaml.safe_load(output)
        assert isinstance(parsed, dict)

    def test_config_to_yaml_contains_top_level_keys(self, sample_config):
        """YAML output contains all expected top-level keys."""
        output = config_to_yaml(sample_config)
        parsed = yaml.safe_load(output)
        expected_keys = {"circuit", "reviewers", "ledger", "apprentice",
                         "chronicle_log_path", "kindex_store_path",
                         "stigmergy_store_path", "seal_chain_path"}
        for key in expected_keys:
            assert key in parsed, f"Missing top-level key: {key}"

    def test_config_to_yaml_roundtrip(self, sample_config):
        """Round-trip: config_to_yaml -> safe_load -> model_validate produces equivalent config."""
        output = config_to_yaml(sample_config)
        parsed = yaml.safe_load(output)
        reconstructed = ExemplarConfig.model_validate(parsed)
        assert reconstructed == sample_config

    def test_config_to_yaml_enum_serialization(self, sample_config):
        """StrEnum values are serialized correctly in YAML output."""
        output = config_to_yaml(sample_config)
        parsed = yaml.safe_load(output)
        # Apprentice phase should be a string
        assert isinstance(parsed["apprentice"]["phase"], str)
        assert parsed["apprentice"]["phase"] == "shadow"


# ---------------------------------------------------------------------------
# TestConfigRoundTrip
# ---------------------------------------------------------------------------

class TestConfigRoundTrip:
    """Round-trip tests ensuring config_to_yaml -> load_config equivalence."""

    def test_roundtrip_default_config(self, write_yaml):
        """Default config survives round-trip through YAML."""
        original = default_config()
        yaml_str = config_to_yaml(original)
        path = write_yaml(yaml_str)
        loaded = load_config(path)
        assert loaded == original

    def test_roundtrip_modified_config(self, write_yaml):
        """Modified config (via YAML override) survives round-trip."""
        # First load with an override
        override_yaml = "chronicle_log_path: /roundtrip/test.log\n"
        path1 = write_yaml(override_yaml, "step1.yaml")
        config1 = load_config(path1)

        # Serialize and re-load
        yaml_str = config_to_yaml(config1)
        path2 = write_yaml(yaml_str, "step2.yaml")
        config2 = load_config(path2)
        assert config1 == config2

    def test_roundtrip_yaml_is_safe_loadable(self, sample_config):
        """YAML output only uses safe types (no Python-specific tags)."""
        output = config_to_yaml(sample_config)
        # safe_load should not raise
        parsed = yaml.safe_load(output)
        assert parsed is not None


# ---------------------------------------------------------------------------
# TestConfigErrors
# ---------------------------------------------------------------------------

class TestConfigErrors:
    """Verify error struct construction, validation, and field access."""

    def test_config_error_valid_construction(self):
        """ConfigError can be constructed with valid message and optional path."""
        err = ConfigError(message="Something failed", path=None)
        assert err.message == "Something failed"
        assert err.path is None

    def test_config_error_with_path(self):
        """ConfigError can include a path for diagnostics."""
        err = ConfigError(message="File issue", path=Path("/some/path"))
        assert err.path == Path("/some/path")

    def test_config_error_empty_message_rejected(self):
        """ConfigError rejects empty string message."""
        with pytest.raises(Exception):  # Pydantic ValidationError
            ConfigError(message="", path=None)

    def test_config_file_not_found_error_fields(self):
        """ConfigFileNotFoundError has message and path fields."""
        err = ConfigFileNotFoundError(message="Not found", path=Path("/missing"))
        assert err.message == "Not found"
        assert err.path == Path("/missing")

    def test_config_file_not_found_error_empty_msg(self):
        """ConfigFileNotFoundError rejects empty message."""
        with pytest.raises(Exception):
            ConfigFileNotFoundError(message="", path=Path("/x"))

    def test_config_validation_error_fields(self):
        """ConfigValidationError has message, path, and validation_errors."""
        err = ConfigValidationError(
            message="Validation failed",
            path=Path("/config.yaml"),
            validation_errors=[{"field": "timeout", "error": "must be positive"}]
        )
        assert err.message == "Validation failed"
        assert err.path == Path("/config.yaml")
        assert len(err.validation_errors) == 1

    def test_config_validation_error_none_path(self):
        """ConfigValidationError can have None path."""
        err = ConfigValidationError(
            message="Validation failed",
            path=None,
            validation_errors=[]
        )
        assert err.path is None

    def test_config_parse_error_fields(self):
        """ConfigParseError has message and path."""
        err = ConfigParseError(message="Parse failure", path=Path("/bad.yaml"))
        assert err.message == "Parse failure"
        assert err.path == Path("/bad.yaml")

    def test_config_parse_error_empty_msg(self):
        """ConfigParseError rejects empty message."""
        with pytest.raises(Exception):
            ConfigParseError(message="", path=Path("/x"))


# ---------------------------------------------------------------------------
# TestEnums
# ---------------------------------------------------------------------------

class TestEnums:
    """Verify all enum types have expected variants."""

    def test_config_source_enum_values(self):
        """ConfigSource has explicit, env_var, conventional, builtin variants."""
        assert ConfigSource.explicit is not None
        assert ConfigSource.env_var is not None
        assert ConfigSource.conventional is not None
        assert ConfigSource.builtin is not None
        # Verify string values
        assert str(ConfigSource.explicit) == "explicit" or ConfigSource.explicit.value == "explicit"

    def test_severity_enum_values(self):
        """Severity has all expected variants."""
        for name in ("critical", "high", "medium", "low", "info"):
            assert hasattr(Severity, name), f"Severity missing variant: {name}"

    def test_review_stage_enum_values(self):
        """ReviewStage has all expected variants."""
        for name in ("security", "correctness", "style", "architecture"):
            assert hasattr(ReviewStage, name), f"ReviewStage missing variant: {name}"

    def test_learner_phase_enum_values(self):
        """LearnerPhase has all expected variants."""
        for name in ("shadow", "canary", "primary"):
            assert hasattr(LearnerPhase, name), f"LearnerPhase missing variant: {name}"

    def test_classification_label_enum_values(self):
        """ClassificationLabel has all expected variants."""
        for name in ("secret", "pii", "internal_api", "public"):
            assert hasattr(ClassificationLabel, name), f"ClassificationLabel missing variant: {name}"


# ---------------------------------------------------------------------------
# TestTypeValidation
# ---------------------------------------------------------------------------

class TestTypeValidation:
    """Test field validators on configuration types."""

    def test_reviewer_config_trust_weight_too_high(self):
        """ReviewerConfig rejects trust_weight > 1.0."""
        with pytest.raises(Exception):
            ReviewerConfig(
                enabled=True,
                stage=ReviewStage.security,
                default_trust_weight=1.5,
                allowed_file_patterns=[],
                denied_file_patterns=[],
                allowed_classifications=[],
                max_severity=Severity.critical,
            )

    def test_reviewer_config_trust_weight_negative(self):
        """ReviewerConfig rejects trust_weight < 0.0."""
        with pytest.raises(Exception):
            ReviewerConfig(
                enabled=True,
                stage=ReviewStage.security,
                default_trust_weight=-0.1,
                allowed_file_patterns=[],
                denied_file_patterns=[],
                allowed_classifications=[],
                max_severity=Severity.critical,
            )

    def test_reviewer_config_trust_weight_at_zero(self):
        """ReviewerConfig accepts trust_weight=0.0 (boundary)."""
        rc = ReviewerConfig(
            enabled=True,
            stage=ReviewStage.security,
            default_trust_weight=0.0,
            allowed_file_patterns=[],
            denied_file_patterns=[],
            allowed_classifications=[],
            max_severity=Severity.critical,
        )
        assert rc.default_trust_weight == 0.0

    def test_reviewer_config_trust_weight_at_one(self):
        """ReviewerConfig accepts trust_weight=1.0 (boundary)."""
        rc = ReviewerConfig(
            enabled=True,
            stage=ReviewStage.security,
            default_trust_weight=1.0,
            allowed_file_patterns=[],
            denied_file_patterns=[],
            allowed_classifications=[],
            max_severity=Severity.critical,
        )
        assert rc.default_trust_weight == 1.0

    def test_circuit_config_timeout_zero_rejected(self):
        """CircuitConfig rejects stage_timeout_ms=0."""
        with pytest.raises(Exception):
            CircuitConfig(
                stages=[],
                parallel_stages=[],
                stage_timeout_ms=0,
                block_threshold=5,
                warn_threshold=3,
            )

    def test_circuit_config_timeout_negative_rejected(self):
        """CircuitConfig rejects stage_timeout_ms=-1."""
        with pytest.raises(Exception):
            CircuitConfig(
                stages=[],
                parallel_stages=[],
                stage_timeout_ms=-1,
                block_threshold=5,
                warn_threshold=3,
            )

    def test_circuit_config_timeout_positive_accepted(self):
        """CircuitConfig accepts stage_timeout_ms=1 (minimum positive)."""
        cc = CircuitConfig(
            stages=[],
            parallel_stages=[],
            stage_timeout_ms=1,
            block_threshold=5,
            warn_threshold=3,
        )
        assert cc.stage_timeout_ms == 1

    def test_apprentice_shadow_to_canary_too_high(self):
        """ApprenticeConfig rejects shadow_to_canary_threshold > 1.0."""
        with pytest.raises(Exception):
            ApprenticeConfig(
                phase=LearnerPhase.shadow,
                storage_path="/tmp/store",
                shadow_to_canary_threshold=1.1,
                canary_to_primary_threshold=0.5,
            )

    def test_apprentice_canary_to_primary_negative(self):
        """ApprenticeConfig rejects canary_to_primary_threshold < 0.0."""
        with pytest.raises(Exception):
            ApprenticeConfig(
                phase=LearnerPhase.shadow,
                storage_path="/tmp/store",
                shadow_to_canary_threshold=0.5,
                canary_to_primary_threshold=-0.1,
            )

    def test_ledger_field_rule_construction(self):
        """LedgerFieldRule can be constructed with valid fields."""
        rule = LedgerFieldRule(
            pattern=r"password\s*=",
            label=ClassificationLabel.secret,
            description="Detects password assignments",
        )
        assert rule.pattern == r"password\s*="
        assert rule.label == ClassificationLabel.secret
        assert rule.description == "Detects password assignments"

    def test_resolved_config_path_construction(self):
        """ResolvedConfigPath can be constructed with path and source."""
        rcp = ResolvedConfigPath(path=Path("/test"), source=ConfigSource.explicit)
        assert rcp.path == Path("/test")
        assert rcp.source == ConfigSource.explicit

    def test_resolved_config_path_none_path(self):
        """ResolvedConfigPath can have None path for builtin source."""
        rcp = ResolvedConfigPath(path=None, source=ConfigSource.builtin)
        assert rcp.path is None
        assert rcp.source == ConfigSource.builtin


# ---------------------------------------------------------------------------
# TestConfigImmutability
# ---------------------------------------------------------------------------

class TestConfigImmutability:
    """Verify frozen models reject mutation at all nesting levels."""

    def test_immutability_top_level(self):
        """Top-level ExemplarConfig fields are immutable."""
        config = default_config()
        with pytest.raises((AttributeError, TypeError, Exception)):
            config.seal_chain_path = "/changed"

    def test_immutability_circuit_config(self):
        """CircuitConfig fields are immutable."""
        config = default_config()
        with pytest.raises((AttributeError, TypeError, Exception)):
            config.circuit.stage_timeout_ms = 999

    def test_immutability_apprentice_config(self):
        """ApprenticeConfig fields are immutable."""
        config = default_config()
        with pytest.raises((AttributeError, TypeError, Exception)):
            config.apprentice.phase = LearnerPhase.primary

    def test_immutability_nested_reviewer(self):
        """Nested ReviewerConfig fields are immutable."""
        config = default_config()
        reviewer = config.reviewers.get("security") or list(config.reviewers.values())[0]
        with pytest.raises((AttributeError, TypeError, Exception)):
            reviewer.enabled = False


# ---------------------------------------------------------------------------
# TestInvariants
# ---------------------------------------------------------------------------

class TestInvariants:
    """Cross-cutting invariant tests from the contract."""

    def test_default_config_always_valid(self):
        """default_config() always returns a valid ExemplarConfig that passes all validators."""
        for _ in range(5):
            config = default_config()
            assert isinstance(config, ExemplarConfig)
            # Re-validate by round-tripping through model_validate
            yaml_str = config_to_yaml(config)
            parsed = yaml.safe_load(yaml_str)
            ExemplarConfig.model_validate(parsed)

    def test_load_no_args_no_file_equals_default(self, monkeypatch, tmp_path):
        """load_config() with no arguments and no config file returns default_config()."""
        monkeypatch.delenv("EXEMPLAR_CONFIG", raising=False)
        monkeypatch.chdir(tmp_path)
        result = load_config(None)
        expected = default_config()
        assert result == expected

    def test_resolution_order_explicit_over_env(self, monkeypatch):
        """Config path resolution: explicit > env_var."""
        monkeypatch.setenv("EXEMPLAR_CONFIG", "/env/path.yaml")
        result = resolve_config_path(Path("/explicit/path.yaml"))
        assert result.source == ConfigSource.explicit

    def test_resolution_order_env_over_conventional(self, monkeypatch, tmp_path):
        """Config path resolution: env_var > conventional."""
        conv_dir = tmp_path / ".exemplar"
        conv_dir.mkdir()
        (conv_dir / "config.yaml").write_text("# conv\n")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("EXEMPLAR_CONFIG", "/env/path.yaml")
        result = resolve_config_path(None)
        assert result.source == ConfigSource.env_var

    def test_resolution_order_conventional_over_builtin(self, monkeypatch, tmp_path):
        """Config path resolution: conventional > builtin."""
        monkeypatch.delenv("EXEMPLAR_CONFIG", raising=False)
        conv_dir = tmp_path / ".exemplar"
        conv_dir.mkdir()
        (conv_dir / "config.yaml").write_text("# conv\n")
        monkeypatch.chdir(tmp_path)
        result = resolve_config_path(None)
        assert result.source == ConfigSource.conventional

    def test_empty_yaml_produces_default(self, write_yaml):
        """An empty YAML file produces default_config()."""
        path = write_yaml("")
        result = load_config(path)
        assert result == default_config()

    def test_parallel_stages_subset_of_stages(self):
        """parallel_stages is always a subset of stages in valid CircuitConfig."""
        config = default_config()
        stages_set = set(config.circuit.stages)
        for group in config.circuit.parallel_stages:
            for stage in group:
                assert stage in stages_set

    def test_all_ledger_patterns_are_compilable_regex(self):
        """Every LedgerFieldRule.pattern is a compilable regex."""
        config = default_config()
        for rule in config.ledger.rules:
            compiled = re.compile(rule.pattern)
            assert compiled is not None
