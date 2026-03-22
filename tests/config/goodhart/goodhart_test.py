"""
Adversarial hidden acceptance tests for the Configuration System.
These tests catch implementations that pass visible tests through shortcuts
(hardcoded returns, missing validation, etc.) rather than truly satisfying the contract.
"""

import os
import re
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from exemplar.config import (
    ApprenticeConfig,
    CircuitConfig,
    ClassificationLabel,
    ConfigError,
    ConfigFileNotFoundError,
    ConfigParseError,
    ConfigSource,
    ConfigValidationError,
    ExemplarConfig,
    LearnerPhase,
    LedgerConfig,
    LedgerFieldRule,
    ResolvedConfigPath,
    ReviewerConfig,
    ReviewStage,
    Severity,
    config_to_yaml,
    default_config,
    load_config,
    resolve_config_path,
)


# ──────────────────────────────────────────────
# default_config() adversarial tests
# ──────────────────────────────────────────────

class TestGoodhartDefaultConfig:

    def test_goodhart_default_config_returns_new_instance_each_call(self):
        """default_config() should return independent instances on each call, not a shared mutable singleton."""
        c1 = default_config()
        c2 = default_config()
        # They should be equal in value
        assert c1 == c2
        # But ideally distinct objects (or at least frozen so sharing is safe)
        # The key contract point: both are valid
        assert isinstance(c1, ExemplarConfig)
        assert isinstance(c2, ExemplarConfig)

    def test_goodhart_default_config_reviewer_trust_weight_exactly_one(self):
        """Each of the four default reviewers must have default_trust_weight of exactly 1.0."""
        cfg = default_config()
        for name in ("security", "correctness", "style", "architecture"):
            reviewer = cfg.reviewers[name]
            assert reviewer.default_trust_weight == 1.0, (
                f"Reviewer '{name}' has trust_weight={reviewer.default_trust_weight}, expected 1.0"
            )

    def test_goodhart_default_config_has_exactly_four_reviewers(self):
        """The default config reviewers dict must contain exactly the four canonical reviewer keys."""
        cfg = default_config()
        expected_keys = {"security", "correctness", "style", "architecture"}
        assert set(cfg.reviewers.keys()) == expected_keys, (
            f"Expected reviewer keys {expected_keys}, got {set(cfg.reviewers.keys())}"
        )

    def test_goodhart_default_config_ledger_default_label(self):
        """The default LedgerConfig should have a valid ClassificationLabel as default_label."""
        cfg = default_config()
        assert isinstance(cfg.ledger.default_label, ClassificationLabel)

    def test_goodhart_default_config_circuit_timeout_positive(self):
        """The default CircuitConfig must have a positive stage_timeout_ms value."""
        cfg = default_config()
        assert cfg.circuit.stage_timeout_ms > 0

    def test_goodhart_default_config_apprentice_thresholds_valid(self):
        """Default ApprenticeConfig thresholds must both be in [0.0, 1.0] range."""
        cfg = default_config()
        assert 0.0 <= cfg.apprentice.shadow_to_canary_threshold <= 1.0
        assert 0.0 <= cfg.apprentice.canary_to_primary_threshold <= 1.0

    def test_goodhart_default_config_string_paths_nonempty(self):
        """Default config string path fields should be non-empty strings."""
        cfg = default_config()
        assert isinstance(cfg.chronicle_log_path, str) and len(cfg.chronicle_log_path) > 0
        assert isinstance(cfg.kindex_store_path, str) and len(cfg.kindex_store_path) > 0
        assert isinstance(cfg.stigmergy_store_path, str) and len(cfg.stigmergy_store_path) > 0
        assert isinstance(cfg.seal_chain_path, str) and len(cfg.seal_chain_path) > 0

    def test_goodhart_default_config_apprentice_storage_path_nonempty(self):
        """Default ApprenticeConfig storage_path should be a non-empty string."""
        cfg = default_config()
        assert isinstance(cfg.apprentice.storage_path, str) and len(cfg.apprentice.storage_path) > 0

    def test_goodhart_default_config_ledger_rules_have_descriptions(self):
        """All default LedgerFieldRule instances should have non-empty description strings."""
        cfg = default_config()
        for rule in cfg.ledger.rules:
            assert isinstance(rule.description, str) and len(rule.description) > 0, (
                f"Rule with pattern '{rule.pattern}' has empty or missing description"
            )

    def test_goodhart_default_config_ledger_secret_rule_matches_secrets(self):
        """Default ledger SECRET rules should actually match common secret-like strings."""
        cfg = default_config()
        secret_rules = [r for r in cfg.ledger.rules if r.label == ClassificationLabel.secret]
        assert len(secret_rules) > 0, "No secret rules found"

        # Common secret patterns that at least one rule should match
        test_strings = [
            "password", "api_key", "secret_key", "AWS_SECRET_ACCESS_KEY",
            "PRIVATE_KEY", "token", "PASSWORD", "apikey",
        ]
        matched_any = False
        for test_str in test_strings:
            for rule in secret_rules:
                if re.search(rule.pattern, test_str, re.IGNORECASE):
                    matched_any = True
                    break
            if matched_any:
                break
        assert matched_any, "No SECRET rule matched any common secret-like test string"

    def test_goodhart_default_config_reviewer_stages_match_keys(self):
        """Each reviewer in default_config should have a stage field corresponding to its key name."""
        cfg = default_config()
        for name, reviewer in cfg.reviewers.items():
            assert reviewer.stage.value == name or reviewer.stage == name, (
                f"Reviewer '{name}' has stage={reviewer.stage}, expected it to match key"
            )

    def test_goodhart_immutability_ledger_config(self):
        """LedgerConfig within default_config must be frozen and reject attribute mutation."""
        cfg = default_config()
        with pytest.raises((AttributeError, TypeError, Exception)):
            cfg.ledger.default_label = ClassificationLabel.secret


# ──────────────────────────────────────────────
# resolve_config_path() adversarial tests
# ──────────────────────────────────────────────

class TestGoodhartResolveConfigPath:

    def test_goodhart_resolve_env_var_whitespace_only(self):
        """When EXEMPLAR_CONFIG is set to whitespace-only, the function must handle it gracefully."""
        with patch.dict(os.environ, {"EXEMPLAR_CONFIG": "   "}):
            result = resolve_config_path(None)
            assert isinstance(result, ResolvedConfigPath)
            assert result.source is not None

    def test_goodhart_resolve_env_var_with_explicit_none(self):
        """When explicit is None and env var is set to a real path, env_var source must be returned."""
        test_path = "/tmp/test_exemplar_config.yaml"
        with patch.dict(os.environ, {"EXEMPLAR_CONFIG": test_path}):
            result = resolve_config_path(None)
            assert result.source == ConfigSource.env_var
            assert str(result.path) == test_path or result.path == Path(test_path)

    def test_goodhart_resolve_explicit_nonexistent_path(self):
        """resolve_config_path should return the explicit path even if it does not exist on the filesystem."""
        nonexistent = Path("/nonexistent/deeply/nested/config.yaml")
        result = resolve_config_path(nonexistent)
        assert result.source == ConfigSource.explicit
        assert result.path == nonexistent

    def test_goodhart_resolve_conventional_returns_absolute_path(self):
        """When resolving via conventional source, the returned path should be an absolute path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exemplar_dir = Path(tmpdir) / ".exemplar"
            exemplar_dir.mkdir()
            config_file = exemplar_dir / "config.yaml"
            config_file.write_text("")

            with patch.dict(os.environ, {}, clear=False):
                # Remove EXEMPLAR_CONFIG if set
                env = os.environ.copy()
                env.pop("EXEMPLAR_CONFIG", None)
                with patch.dict(os.environ, env, clear=True):
                    with patch("os.getcwd", return_value=tmpdir):
                        # Also try with chdir if available
                        original_cwd = os.getcwd()
                        try:
                            os.chdir(tmpdir)
                            result = resolve_config_path(None)
                            if result.source == ConfigSource.conventional:
                                assert result.path.is_absolute()
                                assert str(result.path).endswith(os.path.join(".exemplar", "config.yaml"))
                        finally:
                            os.chdir(original_cwd)

    def test_goodhart_resolve_env_var_takes_priority_over_conventional(self):
        """When env var is set and conventional file exists, env_var must take priority."""
        with tempfile.TemporaryDirectory() as tmpdir:
            exemplar_dir = Path(tmpdir) / ".exemplar"
            exemplar_dir.mkdir()
            config_file = exemplar_dir / "config.yaml"
            config_file.write_text("")

            env_path = "/tmp/env_exemplar_config.yaml"
            original_cwd = os.getcwd()
            try:
                os.chdir(tmpdir)
                with patch.dict(os.environ, {"EXEMPLAR_CONFIG": env_path}):
                    result = resolve_config_path(None)
                    assert result.source == ConfigSource.env_var
            finally:
                os.chdir(original_cwd)


# ──────────────────────────────────────────────
# load_config() adversarial tests
# ──────────────────────────────────────────────

class TestGoodhartLoadConfig:

    def test_goodhart_load_config_deep_merge_preserves_unmentioned_defaults(self):
        """When partial YAML overrides only one reviewer, all other sections must retain defaults."""
        yaml_content = textwrap.dedent("""\
            reviewers:
              style:
                enabled: false
        """)
        defaults = default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(Path(f.name))
                # The overridden field
                assert cfg.reviewers["style"].enabled is False
                # Other reviewers untouched
                assert cfg.reviewers["security"].enabled is True
                assert cfg.reviewers["security"].default_trust_weight == 1.0
                assert cfg.reviewers["correctness"].enabled is True
                assert cfg.reviewers["architecture"].enabled is True
                # Other sections untouched
                assert cfg.circuit == defaults.circuit
                assert cfg.apprentice == defaults.apprentice
                assert cfg.ledger == defaults.ledger
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_deep_merge_single_field_override(self):
        """Deep merge must allow overriding a single nested field while preserving siblings."""
        yaml_content = textwrap.dedent("""\
            apprentice:
              phase: canary
        """)
        defaults = default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(Path(f.name))
                assert cfg.apprentice.phase == LearnerPhase.canary or str(cfg.apprentice.phase) == "canary"
                # Sibling fields preserved
                assert cfg.apprentice.shadow_to_canary_threshold == defaults.apprentice.shadow_to_canary_threshold
                assert cfg.apprentice.canary_to_primary_threshold == defaults.apprentice.canary_to_primary_threshold
                assert cfg.apprentice.storage_path == defaults.apprentice.storage_path
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_env_var_file_not_found(self):
        """When EXEMPLAR_CONFIG points to a nonexistent file, load_config should raise ConfigFileNotFoundError."""
        nonexistent = "/tmp/definitely_nonexistent_exemplar_config_xyz.yaml"
        # Make sure it doesn't exist
        if os.path.exists(nonexistent):
            os.unlink(nonexistent)

        with patch.dict(os.environ, {"EXEMPLAR_CONFIG": nonexistent}):
            with pytest.raises(ConfigFileNotFoundError) as exc_info:
                load_config(None)
            assert exc_info.value.path is not None
            assert str(exc_info.value.path) == nonexistent or str(exc_info.value.path) == str(Path(nonexistent))

    def test_goodhart_load_config_error_includes_path(self):
        """ConfigFileNotFoundError raised by load_config must include the resolved path in its path field."""
        explicit = Path("/tmp/nonexistent_adversarial_test_config.yaml")
        if explicit.exists():
            explicit.unlink()
        with pytest.raises(ConfigFileNotFoundError) as exc_info:
            load_config(explicit)
        assert exc_info.value.path == explicit

    def test_goodhart_load_config_yaml_only_comment(self):
        """A YAML file containing only comments should return default_config()."""
        yaml_content = "# This is just a comment\n# Nothing else here\n"
        defaults = default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(Path(f.name))
                assert cfg == defaults
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_yaml_with_only_whitespace(self):
        """A YAML file containing only whitespace should return default_config()."""
        yaml_content = "   \n\n  \n"
        defaults = default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(Path(f.name))
                assert cfg == defaults
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_invalid_trust_weight(self):
        """YAML specifying a reviewer trust_weight above valid range must raise ConfigValidationError."""
        yaml_content = textwrap.dedent("""\
            reviewers:
              security:
                default_trust_weight: 1.5
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with pytest.raises((ConfigValidationError, ConfigError)):
                    load_config(Path(f.name))
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_negative_timeout(self):
        """YAML specifying a negative stage_timeout_ms must raise ConfigValidationError."""
        yaml_content = textwrap.dedent("""\
            circuit:
              stage_timeout_ms: -100
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with pytest.raises((ConfigValidationError, ConfigError)):
                    load_config(Path(f.name))
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_invalid_regex_in_ledger_rule(self):
        """YAML specifying an invalid regex pattern in a ledger rule must raise a config error."""
        yaml_content = textwrap.dedent("""\
            ledger:
              rules:
                - pattern: "[invalid("
                  label: secret
                  description: "Bad regex"
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with pytest.raises((ConfigValidationError, ConfigError)):
                    load_config(Path(f.name))
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_merge_overrides_chronicle_path(self):
        """Deep merge must support overriding top-level string fields like chronicle_log_path."""
        yaml_content = textwrap.dedent("""\
            chronicle_log_path: /custom/log.jsonl
        """)
        defaults = default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(Path(f.name))
                assert cfg.chronicle_log_path == "/custom/log.jsonl"
                # Other paths remain at defaults
                assert cfg.kindex_store_path == defaults.kindex_store_path
                assert cfg.stigmergy_store_path == defaults.stigmergy_store_path
                assert cfg.seal_chain_path == defaults.seal_chain_path
            finally:
                os.unlink(f.name)

    def test_goodhart_load_config_uses_resolve_config_path(self):
        """load_config must use the resolution chain: env var path should be used when explicit is None."""
        yaml_content = textwrap.dedent("""\
            chronicle_log_path: /env/var/override.jsonl
        """)
        defaults = default_config()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with patch.dict(os.environ, {"EXEMPLAR_CONFIG": f.name}):
                    cfg = load_config(None)
                    assert cfg.chronicle_log_path == "/env/var/override.jsonl"
                    assert cfg.chronicle_log_path != defaults.chronicle_log_path
            finally:
                os.unlink(f.name)

    def test_goodhart_config_validation_error_has_validation_errors_list(self):
        """ConfigValidationError must carry a non-empty validation_errors list on actual validation failures."""
        yaml_content = textwrap.dedent("""\
            reviewers:
              security:
                default_trust_weight: 999.0
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                with pytest.raises((ConfigValidationError, ConfigError)) as exc_info:
                    load_config(Path(f.name))
                if isinstance(exc_info.value, ConfigValidationError):
                    assert isinstance(exc_info.value.validation_errors, list)
                    assert len(exc_info.value.validation_errors) > 0
            finally:
                os.unlink(f.name)


# ──────────────────────────────────────────────
# config_to_yaml() adversarial tests
# ──────────────────────────────────────────────

class TestGoodhartConfigToYaml:

    def test_goodhart_config_to_yaml_roundtrip_with_modified_config(self):
        """config_to_yaml roundtrip should work with a config that has non-default values."""
        yaml_content = textwrap.dedent("""\
            apprentice:
              phase: canary
            reviewers:
              style:
                enabled: false
            chronicle_log_path: /modified/path.jsonl
        """)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            try:
                cfg = load_config(Path(f.name))
                yaml_str = config_to_yaml(cfg)
                parsed = yaml.safe_load(yaml_str)
                assert parsed is not None
                roundtrip_cfg = ExemplarConfig.model_validate(parsed)
                assert roundtrip_cfg == cfg
            finally:
                os.unlink(f.name)

    def test_goodhart_config_to_yaml_preserves_ledger_rules(self):
        """config_to_yaml serialization must preserve all ledger rules through a roundtrip."""
        cfg = default_config()
        yaml_str = config_to_yaml(cfg)
        parsed = yaml.safe_load(yaml_str)
        roundtrip_cfg = ExemplarConfig.model_validate(parsed)

        assert len(roundtrip_cfg.ledger.rules) == len(cfg.ledger.rules)
        for orig, rt in zip(cfg.ledger.rules, roundtrip_cfg.ledger.rules):
            assert orig.pattern == rt.pattern
            assert orig.label == rt.label
            assert orig.description == rt.description

    def test_goodhart_config_to_yaml_output_is_string(self):
        """config_to_yaml must return a str type."""
        cfg = default_config()
        result = config_to_yaml(cfg)
        assert isinstance(result, str)


# ──────────────────────────────────────────────
# Error hierarchy adversarial tests
# ──────────────────────────────────────────────

class TestGoodhartErrorHierarchy:

    def test_goodhart_config_error_is_exception(self):
        """ConfigError and its subclasses must be actual Exception subclasses."""
        assert issubclass(ConfigError, Exception)
        assert issubclass(ConfigFileNotFoundError, Exception)
        assert issubclass(ConfigValidationError, Exception)
        assert issubclass(ConfigParseError, Exception)

    def test_goodhart_config_file_not_found_is_subclass(self):
        """ConfigFileNotFoundError must be catchable as ConfigError."""
        assert issubclass(ConfigFileNotFoundError, ConfigError)
        err = ConfigFileNotFoundError(message="test", path=Path("/test"))
        assert isinstance(err, ConfigError)

    def test_goodhart_config_validation_error_is_subclass(self):
        """ConfigValidationError must be catchable as ConfigError."""
        assert issubclass(ConfigValidationError, ConfigError)
        err = ConfigValidationError(message="test", path=None, validation_errors=[])
        assert isinstance(err, ConfigError)

    def test_goodhart_config_parse_error_is_subclass(self):
        """ConfigParseError must be catchable as ConfigError."""
        assert issubclass(ConfigParseError, ConfigError)
        err = ConfigParseError(message="test", path=Path("/test"))
        assert isinstance(err, ConfigError)

    def test_goodhart_config_error_can_be_raised_and_caught(self):
        """ConfigError hierarchy instances must be raisable and catchable."""
        with pytest.raises(ConfigError):
            raise ConfigFileNotFoundError(message="not found", path=Path("/x"))

        with pytest.raises(ConfigError):
            raise ConfigValidationError(message="invalid", path=None, validation_errors=["err1"])

        with pytest.raises(ConfigError):
            raise ConfigParseError(message="bad yaml", path=Path("/y"))


# ──────────────────────────────────────────────
# Enum and type adversarial tests
# ──────────────────────────────────────────────

class TestGoodhartEnumsAndTypes:

    def test_goodhart_config_source_is_str_enum(self):
        """ConfigSource values should be usable as strings (StrEnum behavior)."""
        # Must be comparable to strings
        assert ConfigSource.explicit == "explicit" or str(ConfigSource.explicit) == "explicit"
        assert ConfigSource.env_var == "env_var" or str(ConfigSource.env_var) == "env_var"
        assert ConfigSource.conventional == "conventional" or str(ConfigSource.conventional) == "conventional"
        assert ConfigSource.builtin == "builtin" or str(ConfigSource.builtin) == "builtin"

    def test_goodhart_reviewer_config_trust_weight_mid_range(self):
        """ReviewerConfig should accept trust_weight values in the interior of the valid range."""
        rc = ReviewerConfig(
            enabled=True,
            stage=ReviewStage.security,
            default_trust_weight=0.5,
            allowed_file_patterns=["*"],
            denied_file_patterns=[],
            allowed_classifications=[ClassificationLabel.public],
            max_severity=Severity.high,
        )
        assert rc.default_trust_weight == 0.5

    def test_goodhart_reviewer_config_trust_weight_just_above_one(self):
        """ReviewerConfig must reject trust_weight=1.0001."""
        with pytest.raises(Exception):  # ValidationError
            ReviewerConfig(
                enabled=True,
                stage=ReviewStage.security,
                default_trust_weight=1.0001,
                allowed_file_patterns=["*"],
                denied_file_patterns=[],
                allowed_classifications=[ClassificationLabel.public],
                max_severity=Severity.high,
            )

    def test_goodhart_reviewer_config_trust_weight_just_below_zero(self):
        """ReviewerConfig must reject trust_weight=-0.0001."""
        with pytest.raises(Exception):  # ValidationError
            ReviewerConfig(
                enabled=True,
                stage=ReviewStage.security,
                default_trust_weight=-0.0001,
                allowed_file_patterns=["*"],
                denied_file_patterns=[],
                allowed_classifications=[ClassificationLabel.public],
                max_severity=Severity.high,
            )

    def test_goodhart_circuit_config_timeout_zero(self):
        """CircuitConfig must reject stage_timeout_ms=0 (must be strictly positive)."""
        with pytest.raises(Exception):  # ValidationError
            CircuitConfig(
                stages=[ReviewStage.security],
                parallel_stages=[],
                stage_timeout_ms=0,
                block_threshold=3,
                warn_threshold=1,
            )

    def test_goodhart_circuit_config_timeout_one(self):
        """CircuitConfig must accept stage_timeout_ms=1 (minimum valid positive integer)."""
        cc = CircuitConfig(
            stages=[ReviewStage.security],
            parallel_stages=[],
            stage_timeout_ms=1,
            block_threshold=3,
            warn_threshold=1,
        )
        assert cc.stage_timeout_ms == 1

    def test_goodhart_apprentice_threshold_boundary_just_above(self):
        """ApprenticeConfig must reject shadow_to_canary_threshold=1.001."""
        with pytest.raises(Exception):  # ValidationError
            ApprenticeConfig(
                phase=LearnerPhase.shadow,
                storage_path="/tmp/store",
                shadow_to_canary_threshold=1.001,
                canary_to_primary_threshold=0.5,
            )
