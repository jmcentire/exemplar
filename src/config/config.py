"""
YAML + Pydantic v2 frozen-model configuration loading with fail-fast validation.

PACT: config.config
"""
from __future__ import annotations

import os
import re
from enum import StrEnum
from pathlib import Path
from typing import Optional, Protocol, runtime_checkable

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

OptionalPath = Optional[Path]
StringList = list[str]
LedgerFieldRuleList = list  # forward ref; defined after LedgerFieldRule


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ConfigSource(StrEnum):
    """How the configuration file path was resolved."""
    explicit = "explicit"
    env_var = "env_var"
    conventional = "conventional"
    builtin = "builtin"


class Severity(StrEnum):
    """Severity level of a review finding."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ReviewStage(StrEnum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


class LearnerPhase(StrEnum):
    """Apprentice learning phase progression stage."""
    shadow = "shadow"
    canary = "canary"
    primary = "primary"


class ClassificationLabel(StrEnum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"


# ---------------------------------------------------------------------------
# Error hierarchy
# ---------------------------------------------------------------------------

class ConfigError(Exception):
    """Base configuration error."""

    def __init__(self, *, message: str, path: OptionalPath = None) -> None:
        if not message:
            raise ValueError("ConfigError message must not be empty")
        self.message = message
        self.path = path
        super().__init__(message)


class ConfigFileNotFoundError(ConfigError):
    """Raised when config path does not exist on the filesystem."""

    def __init__(self, *, message: str, path: Path) -> None:
        super().__init__(message=message, path=path)


class ConfigValidationError(ConfigError):
    """Raised when YAML content fails Pydantic model validation."""

    def __init__(
        self,
        *,
        message: str,
        path: OptionalPath = None,
        validation_errors: list,
    ) -> None:
        self.validation_errors = validation_errors
        super().__init__(message=message, path=path)


class ConfigParseError(ConfigError):
    """Raised when the YAML file cannot be parsed."""

    def __init__(self, *, message: str, path: Path) -> None:
        super().__init__(message=message, path=path)


# ---------------------------------------------------------------------------
# Config models (frozen / immutable)
# ---------------------------------------------------------------------------

class LedgerFieldRule(BaseModel):
    """A single Ledger classification rule."""
    model_config = ConfigDict(frozen=True)

    pattern: str
    label: ClassificationLabel
    description: Optional[str] = None

    @field_validator("pattern")
    @classmethod
    def _validate_pattern(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {v!r} ({exc})") from exc
        return v


LedgerFieldRuleList = list[LedgerFieldRule]


class LedgerConfig(BaseModel):
    """Configuration for Ledger field classification."""
    model_config = ConfigDict(frozen=True)

    rules: list[LedgerFieldRule]
    default_label: ClassificationLabel


class ReviewerConfig(BaseModel):
    """Per-reviewer configuration."""
    model_config = ConfigDict(frozen=True)

    enabled: bool
    stage: ReviewStage
    default_trust_weight: float = Field(ge=0.0, le=1.0)
    allowed_file_patterns: list[str]
    denied_file_patterns: list[str]
    allowed_classifications: list[ClassificationLabel]
    max_severity: Severity


class ReviewerConfigMap(BaseModel):
    """Map of reviewer name to ReviewerConfig."""
    model_config = ConfigDict(frozen=True)

    security: Optional[ReviewerConfig] = None
    correctness: Optional[ReviewerConfig] = None
    style: Optional[ReviewerConfig] = None
    architecture: Optional[ReviewerConfig] = None


class CircuitConfig(BaseModel):
    """Configuration for Baton circuit routing."""
    model_config = ConfigDict(frozen=True)

    stages: list[str]
    parallel_stages: list[list[str]]
    stage_timeout_ms: int = Field(gt=0)
    block_threshold: int
    warn_threshold: int


class ApprenticeConfig(BaseModel):
    """Configuration for the Apprentice learning module."""
    model_config = ConfigDict(frozen=True)

    phase: LearnerPhase
    storage_path: str
    shadow_to_canary_threshold: float = Field(ge=0.0, le=1.0)
    canary_to_primary_threshold: float = Field(ge=0.0, le=1.0)


class ExemplarConfig(BaseModel):
    """Top-level configuration for the Exemplar code review service."""
    model_config = ConfigDict(frozen=True)

    circuit: CircuitConfig
    reviewers: dict[str, ReviewerConfig]
    ledger: LedgerConfig
    apprentice: ApprenticeConfig
    chronicle_log_path: str
    kindex_store_path: str
    stigmergy_store_path: str
    seal_chain_path: str


class ResolvedConfigPath(BaseModel):
    """Result of config path resolution."""
    model_config = ConfigDict(frozen=True)

    path: OptionalPath
    source: ConfigSource


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

@runtime_checkable
class ConfigProvider(Protocol):
    """Protocol defining the config loading interface."""

    def load_config(self, path: OptionalPath = None) -> ExemplarConfig: ...


# ---------------------------------------------------------------------------
# Default configuration factory
# ---------------------------------------------------------------------------

def default_config() -> ExemplarConfig:
    """
    Returns a complete, valid ExemplarConfig with all default values.

    PACT: config.default_config
    """
    return ExemplarConfig(
        circuit=CircuitConfig(
            stages=[
                "intake",
                "security",
                "correctness",
                "style",
                "architecture",
                "assess",
                "report",
            ],
            parallel_stages=[
                ["security", "correctness"],
                ["style", "architecture"],
            ],
            stage_timeout_ms=30000,
            block_threshold=3,
            warn_threshold=1,
        ),
        reviewers={
            "security": ReviewerConfig(
                enabled=True,
                stage=ReviewStage.security,
                default_trust_weight=1.0,
                allowed_file_patterns=["**/*"],
                denied_file_patterns=[],
                allowed_classifications=[
                    ClassificationLabel.secret,
                    ClassificationLabel.pii,
                    ClassificationLabel.internal_api,
                    ClassificationLabel.public,
                ],
                max_severity=Severity.critical,
            ),
            "correctness": ReviewerConfig(
                enabled=True,
                stage=ReviewStage.correctness,
                default_trust_weight=1.0,
                allowed_file_patterns=["**/*"],
                denied_file_patterns=[],
                allowed_classifications=[
                    ClassificationLabel.public,
                    ClassificationLabel.internal_api,
                ],
                max_severity=Severity.high,
            ),
            "style": ReviewerConfig(
                enabled=True,
                stage=ReviewStage.style,
                default_trust_weight=1.0,
                allowed_file_patterns=["**/*"],
                denied_file_patterns=[],
                allowed_classifications=[ClassificationLabel.public],
                max_severity=Severity.medium,
            ),
            "architecture": ReviewerConfig(
                enabled=True,
                stage=ReviewStage.architecture,
                default_trust_weight=1.0,
                allowed_file_patterns=["**/*"],
                denied_file_patterns=[],
                allowed_classifications=[
                    ClassificationLabel.public,
                    ClassificationLabel.internal_api,
                ],
                max_severity=Severity.high,
            ),
        },
        ledger=LedgerConfig(
            rules=[
                LedgerFieldRule(
                    pattern=r"(?i)(password|secret|api[_-]?key|token|credential)\s*[=:]",
                    label=ClassificationLabel.secret,
                    description="Detects hardcoded secrets and credentials",
                ),
                LedgerFieldRule(
                    pattern=r"(?i)(aws_secret|private[_-]?key|BEGIN\s+(RSA|DSA|EC)\s+PRIVATE\s+KEY)",
                    label=ClassificationLabel.secret,
                    description="Detects private keys and AWS secrets",
                ),
                LedgerFieldRule(
                    pattern=r"(?i)(email|phone|ssn|social.security|date.of.birth|address)\s*[=:]",
                    label=ClassificationLabel.pii,
                    description="Detects personally identifiable information fields",
                ),
                LedgerFieldRule(
                    pattern=r"(?i)(first.name|last.name|full.name|birth.date)\s*[=:]",
                    label=ClassificationLabel.pii,
                    description="Detects PII name and date fields",
                ),
                LedgerFieldRule(
                    pattern=r"(?i)(internal[_-]?api|private[_-]?endpoint|localhost:\d+)",
                    label=ClassificationLabel.internal_api,
                    description="Detects internal API references",
                ),
            ],
            default_label=ClassificationLabel.public,
        ),
        apprentice=ApprenticeConfig(
            phase=LearnerPhase.shadow,
            storage_path=".exemplar/learner",
            shadow_to_canary_threshold=0.8,
            canary_to_primary_threshold=0.95,
        ),
        chronicle_log_path=".exemplar/chronicle.jsonl",
        kindex_store_path=".exemplar/kindex.json",
        stigmergy_store_path=".exemplar/stigmergy.json",
        seal_chain_path=".exemplar/seal_chain.json",
    )


# ---------------------------------------------------------------------------
# Config path resolution
# ---------------------------------------------------------------------------

def resolve_config_path(explicit: OptionalPath = None) -> ResolvedConfigPath:
    """
    Resolves config file path using cascading resolution.

    PACT: config.resolve_config_path
    """
    # 1. Explicit path
    if explicit is not None:
        return ResolvedConfigPath(path=explicit, source=ConfigSource.explicit)

    # 2. Environment variable
    env_val = os.environ.get("EXEMPLAR_CONFIG", "")
    if env_val:
        return ResolvedConfigPath(path=Path(env_val), source=ConfigSource.env_var)

    # 3. Conventional path in CWD
    conventional = Path.cwd() / ".exemplar" / "config.yaml"
    if conventional.exists():
        return ResolvedConfigPath(path=conventional, source=ConfigSource.conventional)

    # 4. Builtin defaults
    return ResolvedConfigPath(path=None, source=ConfigSource.builtin)


# ---------------------------------------------------------------------------
# Deep merge helper
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override dict onto base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

def load_config(path: OptionalPath = None) -> ExemplarConfig:
    """
    Primary public API for configuration loading.

    PACT: config.load_config
    """
    resolved = resolve_config_path(path)

    # Builtin: no file
    if resolved.source == ConfigSource.builtin:
        return default_config()

    config_path = resolved.path
    assert config_path is not None

    # Check file exists (only for explicit/env_var; conventional already checked)
    if not config_path.exists():
        raise ConfigFileNotFoundError(
            message=f"Configuration file not found: {config_path}",
            path=config_path,
        )

    # Read file
    try:
        raw = config_path.read_text(encoding="utf-8")
    except PermissionError:
        raise ConfigError(
            message=f"Permission denied reading config file: {config_path}",
            path=config_path,
        )

    # Parse YAML
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise ConfigParseError(
            message=f"Failed to parse YAML config at {config_path}: {e}",
            path=config_path,
        )

    # Empty/null document -> defaults
    if parsed is None:
        return default_config()

    if not isinstance(parsed, dict):
        raise ConfigValidationError(
            message=f"Configuration validation failed for {config_path}: expected a mapping, got {type(parsed).__name__}",
            path=config_path,
            validation_errors=[{"loc": (), "msg": "expected a mapping", "type": "type_error"}],
        )

    # Deep-merge onto defaults
    defaults_dict = default_config().model_dump(mode="json")
    merged = _deep_merge(defaults_dict, parsed)

    # Validate
    try:
        return ExemplarConfig.model_validate(merged)
    except Exception as e:
        from pydantic import ValidationError

        if isinstance(e, ValidationError):
            raise ConfigValidationError(
                message=f"Configuration validation failed for {config_path}: {e}",
                path=config_path,
                validation_errors=e.errors(),
            )
        raise ConfigError(
            message=f"Configuration validation failed for {config_path}: {e}",
            path=config_path,
        )


# ---------------------------------------------------------------------------
# Config serialization
# ---------------------------------------------------------------------------

def config_to_yaml(config: ExemplarConfig) -> str:
    """
    Serializes an ExemplarConfig to a YAML string.

    PACT: config.config_to_yaml
    """
    data = config.model_dump(mode="json")
    return yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)


# ---------------------------------------------------------------------------
# Emission-compliant class wrapper
# ---------------------------------------------------------------------------

PACT_COMPONENT = "config"


def _emit(handler, event: str, pact_key: str, **kwargs) -> None:
    if handler is None:
        return
    try:
        handler({"event": event, "pact_key": pact_key, **kwargs})
    except Exception:
        pass


class Config:
    """Class wrapper around config functions for PACT emission compliance."""

    def __init__(self, event_handler=None) -> None:
        self._handler = event_handler

    def default_config(self) -> ExemplarConfig:
        pact_key = f"PACT:{PACT_COMPONENT}:default_config"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = default_config()
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def resolve_config_path(self, explicit: OptionalPath = None) -> ResolvedConfigPath:
        pact_key = f"PACT:{PACT_COMPONENT}:resolve_config_path"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = resolve_config_path(explicit)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def load_config(self, path: OptionalPath = None) -> ExemplarConfig:
        pact_key = f"PACT:{PACT_COMPONENT}:load_config"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            result = load_config(path)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise

    def config_to_yaml(self, config: ExemplarConfig = None) -> str:
        pact_key = f"PACT:{PACT_COMPONENT}:config_to_yaml"
        _emit(self._handler, "invoked", pact_key, input_classification=[])
        try:
            if config is None:
                raise TypeError("config is required")
            result = config_to_yaml(config)
            _emit(self._handler, "completed", pact_key)
            return result
        except Exception as e:
            _emit(self._handler, "error", pact_key, error=str(e))
            raise
