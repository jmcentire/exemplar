# === Configuration System (config) v2 ===
#  Dependencies: schemas
# YAML + Pydantic v2 frozen-model configuration loading with fail-fast validation. Defines the complete configuration hierarchy: ExemplarConfig (top-level), CircuitConfig (stage ordering, parallelism, thresholds), ReviewerConfig (per-reviewer enablement, trust weight, scope patterns), LedgerConfig (field classification rules for secrets/PII/internal APIs via LedgerFieldRule), and ApprenticeConfig (shadow/canary/primary mode, storage path). Provides a default_config() factory that returns a fully valid out-of-the-box configuration. Supports cascading path resolution: explicit flag > EXEMPLAR_CONFIG env var > .exemplar/config.yaml in CWD > built-in defaults. Deep-merges partial YAML onto defaults and validates via Pydantic. All errors wrapped in a ConfigError hierarchy with clear messages. No Chronicler dependency to avoid circular imports; callers handle event emission.

# Module invariants:
#   - All configuration models are frozen (immutable) after construction
#   - default_config() always returns a valid ExemplarConfig that passes all validators
#   - load_config() with no arguments and no config file present returns default_config()
#   - Config path resolution order is always: explicit > env_var > conventional > builtin
#   - parallel_stages is always a subset of stages in any valid CircuitConfig
#   - min_threshold <= max_threshold in any valid CircuitConfig
#   - LedgerFieldRule.pattern is always a compilable regex
#   - ReviewerConfig.scope_patterns contains only valid glob patterns
#   - CircuitConfig.excluded_file_patterns contains only valid glob patterns
#   - An empty YAML file (null document) produces default_config()
#   - Every public function carries a PACT key annotation for Sentinel attribution
#   - No Chronicler events are emitted from this module; callers handle event emission

class ConfigSource(Enum):
    """StrEnum indicating how the configuration file path was resolved. Used to report provenance of the active configuration."""
    explicit = "explicit"
    env_var = "env_var"
    conventional = "conventional"
    builtin = "builtin"

class ConfigError:
    """Base configuration error. All config-related exceptions inherit from this. Carries a human-readable message and optional resolved path for diagnostics."""
    message: str                             # required, length(min=1), Human-readable error description including resolved path context
    path: OptionalPath = None                # optional, The resolved config file path that caused the error, or None if no path was resolved

class ConfigFileNotFoundError:
    """Raised when an explicitly specified or env-var-resolved config path does not exist on the filesystem. Subclass of ConfigError."""
    message: str                             # required, length(min=1), Error message including the missing file path
    path: Path                               # required, The filesystem path that was not found

class ConfigValidationError:
    """Raised when YAML content is syntactically valid but fails Pydantic model validation (type errors, constraint violations, cross-field invariant failures). Wraps the underlying Pydantic ValidationError details. Subclass of ConfigError."""
    message: str                             # required, length(min=1), Summary of validation failures
    path: OptionalPath = None                # optional, The config file path that produced invalid content
    validation_errors: list                  # required, List of Pydantic validation error dicts, each with loc, msg, and type fields

class ConfigParseError:
    """Raised when the YAML file cannot be parsed (syntax errors, encoding issues). Subclass of ConfigError."""
    message: str                             # required, length(min=1), YAML parse error details including line/column if available
    path: Path                               # required, The config file path that could not be parsed

Path = primitive  # pathlib.Path representing a filesystem path

OptionalPath = Path | None

class LedgerFieldRule:
    """A single Ledger classification rule: a regex pattern mapped to a classification label."""
    pattern: str                             # required, Regex pattern to match against diff hunk content.
    label: ClassificationLabel               # required, Classification label to apply when pattern matches.
    description: str = None                  # optional, Human-readable description of what this rule detects.

class LedgerConfig:
    """Configuration for Ledger field classification: rules for detecting secrets, PII, and internal APIs."""
    rules: list[LedgerFieldRule]             # required, Ordered list of classification rules. First match wins per label category.
    default_label: ClassificationLabel       # required, Default label when no rule matches.

LedgerFieldRuleList = list[LedgerFieldRule]
# Ordered list of LedgerFieldRule instances

class ReviewerConfig:
    """Per-reviewer configuration: enablement, default trust, and policy scope."""
    enabled: bool                            # required, Whether this reviewer is active.
    stage: ReviewStage                       # required, The stage this reviewer operates in.
    default_trust_weight: float              # required, range(0.0 <= value <= 1.0), Initial trust weight for Arbiter scoring.
    allowed_file_patterns: list[str]         # required, Glob patterns for files this reviewer may access.
    denied_file_patterns: list[str]          # required, Glob patterns for files this reviewer must not access.
    allowed_classifications: list[ClassificationLabel] # required, Classification labels this reviewer may see.
    max_severity: Severity                   # required, Maximum severity this reviewer may emit.

class ReviewerConfigMap:
    """Map of reviewer name to ReviewerConfig. Keys are canonical reviewer identifiers."""
    security: ReviewerConfig = None          # optional, Configuration for the security reviewer (OWASP, secret detection)
    correctness: ReviewerConfig = None       # optional, Configuration for the correctness reviewer (logic errors, null checks)
    style: ReviewerConfig = None             # optional, Configuration for the style reviewer (convention violations)
    architecture: ReviewerConfig = None      # optional, Configuration for the architecture reviewer (coupling, layer violations)

class CircuitConfig:
    """Configuration for Baton circuit routing: stage ordering, parallelism, and timeouts."""
    stages: list[ReviewStage]                # required, Ordered list of review stages to execute.
    parallel_stages: list[list[ReviewStage]] # required, Groups of stages that can run in parallel. Each inner list runs concurrently.
    stage_timeout_ms: int                    # required, range(value > 0), Default timeout per stage in milliseconds.
    block_threshold: int                     # required, Minimum number of critical/high findings to trigger a block decision.
    warn_threshold: int                      # required, Minimum number of medium findings to trigger a warn decision.

class ApprenticeConfig:
    """Configuration for the Apprentice learning module: phase, thresholds, and storage."""
    phase: LearnerPhase                      # required, Current learning phase.
    storage_path: str                        # required, Directory path for learning state files.
    shadow_to_canary_threshold: float        # required, range(0.0 <= value <= 1.0), Accuracy threshold to progress from shadow to canary.
    canary_to_primary_threshold: float       # required, range(0.0 <= value <= 1.0), Accuracy threshold to progress from canary to primary.

class ExemplarConfig:
    """Top-level configuration for the Exemplar code review service."""
    circuit: CircuitConfig                   # required, Circuit routing configuration.
    reviewers: dict[str, ReviewerConfig]     # required, Per-reviewer configuration keyed by reviewer_id.
    ledger: LedgerConfig                     # required, Field classification rules.
    apprentice: ApprenticeConfig             # required, Learning module configuration.
    chronicle_log_path: str                  # required, File path for Chronicler JSON-lines log.
    kindex_store_path: str                   # required, File path for Kindex persistent store.
    stigmergy_store_path: str                # required, File path for Stigmergy pattern store.
    seal_chain_path: str                     # required, File path for Tessera seal chain state.

StringList = list[str]
# List of strings, used for stage names, patterns, etc.

class ResolvedConfigPath:
    """Result of config path resolution: the resolved path (or None for builtin) and the source that provided it."""
    path: OptionalPath                       # required, Resolved filesystem path, or None if using built-in defaults
    source: ConfigSource                     # required, How the path was resolved

class ConfigProvider:
    """Protocol (runtime_checkable) defining the config loading interface. Implementations must provide load_config(). Used for dependency injection and testability."""
    load_config: str                         # required, Protocol method signature: (path: Path | None = None) -> ExemplarConfig

class Severity(Enum):
    """Severity level of a review finding, ordered from most to least critical."""
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"

class ReviewStage(Enum):
    """Named stage in the review circuit pipeline."""
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"

class LearnerPhase(Enum):
    """Apprentice learning phase progression stage."""
    shadow = "shadow"
    canary = "canary"
    primary = "primary"

class ClassificationLabel(Enum):
    """Ledger data classification label for diff content."""
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"

def default_config() -> ExemplarConfig:
    """
    Returns a complete, valid ExemplarConfig with all default values. All four reviewers enabled with trust_weight=1.0, standard stage ordering (intake, security, correctness, style, architecture, assess, report), common secret/PII detection patterns in Ledger, and shadow-mode Apprentice. This is the canonical baseline onto which partial YAML overrides are deep-merged.

    Postconditions:
      - Returned config passes all ExemplarConfig validators
      - All four reviewers (security, correctness, style, architecture) are enabled
      - CircuitConfig.stages contains at least: intake, security, correctness, style, architecture, assess, report
      - CircuitConfig.parallel_stages is a subset of CircuitConfig.stages
      - CircuitConfig.min_threshold <= CircuitConfig.max_threshold
      - LedgerConfig contains at least one SECRET and one PII detection rule
      - ApprenticeConfig.mode is 'shadow'
      - All LedgerFieldRule patterns compile as valid regex

    Side effects: none
    Idempotent: yes
    """
    ...

def resolve_config_path(
    explicit: OptionalPath = None,
) -> ResolvedConfigPath:
    """
    Resolves the configuration file path using a cascading resolution chain: (1) explicit path parameter if provided, (2) EXEMPLAR_CONFIG environment variable if set, (3) .exemplar/config.yaml in the current working directory if it exists, (4) None indicating built-in defaults should be used. Returns both the resolved path and the source that provided it. Does NOT validate that the file exists for explicit/env_var sources — that is load_config's responsibility.

    Postconditions:
      - If explicit is not None, returns (explicit, ConfigSource.explicit)
      - If explicit is None and EXEMPLAR_CONFIG env var is set and non-empty, returns (Path(env_var_value), ConfigSource.env_var)
      - If no explicit or env var, and .exemplar/config.yaml exists in CWD, returns (cwd/.exemplar/config.yaml, ConfigSource.conventional)
      - If no path found by any method, returns (None, ConfigSource.builtin)
      - source field is never None

    Side effects: none
    Idempotent: yes
    """
    ...

def load_config(
    path: OptionalPath = None,
) -> ExemplarConfig:
    """
    Primary public API for configuration loading. Resolves config path via resolve_config_path, reads and parses the YAML file if one exists, deep-merges parsed content onto default_config() values, and validates the result via ExemplarConfig.model_validate(). Returns default_config() if no config file is found (builtin source). An empty YAML file (null document) also returns default_config(). All errors are wrapped in the ConfigError hierarchy with clear messages including the resolved path.

    Postconditions:
      - Returned ExemplarConfig passes all model validators and field constraints
      - If no config file exists and no explicit path given, result equals default_config()
      - All LedgerFieldRule patterns in returned config compile as valid regex
      - CircuitConfig cross-field invariants hold (parallel_stages ⊆ stages, threshold ordering)
      - An empty YAML document returns default_config()

    Errors:
      - file_not_found (ConfigFileNotFoundError): Resolved path (from explicit or env_var source) does not exist on filesystem
          message: Configuration file not found: {resolved_path}
          path: resolved_path
      - yaml_parse_error (ConfigParseError): YAML file exists but contains invalid YAML syntax
          message: Failed to parse YAML config at {resolved_path}: {yaml_error}
          path: resolved_path
      - validation_error (ConfigValidationError): Parsed YAML content fails Pydantic model validation (type errors, constraint violations, cross-field invariant failures)
          message: Configuration validation failed for {resolved_path}: {validation_summary}
          path: resolved_path
          validation_errors: pydantic_error_list
      - permission_denied (ConfigError): Config file exists but is not readable due to filesystem permissions
          message: Permission denied reading config file: {resolved_path}
          path: resolved_path

    Side effects: none
    Idempotent: yes
    """
    ...

def config_to_yaml(
    config: ExemplarConfig,
) -> str:
    """
    Serializes an ExemplarConfig back to a YAML string. Useful for generating config templates, dumping effective configuration for debugging, and round-trip testing. Uses Pydantic model_dump() with mode='json' for serialization compatibility, then yaml.dump().

    Preconditions:
      - config is a valid ExemplarConfig instance

    Postconditions:
      - Returned string is valid YAML that can be parsed by yaml.safe_load
      - yaml.safe_load(result) fed back through ExemplarConfig.model_validate produces an equivalent config

    Side effects: none
    Idempotent: yes
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['ConfigSource', 'ConfigError', 'ConfigFileNotFoundError', 'ConfigValidationError', 'ConfigParseError', 'OptionalPath', 'LedgerFieldRule', 'LedgerConfig', 'LedgerFieldRuleList', 'ReviewerConfig', 'ReviewerConfigMap', 'CircuitConfig', 'ApprenticeConfig', 'ExemplarConfig', 'StringList', 'ResolvedConfigPath', 'ConfigProvider', 'Severity', 'ReviewStage', 'LearnerPhase', 'ClassificationLabel', 'default_config', 'resolve_config_path', 'load_config', 'config_to_yaml']
