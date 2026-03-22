# === CLI Entry Point (cli) v1 ===
#  Dependencies: intake, circuit, assessor, reporter, chronicle, learner, schemas, config
# Argparse-based CLI providing four subcommands (review, trust, history, adopt) as a thin transport layer over shared core modules. Manages async event loop lifecycle, maps pipeline results to process exit codes (0=pass, 1=warn, 2=block, 3=error), emits Chronicler events at stage boundaries, and embeds PACT keys for Sentinel attribution. All business logic is delegated to intake, circuit, assessor, reporter, chronicle, and learner modules — the CLI never inspects findings, computes scores, or formats reports directly.

# Module invariants:
#   - CLI is a thin transport layer: it never inspects findings, computes scores, or formats report content — all logic is delegated to dependency modules
#   - Exit codes are deterministic: given the same pipeline result, the same exit code is always returned
#   - Chronicler event emission is fire-and-forget: failure to emit review.started never affects the pipeline result or exit code
#   - stdout carries only subcommand output (report, trust table, history results, adopt findings); stderr carries only diagnostics and error messages
#   - No exception escapes main(): all exceptions are caught at the boundary and mapped to CliExitCode.ERROR (3)
#   - PACT key namespace is always 'EXEMPLAR.CLI' with function-specific suffixes
#   - Config resolution order: --config flag > XDG_CONFIG_HOME/exemplar/.exemplar.yml > cwd/.exemplar.yml
#   - All data models are frozen (Pydantic frozen=True); CliArgs and CliResult are immutable after construction
#   - The --debug flag controls stderr verbosity but never changes stdout content or exit codes

class CliExitCode(Enum):
    """CLI process exit codes mapping to review outcomes."""
    0 = "0"
    1 = "1"
    2 = "2"
    3 = "3"

class SubcommandName(Enum):
    """Valid CLI subcommand identifiers used as dispatch keys."""
    review = "review"
    trust = "trust"
    history = "history"
    adopt = "adopt"

class CliArgs:
    """Parsed and validated CLI arguments after argparse processing. Frozen Pydantic model wrapping argparse.Namespace fields into typed structure."""
    subcommand: SubcommandName               # required, Which subcommand was invoked
    diff_file: FilePath = None               # optional, Path to diff file (review subcommand only)
    config_path: FilePath = None             # optional, Override path to YAML config file. Defaults to XDG config or cwd/.exemplar.yml
    output_format: OutputFormat = json       # optional, Report output format. Only used by review subcommand.
    query: str = None                        # optional, Search term for history subcommand
    debug: bool = false                      # optional, Enable verbose diagnostic output to stderr

FilePath = primitive  # A validated filesystem path string. Must be non-empty when required and contain only valid path characters.

class OutputFormat(Enum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"

class CliResult:
    """Internal result from a subcommand handler before exit code mapping. Carries both the output text and the semantic exit code."""
    exit_code: CliExitCode                   # required, Semantic exit code to return from process
    stdout_output: str                       # required, Formatted output to write to stdout. Empty string means no output.
    stderr_output: str = None                # optional, Diagnostic or error messages to write to stderr. Empty string means no diagnostics.

class SubcommandDispatchTable:
    """Maps SubcommandName to its async handler function. Used by main() for dispatch. The handler signature is async (CliArgs) -> CliResult."""
    handlers: dict                           # required, Mapping of SubcommandName -> async callable(CliArgs) -> CliResult

class PactKey:
    """PACT attribution key embedded in public methods for Sentinel tracing."""
    namespace: str                           # required, regex(^EXEMPLAR\.CLI$), Module-level PACT namespace, always 'EXEMPLAR.CLI'
    function_key: str                        # required, regex(^EXEMPLAR\.CLI\.[a-z_]+$), Per-function PACT key, e.g. 'EXEMPLAR.CLI.handle_review'

def build_parser() -> any:
    """
    Constructs the argparse.ArgumentParser with all four subcommands (review, trust, history, adopt) and their respective arguments. Pure function with no side effects. The review subcommand accepts a positional diff-file arg plus --config and --format options. The trust subcommand has no additional args. The history subcommand accepts an optional --query flag. The adopt subcommand has no additional args. A global --debug flag is added to the parent parser.

    Postconditions:
      - Returned parser has exactly 4 subcommands: review, trust, history, adopt
      - review subcommand has positional 'diff_file' argument
      - review subcommand has --config optional argument
      - review subcommand has --format optional argument with choices ['json', 'md', 'github']
      - history subcommand has --query optional argument
      - Parent parser has --debug flag defaulting to False
      - Parser prog name is 'exemplar'

    Side effects: none
    Idempotent: yes
    """
    ...

def parse_and_validate_args(
    parser: any,
    argv: list,
) -> CliArgs:
    """
    Parses raw argv using the argparse parser and converts the resulting Namespace into a validated CliArgs struct. Validates that required arguments for each subcommand are present (e.g., diff_file for review). Returns structured, typed args or raises on invalid input.

    Preconditions:
      - parser is a fully constructed ArgumentParser from build_parser()

    Postconditions:
      - Returned CliArgs has a valid subcommand
      - If subcommand is 'review', diff_file is non-empty
      - output_format is a valid OutputFormat variant

    Errors:
      - no_subcommand (SystemExit): No subcommand provided in argv
          exit_code: 3
          detail: argparse prints usage to stderr and raises SystemExit(2) which is caught and remapped to exit code 3
      - unknown_argument (SystemExit): Unrecognized argument passed
          exit_code: 3
      - missing_diff_file (SystemExit): review subcommand invoked without diff-file positional argument
          exit_code: 3

    Side effects: none
    Idempotent: yes
    """
    ...

async def handle_review(
    args: CliArgs,
) -> CliResult:
    """
    Async handler for the 'review' subcommand. Loads config, emits review.started Chronicler event (fire-and-forget), reads diff file, invokes intake.parse_diff → circuit.route_stages → assessor.assess → reporter.format_report pipeline, maps PipelineResult to CliResult with appropriate exit code. All output goes to stdout_output; errors and progress to stderr_output. PACT key: EXEMPLAR.CLI.handle_review.

    Preconditions:
      - args.subcommand == SubcommandName.review
      - args.diff_file is non-empty and points to a readable file

    Postconditions:
      - A review.started ChroniclerEvent was emitted (fire-and-forget, failure does not affect result)
      - exit_code is PASS(0), WARN(1), or BLOCK(2) on successful pipeline completion
      - exit_code is ERROR(3) if any pipeline stage raised an unrecoverable exception
      - stdout_output contains the formatted report in the requested OutputFormat
      - stderr_output contains diagnostic info if args.debug is true

    Errors:
      - diff_file_not_found (FileNotFoundError): The diff file path does not exist or is not readable
          exit_code: 3
          detail: Diff file not found: {path}
      - diff_file_read_error (IOError): The diff file exists but cannot be read (permissions, encoding)
          exit_code: 3
          detail: Failed to read diff file: {path}
      - config_load_error (ValueError): Config file specified via --config does not exist or is invalid YAML/schema
          exit_code: 3
          detail: Invalid or missing config: {path}
      - pipeline_stage_failure (RuntimeError): Any pipeline stage (intake, circuit, assessor, reporter) raises an unhandled exception
          exit_code: 3
          detail: Pipeline failed at stage: {stage_name}
      - diff_file_empty (ValueError): Diff file exists and is readable but contains zero bytes
          exit_code: 3
          detail: Diff file is empty: {path}

    Side effects: none
    Idempotent: no
    """
    ...

async def handle_trust(
    args: CliArgs,
) -> CliResult:
    """
    Async handler for the 'trust' subcommand. Loads config, retrieves current reviewer trust scores from assessor.get_trust_scores(), formats them as a human-readable table to stdout. Always returns exit code PASS(0) on success. PACT key: EXEMPLAR.CLI.handle_trust.

    Preconditions:
      - args.subcommand == SubcommandName.trust

    Postconditions:
      - exit_code is PASS(0) on success
      - exit_code is ERROR(3) on failure
      - stdout_output contains formatted trust score table with one row per reviewer

    Errors:
      - trust_data_unavailable (RuntimeError): Trust score storage is missing or corrupt
          exit_code: 3
          detail: Failed to load trust scores
      - config_load_error (ValueError): Config file cannot be loaded
          exit_code: 3
          detail: Invalid or missing config: {path}

    Side effects: none
    Idempotent: yes
    """
    ...

async def handle_history(
    args: CliArgs,
) -> CliResult:
    """
    Async handler for the 'history' subcommand. Queries past review records from Kindex store via learner.query_history(). If --query is provided, filters results by term; otherwise returns recent reviews. Formats results to stdout. PACT key: EXEMPLAR.CLI.handle_history.

    Preconditions:
      - args.subcommand == SubcommandName.history

    Postconditions:
      - exit_code is PASS(0) on success, even if zero results returned
      - exit_code is ERROR(3) on failure
      - stdout_output contains formatted history results (may be empty set message)

    Errors:
      - kindex_unavailable (RuntimeError): Kindex store is unreachable or corrupt
          exit_code: 3
          detail: Failed to query review history from Kindex
      - config_load_error (ValueError): Config file cannot be loaded
          exit_code: 3
          detail: Invalid or missing config: {path}

    Side effects: none
    Idempotent: yes
    """
    ...

async def handle_adopt(
    args: CliArgs,
) -> CliResult:
    """
    Async handler for the 'adopt' subcommand (Cartographer). Scans cwd for linter configuration files (.eslintrc, .pylintrc, .flake8, pyproject.toml [tool.ruff], etc.) via learner.scan_linter_configs(). Reports findings with migration suggestions showing how existing rules map to Exemplar reviewers. PACT key: EXEMPLAR.CLI.handle_adopt.

    Preconditions:
      - args.subcommand == SubcommandName.adopt

    Postconditions:
      - exit_code is PASS(0) on success, even if no linter configs found
      - exit_code is ERROR(3) on failure
      - stdout_output contains scan results with per-file findings and migration suggestions

    Errors:
      - cwd_unreadable (PermissionError): Current working directory is not readable or does not exist
          exit_code: 3
          detail: Cannot read current working directory
      - scan_error (RuntimeError): Unexpected error during filesystem scan of linter configs
          exit_code: 3
          detail: Failed during linter config scan

    Side effects: none
    Idempotent: yes
    """
    ...

def build_dispatch_table() -> SubcommandDispatchTable:
    """
    Constructs the SubcommandDispatchTable mapping each SubcommandName to its async handler function. Pure function, returns a static mapping. Used by main() to route parsed subcommands to handlers.

    Postconditions:
      - Returned table has exactly 4 entries, one per SubcommandName variant
      - Each handler value is an async callable accepting CliArgs and returning CliResult

    Side effects: none
    Idempotent: yes
    """
    ...

def map_decision_to_exit_code(
    decision: str,             # custom(value in ('pass', 'warn', 'block', 'error'))
) -> CliExitCode:
    """
    Pure mapping function from ReviewDecision enum to CliExitCode. pass→PASS(0), warn→WARN(1), block→BLOCK(2), error→ERROR(3). Used by handle_review to convert pipeline output to process exit code.

    Preconditions:
      - decision is a valid ReviewDecision variant

    Postconditions:
      - Returned CliExitCode numeric value matches: pass→0, warn→1, block→2, error→3

    Errors:
      - invalid_decision (ValueError): decision string is not a recognized ReviewDecision variant
          detail: Unknown ReviewDecision: {decision}

    Side effects: none
    Idempotent: yes
    """
    ...

def main(
    argv: list = None,
) -> int:
    """
    Synchronous entry point for the CLI. Builds parser, parses argv (defaults to sys.argv[1:] if None), constructs dispatch table, runs the appropriate async handler via asyncio.run(), writes stdout_output to sys.stdout and stderr_output to sys.stderr, and returns the integer exit code. Catches all exceptions at the boundary and maps them to exit code 3 (ERROR). Only calls sys.exit() when invoked as __main__ script entry point — the function itself returns int for testability. PACT key: EXEMPLAR.CLI.main.

    Postconditions:
      - Return value is 0, 1, 2, or 3
      - On success, formatted output was written to stdout
      - On error, diagnostic message was written to stderr
      - No exception escapes this function — all are caught and mapped to exit code 3

    Errors:
      - unhandled_exception (Exception): Any exception not caught by subcommand handlers propagates to main
          exit_code: 3
          detail: Caught at boundary, logged to stderr, returns 3
      - keyboard_interrupt (KeyboardInterrupt): User sends SIGINT/Ctrl+C during execution
          exit_code: 3
          detail: Interrupted by user

    Side effects: Writes to sys.stdout, Writes to sys.stderr, Calls asyncio.run() to execute async handlers, May call sys.exit() when invoked as __main__
    Idempotent: no
    """
    ...

# ── REQUIRED EXPORTS ──────────────────────────────────
# Your implementation module MUST export ALL of these names
# with EXACTLY these spellings. Tests import them by name.
# __all__ = ['CliExitCode', 'SubcommandName', 'CliArgs', 'OutputFormat', 'CliResult', 'SubcommandDispatchTable', 'PactKey', 'build_parser', 'parse_and_validate_args', 'SystemExit', 'handle_review', 'handle_trust', 'handle_history', 'handle_adopt', 'build_dispatch_table', 'map_decision_to_exit_code', 'main', 'KeyboardInterrupt']
