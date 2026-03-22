"""CLI Entry Point for Exemplar.

Argparse-based CLI providing four subcommands (review, trust, history, adopt)
as a thin transport layer over shared core modules. Manages async event loop
lifecycle, maps pipeline results to process exit codes, emits Chronicler events
at stage boundaries, and embeds PACT keys for Sentinel attribution.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
import types as _types
from enum import IntEnum, Enum
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, ConfigDict, field_validator


# ---------------------------------------------------------------------------
# Dependency module imports — module-level so patch("exemplar.cli.X") works.
# Tests mock these; production resolves them from the exemplar namespace.
# ---------------------------------------------------------------------------
def _import_dep(name: str):
    try:
        _ex = __import__("exemplar")
        return getattr(_ex, name)
    except (ImportError, AttributeError):
        return _types.ModuleType(name)


intake = _import_dep("intake")
circuit = _import_dep("circuit")
assessor = _import_dep("assessor")
reporter = _import_dep("reporter")
chronicle = _import_dep("chronicle")
config = _import_dep("config")
learner = _import_dep("learner")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CliExitCode(IntEnum):
    """CLI process exit codes mapping to review outcomes."""
    PASS = 0
    WARN = 1
    BLOCK = 2
    ERROR = 3


class SubcommandName(str, Enum):
    """Valid CLI subcommand identifiers used as dispatch keys."""
    review = "review"
    trust = "trust"
    history = "history"
    adopt = "adopt"


class OutputFormat(str, Enum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------
class FilePath(BaseModel):
    """A validated filesystem path string."""
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        if not v:
            raise ValueError("FilePath must be non-empty")
        if "\x00" in v:
            raise ValueError("FilePath must not contain null bytes")
        if len(v) > 4096:
            raise ValueError("FilePath must not exceed 4096 characters")
        return v


class PactKey(BaseModel):
    """PACT attribution key for Sentinel tracing."""
    model_config = ConfigDict(frozen=True)
    namespace: str
    function_key: str

    @field_validator("namespace")
    @classmethod
    def validate_namespace(cls, v: str) -> str:
        if v != "EXEMPLAR.CLI":
            raise ValueError(f"PactKey namespace must be 'EXEMPLAR.CLI', got '{v}'")
        return v

    @field_validator("function_key")
    @classmethod
    def validate_function_key(cls, v: str) -> str:
        if not re.match(r"^EXEMPLAR\.CLI\.[a-z_]+$", v):
            raise ValueError(
                f"PactKey function_key must match ^EXEMPLAR\\.CLI\\.[a-z_]+$, got '{v}'"
            )
        return v


class CliArgs(BaseModel):
    """Parsed and validated CLI arguments. Frozen Pydantic model."""
    model_config = ConfigDict(frozen=True)
    subcommand: SubcommandName
    diff_file: Optional[FilePath] = None
    config_path: Optional[FilePath] = None
    output_format: OutputFormat = OutputFormat.json
    query: Optional[str] = None
    debug: bool = False


class CliResult(BaseModel):
    """Internal result from a subcommand handler before exit code mapping."""
    model_config = ConfigDict(frozen=True)
    exit_code: CliExitCode
    stdout_output: str
    stderr_output: Optional[str] = None


class SubcommandDispatchTable(BaseModel):
    """Maps SubcommandName to its async handler function."""
    model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)
    handlers: dict


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    """Constructs the argparse.ArgumentParser with all four subcommands."""
    parser = argparse.ArgumentParser(prog="exemplar")
    parser.add_argument("--debug", action="store_true", default=False,
                        help="Enable verbose diagnostic output to stderr")
    subparsers = parser.add_subparsers(dest="subcommand")

    review_parser = subparsers.add_parser("review")
    review_parser.add_argument("diff_file")
    review_parser.add_argument("--config", dest="config", default=None)
    review_parser.add_argument("--format", dest="format", default="json",
                               choices=["json", "md", "github"])

    subparsers.add_parser("trust")

    history_parser = subparsers.add_parser("history")
    history_parser.add_argument("--query", default=None)

    subparsers.add_parser("adopt")

    return parser


def parse_and_validate_args(parser: argparse.ArgumentParser, argv: list) -> CliArgs:
    """Parses raw argv and converts to validated CliArgs struct."""
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_usage(sys.stderr)
        raise SystemExit(2)

    subcommand = SubcommandName(args.subcommand)

    diff_file = None
    config_path = None
    output_format = OutputFormat.json
    query = None
    debug = getattr(args, "debug", False)

    if subcommand == SubcommandName.review:
        diff_val = getattr(args, "diff_file", None)
        if not diff_val:
            raise SystemExit(2)
        diff_file = FilePath(value=diff_val)
        config_val = getattr(args, "config", None)
        if config_val:
            config_path = FilePath(value=config_val)
        fmt = getattr(args, "format", "json")
        output_format = OutputFormat(fmt)

    if subcommand == SubcommandName.history:
        query = getattr(args, "query", None)

    return CliArgs(
        subcommand=subcommand,
        diff_file=diff_file,
        config_path=config_path,
        output_format=output_format,
        query=query,
        debug=debug,
    )


# ---------------------------------------------------------------------------
# Decision -> Exit Code
# ---------------------------------------------------------------------------
_DECISION_MAP = {
    "pass": CliExitCode.PASS,
    "warn": CliExitCode.WARN,
    "block": CliExitCode.BLOCK,
    "error": CliExitCode.ERROR,
}


def map_decision_to_exit_code(decision: str) -> CliExitCode:
    """Pure mapping from ReviewDecision string to CliExitCode."""
    if decision not in _DECISION_MAP:
        raise ValueError(f"Unknown ReviewDecision: {decision}")
    return _DECISION_MAP[decision]


# ---------------------------------------------------------------------------
# Async Handlers
# ---------------------------------------------------------------------------
async def handle_review(args: CliArgs) -> CliResult:
    """Async handler for the 'review' subcommand. PACT: EXEMPLAR.CLI.handle_review"""
    stderr_parts: list[str] = []
    try:
        # Load config
        cfg_path = args.config_path.value if args.config_path else None
        cfg = config.load_config(cfg_path)

        if args.debug:
            stderr_parts.append(f"[debug] Config loaded from: {cfg_path}")

        # Emit review.started (fire-and-forget)
        try:
            await chronicle.emit_event({"event_type": "review.started"})
        except Exception:
            if args.debug:
                stderr_parts.append("[debug] Chronicler emission failed (non-fatal)")

        # Read diff file
        diff_path_str = args.diff_file.value if args.diff_file else None
        if not diff_path_str:
            return CliResult(
                exit_code=CliExitCode.ERROR, stdout_output="",
                stderr_output="No diff file specified",
            )

        p = Path(diff_path_str)
        if not p.exists():
            return CliResult(
                exit_code=CliExitCode.ERROR, stdout_output="",
                stderr_output=f"Diff file not found: {diff_path_str}",
            )

        try:
            raw_diff = p.read_text()
        except (PermissionError, IOError, OSError):
            return CliResult(
                exit_code=CliExitCode.ERROR, stdout_output="",
                stderr_output=f"Failed to read diff file: {diff_path_str}",
            )

        if len(raw_diff) == 0:
            return CliResult(
                exit_code=CliExitCode.ERROR, stdout_output="",
                stderr_output=f"Diff file is empty: {diff_path_str}",
            )

        if args.debug:
            stderr_parts.append(f"[debug] Diff read: {diff_path_str} ({len(raw_diff)} bytes)")

        # Pipeline: intake -> circuit -> assessor -> reporter
        parsed = await intake.parse_diff(raw_diff)
        routed = await circuit.route_stages(parsed)
        assessment = await assessor.assess(routed)
        decision_str = assessment.decision
        output = await reporter.format_report(assessment)
        exit_code = map_decision_to_exit_code(decision_str)

        if args.debug:
            stderr_parts.append(f"[debug] Pipeline complete, decision: {decision_str}")

        return CliResult(
            exit_code=exit_code,
            stdout_output=output,
            stderr_output="\n".join(stderr_parts) if stderr_parts else "",
        )
    except Exception as e:
        stderr_parts.append(f"Pipeline failed: {e}")
        return CliResult(
            exit_code=CliExitCode.ERROR, stdout_output="",
            stderr_output="\n".join(stderr_parts),
        )


async def handle_trust(args: CliArgs) -> CliResult:
    """Async handler for the 'trust' subcommand. PACT: EXEMPLAR.CLI.handle_trust"""
    try:
        cfg_path = args.config_path.value if args.config_path else None
        cfg = config.load_config(cfg_path)
        scores = await assessor.get_trust_scores()

        lines = ["Reviewer Trust Scores", "=" * 40]
        for entry in scores:
            if isinstance(entry, dict):
                lines.append(f"  {entry.get('reviewer', 'unknown')}: {entry.get('score', 0.0):.2f}")
            else:
                lines.append(f"  {entry}")
        if not scores:
            lines.append("  No trust scores available.")

        return CliResult(
            exit_code=CliExitCode.PASS,
            stdout_output="\n".join(lines),
            stderr_output="",
        )
    except Exception as e:
        return CliResult(
            exit_code=CliExitCode.ERROR, stdout_output="",
            stderr_output=f"Failed to load trust scores: {e}",
        )


async def handle_history(args: CliArgs) -> CliResult:
    """Async handler for the 'history' subcommand. PACT: EXEMPLAR.CLI.handle_history"""
    try:
        cfg_path = args.config_path.value if args.config_path else None
        cfg = config.load_config(cfg_path)
        results = await learner.query_history(args.query)

        if not results:
            output = "No review history found."
        else:
            lines = ["Review History", "=" * 40]
            for entry in results:
                if isinstance(entry, dict):
                    lines.append(f"  {json.dumps(entry)}")
                else:
                    lines.append(f"  {entry}")
            output = "\n".join(lines)

        return CliResult(
            exit_code=CliExitCode.PASS, stdout_output=output, stderr_output="",
        )
    except Exception as e:
        return CliResult(
            exit_code=CliExitCode.ERROR, stdout_output="",
            stderr_output=f"Failed to query review history from Kindex: {e}",
        )


async def handle_adopt(args: CliArgs) -> CliResult:
    """Async handler for the 'adopt' subcommand. PACT: EXEMPLAR.CLI.handle_adopt"""
    try:
        cfg_path = args.config_path.value if args.config_path else None
        cfg = config.load_config(cfg_path)
        findings = await learner.scan_linter_configs()

        if not findings:
            output = "No linter configurations found in current directory."
        else:
            lines = ["Linter Config Scan Results", "=" * 40]
            for entry in findings:
                if isinstance(entry, dict):
                    lines.append(f"  {json.dumps(entry)}")
                else:
                    lines.append(f"  {entry}")
            output = "\n".join(lines)

        return CliResult(
            exit_code=CliExitCode.PASS, stdout_output=output, stderr_output="",
        )
    except Exception as e:
        return CliResult(
            exit_code=CliExitCode.ERROR, stdout_output="",
            stderr_output=f"Failed during linter config scan: {e}",
        )


# ---------------------------------------------------------------------------
# Dispatch Table
# ---------------------------------------------------------------------------
def build_dispatch_table() -> SubcommandDispatchTable:
    """Constructs the SubcommandDispatchTable."""
    return SubcommandDispatchTable(handlers={
        SubcommandName.review: handle_review,
        SubcommandName.trust: handle_trust,
        SubcommandName.history: handle_history,
        SubcommandName.adopt: handle_adopt,
    })


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
def main(argv: list | None = None) -> int:
    """Synchronous entry point for the CLI. PACT: EXEMPLAR.CLI.main"""
    try:
        if argv is None:
            argv = sys.argv[1:]

        parser = build_parser()
        args = parse_and_validate_args(parser, argv)
        table = build_dispatch_table()
        handler = table.handlers[args.subcommand]
        result = asyncio.run(handler(args))

        if result.stdout_output:
            sys.stdout.write(result.stdout_output)
            if not result.stdout_output.endswith("\n"):
                sys.stdout.write("\n")

        if result.stderr_output:
            sys.stderr.write(result.stderr_output)
            if not result.stderr_output.endswith("\n"):
                sys.stderr.write("\n")

        exit_code = result.exit_code
        return exit_code.value if hasattr(exit_code, 'value') else int(exit_code)

    except KeyboardInterrupt:
        try:
            sys.stderr.write("Interrupted by user\n")
        except Exception:
            pass
        return CliExitCode.ERROR.value

    except SystemExit:
        return CliExitCode.ERROR.value

    except Exception as e:
        try:
            sys.stderr.write(f"Error: {e}\n")
        except Exception:
            pass
        return CliExitCode.ERROR.value


if __name__ == "__main__":
    sys.exit(main())
