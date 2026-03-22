"""
Contract tests for exemplar.cli module.

Tests organized in five sections:
1. Type validation (enums, data models, validators)
2. Parser & argument validation (pure, synchronous)
3. Exit code mapping (pure, synchronous)
4. Dispatch table (pure, synchronous)
5. Async handlers (mocked I/O)
6. Main orchestrator (integration-level)
7. Invariants (cross-cutting)
"""

import asyncio
import inspect
import os
import random
import string
import sys
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

import pytest

# Import all public symbols from the CLI module
from exemplar.cli import (
    CliExitCode,
    SubcommandName,
    CliArgs,
    FilePath,
    OutputFormat,
    CliResult,
    SubcommandDispatchTable,
    PactKey,
    build_parser,
    parse_and_validate_args,
    handle_review,
    handle_trust,
    handle_history,
    handle_adopt,
    build_dispatch_table,
    map_decision_to_exit_code,
    main,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def parser():
    """Build a fresh parser for each test."""
    return build_parser()


@pytest.fixture
def tmp_diff_file(tmp_path):
    """Create a temporary diff file with content."""
    diff = tmp_path / "test.diff"
    diff.write_text("diff --git a/foo.py b/foo.py\n--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new\n")
    return diff


@pytest.fixture
def tmp_empty_diff_file(tmp_path):
    """Create an empty diff file."""
    diff = tmp_path / "empty.diff"
    diff.write_text("")
    return diff


@pytest.fixture
def tmp_config_file(tmp_path):
    """Create a minimal config file."""
    cfg = tmp_path / ".exemplar.yml"
    cfg.write_text("version: 1\n")
    return cfg


@pytest.fixture
def cli_args_factory():
    """Factory that creates CliArgs with sensible defaults, allows overrides."""
    def _factory(**overrides):
        defaults = {
            "subcommand": SubcommandName.review,
            "diff_file": FilePath(value="/tmp/test.diff"),
            "config_path": FilePath(value="/tmp/.exemplar.yml"),
            "output_format": OutputFormat.json,
            "query": "",
            "debug": False,
        }
        defaults.update(overrides)
        return CliArgs(**defaults)
    return _factory


@pytest.fixture
def mock_pipeline():
    """Mock all pipeline dependencies for handle_review."""
    with patch("exemplar.cli.intake") as m_intake, \
         patch("exemplar.cli.circuit") as m_circuit, \
         patch("exemplar.cli.assessor") as m_assessor, \
         patch("exemplar.cli.reporter") as m_reporter, \
         patch("exemplar.cli.chronicle") as m_chronicle:

        # Set up async mocks where needed
        m_intake.parse_diff = AsyncMock(return_value=MagicMock())
        m_circuit.route_stages = AsyncMock(return_value=MagicMock())
        m_assessor.assess = AsyncMock(return_value=MagicMock(decision="pass"))
        m_reporter.format_report = AsyncMock(return_value="formatted report output")
        m_chronicle.emit_event = AsyncMock()

        yield {
            "intake": m_intake,
            "circuit": m_circuit,
            "assessor": m_assessor,
            "reporter": m_reporter,
            "chronicle": m_chronicle,
        }


@pytest.fixture
def mock_config():
    """Mock config loading."""
    with patch("exemplar.cli.config") as m_config:
        m_config.load_config = MagicMock(return_value=MagicMock())
        yield m_config


@pytest.fixture
def mock_learner():
    """Mock learner module."""
    with patch("exemplar.cli.learner") as m_learner:
        m_learner.query_history = AsyncMock(return_value=[])
        m_learner.scan_linter_configs = AsyncMock(return_value=[])
        yield m_learner


# ============================================================================
# Section 1: Type Validation
# ============================================================================

class TestCliExitCode:
    """Tests for CliExitCode enum."""

    def test_has_all_variants(self):
        """CliExitCode has exactly 0, 1, 2, 3 variants."""
        values = {e.value if hasattr(e, 'value') else e for e in CliExitCode}
        assert 0 in values
        assert 1 in values
        assert 2 in values
        assert 3 in values
        assert len(list(CliExitCode)) == 4


class TestSubcommandName:
    """Tests for SubcommandName enum."""

    def test_has_all_variants(self):
        """SubcommandName has exactly review, trust, history, adopt."""
        names = {e.value if hasattr(e, 'value') else str(e) for e in SubcommandName}
        for expected in ["review", "trust", "history", "adopt"]:
            assert any(expected in str(n) for n in names), f"Missing variant: {expected}"
        assert len(list(SubcommandName)) == 4


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_has_all_variants(self):
        """OutputFormat has exactly json, md, github."""
        names = {e.value if hasattr(e, 'value') else str(e) for e in OutputFormat}
        for expected in ["json", "md", "github"]:
            assert any(expected in str(n) for n in names), f"Missing variant: {expected}"
        assert len(list(OutputFormat)) == 3


class TestFilePath:
    """Tests for FilePath type validation."""

    def test_valid_path(self):
        """FilePath accepts a valid non-empty path string."""
        fp = FilePath(value="/some/path.diff")
        assert fp.value == "/some/path.diff"

    def test_single_char_path(self):
        """FilePath accepts minimum length path (1 char)."""
        fp = FilePath(value="x")
        assert fp.value == "x"

    def test_max_length_path_accepted(self):
        """FilePath accepts string of exactly 4096 characters."""
        path = "a" * 4096
        fp = FilePath(value=path)
        assert len(fp.value) == 4096

    def test_exceeds_max_length_rejected(self):
        """FilePath rejects string exceeding 4096 characters."""
        path = "a" * 4097
        with pytest.raises((ValueError, Exception)):
            FilePath(value=path)

    def test_empty_string_rejected(self):
        """FilePath rejects empty string."""
        with pytest.raises((ValueError, Exception)):
            FilePath(value="")

    def test_null_byte_rejected(self):
        """FilePath rejects string containing null byte."""
        with pytest.raises((ValueError, Exception)):
            FilePath(value="path\x00evil")

    def test_path_with_spaces(self):
        """FilePath accepts paths with spaces."""
        fp = FilePath(value="/some path/with spaces.diff")
        assert fp.value == "/some path/with spaces.diff"

    def test_path_with_unicode(self):
        """FilePath accepts paths with unicode characters."""
        fp = FilePath(value="/some/café/résumé.diff")
        assert fp.value == "/some/café/résumé.diff"


class TestPactKey:
    """Tests for PactKey validation."""

    def test_valid_pact_key(self):
        """PactKey accepts valid namespace and function_key."""
        pk = PactKey(namespace="EXEMPLAR.CLI", function_key="EXEMPLAR.CLI.handle_review")
        assert pk.namespace == "EXEMPLAR.CLI"
        assert pk.function_key == "EXEMPLAR.CLI.handle_review"

    def test_valid_function_keys(self):
        """PactKey accepts various valid function_key patterns."""
        for fk in ["EXEMPLAR.CLI.handle_review", "EXEMPLAR.CLI.handle_trust",
                    "EXEMPLAR.CLI.handle_history", "EXEMPLAR.CLI.handle_adopt",
                    "EXEMPLAR.CLI.main"]:
            pk = PactKey(namespace="EXEMPLAR.CLI", function_key=fk)
            assert pk.function_key == fk

    def test_invalid_namespace_rejected(self):
        """PactKey rejects invalid namespace."""
        with pytest.raises((ValueError, Exception)):
            PactKey(namespace="WRONG.NAMESPACE", function_key="EXEMPLAR.CLI.main")

    def test_invalid_function_key_rejected(self):
        """PactKey rejects function_key not matching pattern."""
        with pytest.raises((ValueError, Exception)):
            PactKey(namespace="EXEMPLAR.CLI", function_key="BAD_KEY")

    def test_function_key_uppercase_rejected(self):
        """PactKey rejects function_key with uppercase letters after prefix."""
        with pytest.raises((ValueError, Exception)):
            PactKey(namespace="EXEMPLAR.CLI", function_key="EXEMPLAR.CLI.HandleReview")


class TestCliArgsImmutability:
    """Tests for CliArgs frozen model."""

    def test_immutable_after_construction(self, cli_args_factory):
        """CliArgs instances are frozen; attribute assignment raises."""
        args = cli_args_factory()
        with pytest.raises((AttributeError, TypeError, Exception)):
            args.subcommand = SubcommandName.trust

    def test_construction_succeeds(self, cli_args_factory):
        """CliArgs can be constructed with valid fields."""
        args = cli_args_factory()
        assert args.subcommand == SubcommandName.review


class TestCliResultImmutability:
    """Tests for CliResult frozen model."""

    def test_immutable_after_construction(self):
        """CliResult instances are frozen; attribute assignment raises."""
        result = CliResult(exit_code=CliExitCode(0), stdout_output="ok", stderr_output="")
        with pytest.raises((AttributeError, TypeError, Exception)):
            result.exit_code = CliExitCode(1)

    def test_construction_succeeds(self):
        """CliResult can be constructed with valid fields."""
        result = CliResult(exit_code=CliExitCode(0), stdout_output="output", stderr_output="diag")
        assert result.stdout_output == "output"


# ============================================================================
# Section 2: Parser & Argument Validation
# ============================================================================

class TestBuildParser:
    """Tests for build_parser() function."""

    def test_returns_parser(self, parser):
        """build_parser returns an ArgumentParser instance."""
        import argparse
        assert isinstance(parser, argparse.ArgumentParser)

    def test_prog_name_is_exemplar(self, parser):
        """Parser prog name is 'exemplar'."""
        assert parser.prog == "exemplar"

    def test_has_four_subcommands(self, parser):
        """Parser has exactly 4 subcommands."""
        # Access subparsers via internal API
        subparsers_actions = [
            action for action in parser._subparsers._actions
            if hasattr(action, '_parser_class')
        ]
        # Find the subparsers action
        for action in parser._subparsers._actions:
            if hasattr(action, 'choices') and action.choices:
                choices = action.choices
                assert len(choices) == 4
                assert "review" in choices
                assert "trust" in choices
                assert "history" in choices
                assert "adopt" in choices
                return
        # If we get here, try parsing to verify subcommands exist
        for subcmd in ["review", "trust", "history", "adopt"]:
            # Just verify the parser doesn't fail for known subcommands
            pass

    def test_review_accepts_diff_file(self, parser):
        """Review subcommand has positional diff_file argument."""
        args = parser.parse_args(["review", "test.diff"])
        assert hasattr(args, "diff_file") or hasattr(args, "diff-file")

    def test_review_has_config_option(self, parser):
        """Review subcommand accepts --config."""
        args = parser.parse_args(["review", "test.diff", "--config", "myconfig.yml"])
        config_val = getattr(args, "config", None) or getattr(args, "config_path", None)
        assert config_val is not None

    def test_review_has_format_option_with_choices(self, parser):
        """Review --format accepts json, md, github."""
        for fmt in ["json", "md", "github"]:
            args = parser.parse_args(["review", "test.diff", "--format", fmt])
            format_val = getattr(args, "format", None) or getattr(args, "output_format", None)
            assert format_val == fmt

    def test_review_format_invalid_choice_rejected(self, parser):
        """Review --format rejects invalid format."""
        with pytest.raises(SystemExit):
            parser.parse_args(["review", "test.diff", "--format", "xml"])

    def test_history_has_query_option(self, parser):
        """History subcommand accepts --query."""
        args = parser.parse_args(["history", "--query", "security"])
        assert getattr(args, "query", None) == "security"

    def test_debug_flag_defaults_false(self, parser):
        """--debug flag defaults to False."""
        args = parser.parse_args(["trust"])
        assert getattr(args, "debug", None) is False

    def test_debug_flag_can_be_set(self, parser):
        """--debug flag can be set to True."""
        args = parser.parse_args(["--debug", "trust"])
        assert getattr(args, "debug", None) is True


class TestParseAndValidateArgs:
    """Tests for parse_and_validate_args() function."""

    def test_review_with_diff_file(self, parser):
        """Parses review subcommand with diff file into valid CliArgs."""
        result = parse_and_validate_args(parser, ["review", "my.diff"])
        assert isinstance(result, CliArgs)
        assert result.subcommand == SubcommandName.review
        # diff_file should be non-empty
        if isinstance(result.diff_file, FilePath):
            assert len(result.diff_file.value) > 0
        else:
            assert len(str(result.diff_file)) > 0

    def test_trust_subcommand(self, parser):
        """Parses trust subcommand into valid CliArgs."""
        result = parse_and_validate_args(parser, ["trust"])
        assert isinstance(result, CliArgs)
        assert result.subcommand == SubcommandName.trust

    def test_history_subcommand(self, parser):
        """Parses history subcommand into valid CliArgs."""
        result = parse_and_validate_args(parser, ["history"])
        assert isinstance(result, CliArgs)
        assert result.subcommand == SubcommandName.history

    def test_history_with_query(self, parser):
        """Parses history --query into CliArgs with query field."""
        result = parse_and_validate_args(parser, ["history", "--query", "security"])
        assert result.query == "security"

    def test_adopt_subcommand(self, parser):
        """Parses adopt subcommand into valid CliArgs."""
        result = parse_and_validate_args(parser, ["adopt"])
        assert isinstance(result, CliArgs)
        assert result.subcommand == SubcommandName.adopt

    def test_review_with_all_options(self, parser):
        """Parses review with --config, --format, --debug."""
        result = parse_and_validate_args(
            parser, ["--debug", "review", "my.diff", "--config", "cfg.yml", "--format", "json"]
        )
        assert result.debug is True
        assert result.output_format == OutputFormat.json

    def test_output_format_is_valid(self, parser):
        """Returned CliArgs has valid OutputFormat."""
        result = parse_and_validate_args(parser, ["review", "my.diff", "--format", "md"])
        assert result.output_format in list(OutputFormat)

    def test_no_subcommand_raises(self, parser):
        """Raises error when no subcommand provided."""
        with pytest.raises((SystemExit, ValueError, Exception)):
            parse_and_validate_args(parser, [])

    def test_unknown_argument_raises(self, parser):
        """Raises error on unrecognized argument."""
        with pytest.raises((SystemExit, ValueError, Exception)):
            parse_and_validate_args(parser, ["review", "my.diff", "--banana"])

    def test_missing_diff_file_raises(self, parser):
        """Raises error when review invoked without diff-file."""
        with pytest.raises((SystemExit, ValueError, Exception)):
            parse_and_validate_args(parser, ["review"])


# ============================================================================
# Section 3: Exit Code Mapping
# ============================================================================

class TestMapDecisionToExitCode:
    """Tests for map_decision_to_exit_code() pure function."""

    @pytest.mark.parametrize("decision,expected_code", [
        ("pass", 0),
        ("warn", 1),
        ("block", 2),
        ("error", 3),
    ])
    def test_valid_decisions(self, decision, expected_code):
        """Each valid decision maps to the correct exit code."""
        result = map_decision_to_exit_code(decision)
        # Compare numeric value
        result_val = result.value if hasattr(result, 'value') else int(result)
        assert result_val == expected_code

    def test_invalid_decision_raises(self):
        """Unknown decision string raises error."""
        with pytest.raises((ValueError, KeyError, Exception)):
            map_decision_to_exit_code("banana")

    def test_empty_decision_raises(self):
        """Empty string decision raises error."""
        with pytest.raises((ValueError, KeyError, Exception)):
            map_decision_to_exit_code("")

    def test_case_sensitive_pass_uppercase(self):
        """'PASS' (uppercase) is not a valid decision."""
        with pytest.raises((ValueError, KeyError, Exception)):
            map_decision_to_exit_code("PASS")

    def test_case_sensitive_warn_uppercase(self):
        """'WARN' (uppercase) is not a valid decision."""
        with pytest.raises((ValueError, KeyError, Exception)):
            map_decision_to_exit_code("WARN")

    def test_none_raises(self):
        """None decision raises error."""
        with pytest.raises((ValueError, KeyError, TypeError, Exception)):
            map_decision_to_exit_code(None)

    def test_deterministic(self):
        """Same decision always produces the same exit code."""
        for decision in ["pass", "warn", "block", "error"]:
            results = [map_decision_to_exit_code(decision) for _ in range(10)]
            assert all(r == results[0] for r in results)

    def test_random_invalid_strings(self):
        """Random strings not in valid set always raise error."""
        valid = {"pass", "warn", "block", "error"}
        for _ in range(50):
            s = "".join(random.choices(string.ascii_letters + string.digits, k=random.randint(1, 20)))
            if s not in valid:
                with pytest.raises((ValueError, KeyError, Exception)):
                    map_decision_to_exit_code(s)


# ============================================================================
# Section 4: Dispatch Table
# ============================================================================

class TestBuildDispatchTable:
    """Tests for build_dispatch_table() function."""

    def test_returns_dispatch_table(self):
        """build_dispatch_table returns a SubcommandDispatchTable."""
        table = build_dispatch_table()
        assert isinstance(table, SubcommandDispatchTable)

    def test_has_four_entries(self):
        """Dispatch table has exactly 4 entries."""
        table = build_dispatch_table()
        assert len(table.handlers) == 4

    def test_all_subcommands_present(self):
        """Every SubcommandName variant has a handler entry."""
        table = build_dispatch_table()
        for name in SubcommandName:
            assert name in table.handlers, f"Missing handler for {name}"

    def test_no_extra_keys(self):
        """Dispatch table has no keys beyond SubcommandName variants."""
        table = build_dispatch_table()
        valid_keys = set(SubcommandName)
        actual_keys = set(table.handlers.keys())
        assert actual_keys == valid_keys, f"Extra keys: {actual_keys - valid_keys}"

    def test_handlers_are_async_callables(self):
        """Each handler is an async callable."""
        table = build_dispatch_table()
        for name, handler in table.handlers.items():
            assert callable(handler), f"Handler for {name} is not callable"
            assert asyncio.iscoroutinefunction(handler), f"Handler for {name} is not async"

    def test_review_handler_is_handle_review(self):
        """Review handler maps to handle_review function."""
        table = build_dispatch_table()
        assert table.handlers[SubcommandName.review] is handle_review

    def test_trust_handler_is_handle_trust(self):
        """Trust handler maps to handle_trust function."""
        table = build_dispatch_table()
        assert table.handlers[SubcommandName.trust] is handle_trust

    def test_history_handler_is_handle_history(self):
        """History handler maps to handle_history function."""
        table = build_dispatch_table()
        assert table.handlers[SubcommandName.history] is handle_history

    def test_adopt_handler_is_handle_adopt(self):
        """Adopt handler maps to handle_adopt function."""
        table = build_dispatch_table()
        assert table.handlers[SubcommandName.adopt] is handle_adopt


# ============================================================================
# Section 5: Async Handlers
# ============================================================================

@pytest.mark.asyncio
class TestHandleReview:
    """Tests for async handle_review() function."""

    async def test_happy_path(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """handle_review returns successful CliResult on happy path."""
        args = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        result = await handle_review(args)

        assert isinstance(result, CliResult)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val in (0, 1, 2), f"Expected PASS/WARN/BLOCK, got {exit_val}"
        assert len(result.stdout_output) > 0

    async def test_chronicler_event_emitted(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """handle_review emits a review.started Chronicler event."""
        args = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        await handle_review(args)
        mock_pipeline["chronicle"].emit_event.assert_called()

    async def test_chronicler_failure_does_not_block(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """handle_review succeeds even when Chronicler raises."""
        mock_pipeline["chronicle"].emit_event = AsyncMock(side_effect=Exception("chronicle down"))
        args = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        result = await handle_review(args)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val != 3, "Chronicler failure should not cause ERROR exit"

    async def test_diff_file_not_found(self, cli_args_factory, tmp_config_file, mock_pipeline, mock_config):
        """handle_review returns ERROR(3) when diff file does not exist."""
        args = cli_args_factory(
            diff_file=FilePath(value="/nonexistent/path/no.diff"),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        result = await handle_review(args)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3

    async def test_diff_file_empty(self, cli_args_factory, tmp_empty_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """handle_review returns ERROR(3) when diff file is empty."""
        args = cli_args_factory(
            diff_file=FilePath(value=str(tmp_empty_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        result = await handle_review(args)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3

    async def test_diff_file_read_error(self, cli_args_factory, tmp_path, tmp_config_file, mock_pipeline, mock_config):
        """handle_review returns ERROR(3) when diff file has permission error."""
        diff = tmp_path / "noperm.diff"
        diff.write_text("some content")
        diff.chmod(0o000)
        try:
            args = cli_args_factory(
                diff_file=FilePath(value=str(diff)),
                config_path=FilePath(value=str(tmp_config_file)),
            )
            result = await handle_review(args)
            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 3
        finally:
            diff.chmod(0o644)  # Restore permissions for cleanup

    async def test_config_load_error(self, cli_args_factory, tmp_diff_file, mock_pipeline):
        """handle_review returns ERROR(3) when config file is invalid."""
        with patch("exemplar.cli.config") as m_config:
            m_config.load_config = MagicMock(side_effect=Exception("bad config"))
            args = cli_args_factory(
                diff_file=FilePath(value=str(tmp_diff_file)),
                config_path=FilePath(value="/nonexistent/config.yml"),
            )
            result = await handle_review(args)
            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 3

    async def test_pipeline_stage_failure(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """handle_review returns ERROR(3) when a pipeline stage raises."""
        mock_pipeline["intake"].parse_diff = AsyncMock(side_effect=RuntimeError("intake exploded"))
        args = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        result = await handle_review(args)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3

    async def test_debug_stderr_output(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """handle_review includes diagnostic info in stderr when debug=True."""
        args = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
            debug=True,
        )
        result = await handle_review(args)
        assert len(result.stderr_output) > 0, "debug=True should produce stderr output"

    async def test_stderr_output_on_error(self, cli_args_factory, tmp_config_file, mock_pipeline, mock_config):
        """handle_review includes error info in stderr on failure."""
        args = cli_args_factory(
            diff_file=FilePath(value="/nonexistent/file.diff"),
            config_path=FilePath(value=str(tmp_config_file)),
        )
        result = await handle_review(args)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3
        assert len(result.stderr_output) > 0


@pytest.mark.asyncio
class TestHandleTrust:
    """Tests for async handle_trust() function."""

    async def test_happy_path(self, cli_args_factory, mock_config):
        """handle_trust returns PASS(0) with trust score table."""
        with patch("exemplar.cli.assessor") as m_assessor:
            m_assessor.get_trust_scores = AsyncMock(return_value=[
                {"reviewer": "alice", "score": 0.95},
                {"reviewer": "bob", "score": 0.80},
            ])
            args = cli_args_factory(subcommand=SubcommandName.trust)
            result = await handle_trust(args)

            assert isinstance(result, CliResult)
            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 0
            assert len(result.stdout_output) > 0

    async def test_trust_data_unavailable(self, cli_args_factory, mock_config):
        """handle_trust returns ERROR(3) when trust data unavailable."""
        with patch("exemplar.cli.assessor") as m_assessor:
            m_assessor.get_trust_scores = AsyncMock(side_effect=Exception("trust store corrupt"))
            args = cli_args_factory(subcommand=SubcommandName.trust)
            result = await handle_trust(args)

            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 3

    async def test_config_load_error(self, cli_args_factory):
        """handle_trust returns ERROR(3) when config fails."""
        with patch("exemplar.cli.config") as m_config, \
             patch("exemplar.cli.assessor") as m_assessor:
            m_config.load_config = MagicMock(side_effect=Exception("config broken"))
            args = cli_args_factory(subcommand=SubcommandName.trust)
            result = await handle_trust(args)

            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 3


@pytest.mark.asyncio
class TestHandleHistory:
    """Tests for async handle_history() function."""

    async def test_happy_path(self, cli_args_factory, mock_config, mock_learner):
        """handle_history returns PASS(0) with results."""
        mock_learner.query_history = AsyncMock(return_value=[
            {"id": "1", "summary": "Review of PR #42"},
        ])
        args = cli_args_factory(subcommand=SubcommandName.history)
        result = await handle_history(args)

        assert isinstance(result, CliResult)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 0
        assert len(result.stdout_output) > 0

    async def test_empty_results_still_pass(self, cli_args_factory, mock_config, mock_learner):
        """handle_history returns PASS(0) even with zero results."""
        mock_learner.query_history = AsyncMock(return_value=[])
        args = cli_args_factory(subcommand=SubcommandName.history)
        result = await handle_history(args)

        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 0

    async def test_with_query_filter(self, cli_args_factory, mock_config, mock_learner):
        """handle_history respects --query filter."""
        mock_learner.query_history = AsyncMock(return_value=[])
        args = cli_args_factory(subcommand=SubcommandName.history, query="security")
        result = await handle_history(args)

        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 0

    async def test_kindex_unavailable(self, cli_args_factory, mock_config, mock_learner):
        """handle_history returns ERROR(3) when kindex store unreachable."""
        mock_learner.query_history = AsyncMock(side_effect=Exception("kindex unavailable"))
        args = cli_args_factory(subcommand=SubcommandName.history)
        result = await handle_history(args)

        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3

    async def test_config_load_error(self, cli_args_factory):
        """handle_history returns ERROR(3) when config fails."""
        with patch("exemplar.cli.config") as m_config, \
             patch("exemplar.cli.learner") as m_learner:
            m_config.load_config = MagicMock(side_effect=Exception("config error"))
            args = cli_args_factory(subcommand=SubcommandName.history)
            result = await handle_history(args)

            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 3


@pytest.mark.asyncio
class TestHandleAdopt:
    """Tests for async handle_adopt() function."""

    async def test_happy_path(self, cli_args_factory, mock_config, mock_learner):
        """handle_adopt returns PASS(0) with scan findings."""
        mock_learner.scan_linter_configs = AsyncMock(return_value=[
            {"file": ".eslintrc", "rules": 42, "suggestions": ["map rule X to reviewer Y"]},
        ])
        args = cli_args_factory(subcommand=SubcommandName.adopt)
        result = await handle_adopt(args)

        assert isinstance(result, CliResult)
        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 0
        assert len(result.stdout_output) > 0

    async def test_no_configs_found_still_pass(self, cli_args_factory, mock_config, mock_learner):
        """handle_adopt returns PASS(0) even when no linter configs found."""
        mock_learner.scan_linter_configs = AsyncMock(return_value=[])
        args = cli_args_factory(subcommand=SubcommandName.adopt)
        result = await handle_adopt(args)

        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 0

    async def test_scan_error(self, cli_args_factory, mock_config, mock_learner):
        """handle_adopt returns ERROR(3) on unexpected scan error."""
        mock_learner.scan_linter_configs = AsyncMock(side_effect=RuntimeError("scan failed"))
        args = cli_args_factory(subcommand=SubcommandName.adopt)
        result = await handle_adopt(args)

        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3

    async def test_cwd_unreadable(self, cli_args_factory, mock_config, mock_learner):
        """handle_adopt returns ERROR(3) when cwd is unreadable."""
        mock_learner.scan_linter_configs = AsyncMock(side_effect=OSError("cwd unreadable"))
        args = cli_args_factory(subcommand=SubcommandName.adopt)
        result = await handle_adopt(args)

        exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
        assert exit_val == 3

    async def test_config_load_error(self, cli_args_factory):
        """handle_adopt returns ERROR(3) when config fails to load."""
        with patch("exemplar.cli.config") as m_config, \
             patch("exemplar.cli.learner") as m_learner:
            m_config.load_config = MagicMock(side_effect=Exception("config error"))
            args = cli_args_factory(subcommand=SubcommandName.adopt)
            result = await handle_adopt(args)

            exit_val = result.exit_code.value if hasattr(result.exit_code, 'value') else int(result.exit_code)
            assert exit_val == 3


# ============================================================================
# Section 6: Main Orchestrator
# ============================================================================

class TestMain:
    """Tests for main() synchronous entry point."""

    def test_review_happy_path(self, tmp_diff_file, tmp_config_file):
        """main() returns 0 for successful review subcommand with mocked backends."""
        mock_result = CliResult(
            exit_code=CliExitCode(0),
            stdout_output="report output",
            stderr_output="",
        )
        with patch("exemplar.cli.handle_review", new_callable=lambda: lambda: AsyncMock(return_value=mock_result)) as _, \
             patch("exemplar.cli.handle_review", new=AsyncMock(return_value=mock_result)), \
             patch("exemplar.cli.config") as m_config, \
             patch("sys.stdout"), patch("sys.stderr"):
            m_config.load_config = MagicMock(return_value=MagicMock())
            exit_code = main(["review", str(tmp_diff_file), "--config", str(tmp_config_file)])

            assert isinstance(exit_code, int)
            assert exit_code in (0, 1, 2, 3)

    def test_returns_int(self):
        """main() always returns an int."""
        mock_result = CliResult(
            exit_code=CliExitCode(0),
            stdout_output="output",
            stderr_output="",
        )
        with patch("exemplar.cli.build_dispatch_table") as m_dispatch, \
             patch("exemplar.cli.parse_and_validate_args") as m_parse, \
             patch("sys.stdout"), patch("sys.stderr"):
            m_parse.return_value = MagicMock(subcommand=SubcommandName.trust)
            mock_handler = AsyncMock(return_value=mock_result)
            m_dispatch.return_value = SubcommandDispatchTable(
                handlers={
                    SubcommandName.review: mock_handler,
                    SubcommandName.trust: mock_handler,
                    SubcommandName.history: mock_handler,
                    SubcommandName.adopt: mock_handler,
                }
            )
            result = main(["trust"])
            assert isinstance(result, int)

    def test_no_exception_escapes(self):
        """main() catches all exceptions and returns 3."""
        with patch("exemplar.cli.build_parser", side_effect=RuntimeError("boom")), \
             patch("sys.stdout"), patch("sys.stderr"):
            result = main(["review", "some.diff"])
            assert isinstance(result, int)
            assert result == 3

    def test_keyboard_interrupt(self):
        """main() handles KeyboardInterrupt gracefully."""
        with patch("exemplar.cli.build_parser", side_effect=KeyboardInterrupt()), \
             patch("sys.stdout"), patch("sys.stderr"):
            result = main(["review", "some.diff"])
            assert isinstance(result, int)
            # KeyboardInterrupt should map to a valid exit code
            assert result in (0, 1, 2, 3)

    def test_unhandled_exception_returns_3(self):
        """main() maps unhandled exceptions to exit code 3."""
        with patch("exemplar.cli.build_parser", side_effect=TypeError("unexpected")), \
             patch("sys.stdout"), patch("sys.stderr"):
            result = main(["trust"])
            assert result == 3

    def test_writes_to_stdout_on_success(self, capsys):
        """main() writes handler stdout_output to sys.stdout on success."""
        mock_result = CliResult(
            exit_code=CliExitCode(0),
            stdout_output="trust score table output",
            stderr_output="",
        )
        with patch("exemplar.cli.build_dispatch_table") as m_dispatch, \
             patch("exemplar.cli.parse_and_validate_args") as m_parse:
            m_parse.return_value = MagicMock(subcommand=SubcommandName.trust)
            mock_handler = AsyncMock(return_value=mock_result)
            m_dispatch.return_value = SubcommandDispatchTable(
                handlers={
                    SubcommandName.review: mock_handler,
                    SubcommandName.trust: mock_handler,
                    SubcommandName.history: mock_handler,
                    SubcommandName.adopt: mock_handler,
                }
            )
            result = main(["trust"])
            captured = capsys.readouterr()
            assert "trust score table output" in captured.out

    def test_writes_to_stderr_on_error(self, capsys):
        """main() writes diagnostic to sys.stderr on error."""
        mock_result = CliResult(
            exit_code=CliExitCode(3),
            stdout_output="",
            stderr_output="something went wrong",
        )
        with patch("exemplar.cli.build_dispatch_table") as m_dispatch, \
             patch("exemplar.cli.parse_and_validate_args") as m_parse:
            m_parse.return_value = MagicMock(subcommand=SubcommandName.trust)
            mock_handler = AsyncMock(return_value=mock_result)
            m_dispatch.return_value = SubcommandDispatchTable(
                handlers={
                    SubcommandName.review: mock_handler,
                    SubcommandName.trust: mock_handler,
                    SubcommandName.history: mock_handler,
                    SubcommandName.adopt: mock_handler,
                }
            )
            result = main(["trust"])
            captured = capsys.readouterr()
            assert "something went wrong" in captured.err

    def test_return_value_in_valid_range(self):
        """main() return value is always 0, 1, 2, or 3."""
        # Even with totally broken internals
        with patch("exemplar.cli.build_parser", side_effect=Exception("total failure")), \
             patch("sys.stdout"), patch("sys.stderr"):
            result = main(["anything"])
            assert result in (0, 1, 2, 3)

    @pytest.mark.parametrize("subcommand", ["review", "trust", "history", "adopt"])
    def test_each_subcommand_dispatches(self, subcommand, tmp_diff_file):
        """main() dispatches to the correct handler for each subcommand."""
        mock_result = CliResult(
            exit_code=CliExitCode(0),
            stdout_output="output",
            stderr_output="",
        )
        argv = [subcommand]
        if subcommand == "review":
            argv.append(str(tmp_diff_file))

        with patch("exemplar.cli.build_dispatch_table") as m_dispatch, \
             patch("exemplar.cli.parse_and_validate_args") as m_parse, \
             patch("sys.stdout"), patch("sys.stderr"):
            m_parse.return_value = MagicMock(subcommand=SubcommandName(subcommand))
            mock_handler = AsyncMock(return_value=mock_result)
            m_dispatch.return_value = SubcommandDispatchTable(
                handlers={
                    SubcommandName.review: mock_handler,
                    SubcommandName.trust: mock_handler,
                    SubcommandName.history: mock_handler,
                    SubcommandName.adopt: mock_handler,
                }
            )
            result = main(argv)
            mock_handler.assert_called_once()
            assert isinstance(result, int)


# ============================================================================
# Section 7: Invariants
# ============================================================================

class TestInvariants:
    """Cross-cutting invariant tests."""

    def test_exit_code_deterministic_property(self):
        """Given the same pipeline result, the same exit code is always returned."""
        for decision in ["pass", "warn", "block", "error"]:
            results = set()
            for _ in range(100):
                result = map_decision_to_exit_code(decision)
                result_val = result.value if hasattr(result, 'value') else int(result)
                results.add(result_val)
            assert len(results) == 1, f"Non-deterministic exit code for {decision}: {results}"

    @pytest.mark.asyncio
    async def test_debug_flag_does_not_change_exit_code(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """--debug flag does not change exit codes."""
        args_no_debug = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
            debug=False,
        )
        args_debug = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
            debug=True,
        )
        result_no_debug = await handle_review(args_no_debug)
        result_debug = await handle_review(args_debug)

        no_debug_code = result_no_debug.exit_code.value if hasattr(result_no_debug.exit_code, 'value') else int(result_no_debug.exit_code)
        debug_code = result_debug.exit_code.value if hasattr(result_debug.exit_code, 'value') else int(result_debug.exit_code)
        assert no_debug_code == debug_code

    @pytest.mark.asyncio
    async def test_debug_flag_does_not_change_stdout(self, cli_args_factory, tmp_diff_file, tmp_config_file, mock_pipeline, mock_config):
        """--debug flag does not change stdout content."""
        args_no_debug = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
            debug=False,
        )
        args_debug = cli_args_factory(
            diff_file=FilePath(value=str(tmp_diff_file)),
            config_path=FilePath(value=str(tmp_config_file)),
            debug=True,
        )
        result_no_debug = await handle_review(args_no_debug)
        result_debug = await handle_review(args_debug)

        assert result_no_debug.stdout_output == result_debug.stdout_output

    def test_pact_key_namespace_always_exemplar_cli(self):
        """PACT key namespace is always 'EXEMPLAR.CLI'."""
        valid_keys = [
            "EXEMPLAR.CLI.handle_review",
            "EXEMPLAR.CLI.handle_trust",
            "EXEMPLAR.CLI.handle_history",
            "EXEMPLAR.CLI.handle_adopt",
            "EXEMPLAR.CLI.main",
        ]
        for fk in valid_keys:
            pk = PactKey(namespace="EXEMPLAR.CLI", function_key=fk)
            assert pk.namespace == "EXEMPLAR.CLI"

    def test_all_cli_exit_codes_are_valid(self):
        """All CliExitCode values are 0, 1, 2, or 3."""
        valid_values = {0, 1, 2, 3}
        for code in CliExitCode:
            val = code.value if hasattr(code, 'value') else int(code)
            assert val in valid_values

    def test_subcommand_dispatch_completeness(self):
        """Every SubcommandName has a corresponding handler in the dispatch table."""
        table = build_dispatch_table()
        for name in SubcommandName:
            assert name in table.handlers

    def test_handler_functions_are_async(self):
        """All handler functions are async coroutine functions."""
        for handler in [handle_review, handle_trust, handle_history, handle_adopt]:
            assert asyncio.iscoroutinefunction(handler), f"{handler.__name__} is not async"

    def test_main_is_sync(self):
        """main() is a synchronous function."""
        assert not asyncio.iscoroutinefunction(main)

    def test_build_parser_is_sync(self):
        """build_parser() is a synchronous function."""
        assert not asyncio.iscoroutinefunction(build_parser)

    def test_parse_and_validate_args_is_sync(self):
        """parse_and_validate_args() is a synchronous function."""
        assert not asyncio.iscoroutinefunction(parse_and_validate_args)

    def test_map_decision_to_exit_code_is_sync(self):
        """map_decision_to_exit_code() is a synchronous function."""
        assert not asyncio.iscoroutinefunction(map_decision_to_exit_code)

    def test_build_dispatch_table_is_sync(self):
        """build_dispatch_table() is a synchronous function."""
        assert not asyncio.iscoroutinefunction(build_dispatch_table)

    def test_cli_args_has_expected_fields(self, cli_args_factory):
        """CliArgs struct has all expected fields."""
        args = cli_args_factory()
        assert hasattr(args, 'subcommand')
        assert hasattr(args, 'diff_file')
        assert hasattr(args, 'config_path')
        assert hasattr(args, 'output_format')
        assert hasattr(args, 'query')
        assert hasattr(args, 'debug')

    def test_cli_result_has_expected_fields(self):
        """CliResult struct has all expected fields."""
        result = CliResult(exit_code=CliExitCode(0), stdout_output="", stderr_output="")
        assert hasattr(result, 'exit_code')
        assert hasattr(result, 'stdout_output')
        assert hasattr(result, 'stderr_output')
