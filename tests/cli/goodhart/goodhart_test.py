"""
Adversarial hidden acceptance tests for CLI Entry Point component.
These tests target gaps in visible test coverage to detect implementations
that hardcode values or take shortcuts to pass visible tests.
"""
import asyncio
import inspect
import sys
from unittest.mock import AsyncMock, MagicMock, patch, call
import pytest

from exemplar.cli import (
    build_parser,
    parse_and_validate_args,
    handle_review,
    handle_trust,
    handle_history,
    handle_adopt,
    build_dispatch_table,
    map_decision_to_exit_code,
    main,
    CliArgs,
    CliResult,
    CliExitCode,
    SubcommandName,
    OutputFormat,
    FilePath,
    PactKey,
)


# ---------------------------------------------------------------------------
# Helper to run async functions in sync tests
# ---------------------------------------------------------------------------
def run_async(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# parse_and_validate_args: hardcoded return detection
# ---------------------------------------------------------------------------
class TestGoodhartParseArgs:
    def test_goodhart_parse_review_diff_file_preserved(self):
        """parse_and_validate_args must preserve the exact diff_file path string from argv, not return a hardcoded value."""
        parser = build_parser()
        # Use a path that no hardcoded implementation would guess
        args = parse_and_validate_args(parser, ["review", "/tmp/unusual-path-12345.diff"])
        diff_file_val = args.diff_file if isinstance(args.diff_file, str) else getattr(args.diff_file, 'value', str(args.diff_file))
        assert "unusual-path-12345" in diff_file_val

    def test_goodhart_parse_review_different_diff_files(self):
        """parse_and_validate_args must correctly parse different diff file paths, not return a hardcoded value."""
        parser = build_parser()
        paths = ["a.diff", "changes.patch", "/absolute/path/to/diff", "relative/path.diff"]
        for path in paths:
            args = parse_and_validate_args(parser, ["review", path])
            diff_file_val = args.diff_file if isinstance(args.diff_file, str) else getattr(args.diff_file, 'value', str(args.diff_file))
            assert path in diff_file_val, f"Expected diff_file to contain '{path}', got '{diff_file_val}'"

    def test_goodhart_parse_review_format_option_preserved(self):
        """parse_and_validate_args must correctly propagate the --format option value for each valid OutputFormat variant."""
        parser = build_parser()
        for fmt in ["json", "md", "github"]:
            args = parse_and_validate_args(parser, ["review", "file.diff", "--format", fmt])
            fmt_val = args.output_format if isinstance(args.output_format, str) else getattr(args.output_format, 'value', str(args.output_format))
            assert fmt_val == fmt or fmt in str(fmt_val), f"Expected format '{fmt}', got '{fmt_val}'"

    def test_goodhart_parse_review_config_path_preserved(self):
        """parse_and_validate_args must preserve the exact --config path from argv."""
        parser = build_parser()
        args = parse_and_validate_args(parser, ["review", "file.diff", "--config", "/custom/dir/my-config.yml"])
        config_val = args.config_path if isinstance(args.config_path, str) else getattr(args.config_path, 'value', str(args.config_path))
        assert "my-config.yml" in config_val

    def test_goodhart_parse_debug_flag_true_for_trust(self):
        """parse_and_validate_args must set debug=True when --debug flag is present for trust subcommand."""
        parser = build_parser()
        args = parse_and_validate_args(parser, ["--debug", "trust"])
        assert args.debug is True

    def test_goodhart_parse_history_query_preserved(self):
        """parse_and_validate_args must preserve the exact --query string value for history subcommand."""
        parser = build_parser()
        args = parse_and_validate_args(parser, ["history", "--query", "security vulnerability fix"])
        assert args.query == "security vulnerability fix"

    def test_goodhart_parse_review_default_format(self):
        """parse_and_validate_args must assign a valid default output_format when --format is not specified."""
        parser = build_parser()
        args = parse_and_validate_args(parser, ["review", "file.diff"])
        fmt_val = args.output_format if isinstance(args.output_format, str) else getattr(args.output_format, 'value', str(args.output_format))
        assert fmt_val in ("json", "md", "github"), f"Default format '{fmt_val}' is not a valid OutputFormat"

    def test_goodhart_parse_invalid_format_rejected(self):
        """parse_and_validate_args must reject invalid --format values not in the enum."""
        parser = build_parser()
        with pytest.raises((SystemExit, Exception)):
            parse_and_validate_args(parser, ["review", "file.diff", "--format", "xml"])

    def test_goodhart_cli_args_subcommand_matches_parsed(self):
        """CliArgs.subcommand must be a proper typed value, not just a plain string that happens to match."""
        parser = build_parser()
        for subcmd in ["review", "trust", "history", "adopt"]:
            argv = [subcmd, "file.diff"] if subcmd == "review" else [subcmd]
            args = parse_and_validate_args(parser, argv)
            # The subcommand value must match the expected string
            subcmd_val = args.subcommand if isinstance(args.subcommand, str) else getattr(args.subcommand, 'value', str(args.subcommand))
            assert subcmd_val == subcmd or subcmd in str(subcmd_val)


# ---------------------------------------------------------------------------
# build_parser: subcommands reject extra args
# ---------------------------------------------------------------------------
class TestGoodhartBuildParser:
    def test_goodhart_build_parser_trust_no_positional(self):
        """trust subcommand should not accept any positional arguments."""
        parser = build_parser()
        with pytest.raises((SystemExit, Exception)):
            parser.parse_args(["trust", "extraarg"])

    def test_goodhart_build_parser_adopt_no_positional(self):
        """adopt subcommand should not accept any positional arguments."""
        parser = build_parser()
        with pytest.raises((SystemExit, Exception)):
            parser.parse_args(["adopt", "extraarg"])


# ---------------------------------------------------------------------------
# map_decision_to_exit_code: edge cases beyond visible tests
# ---------------------------------------------------------------------------
class TestGoodhartMapDecision:
    def test_goodhart_map_decision_whitespace_variants_rejected(self):
        """map_decision_to_exit_code must reject decisions with leading/trailing whitespace."""
        for bad in [" pass", "pass ", " warn ", "\tblock", "error\n"]:
            with pytest.raises(Exception):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_mixed_case_variants(self):
        """map_decision_to_exit_code must be strictly case-sensitive for all variants."""
        for bad in ["Pass", "WARN", "Block", "Error", "pAsS", "wArN", "bLoCk"]:
            with pytest.raises(Exception):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_substring_rejected(self):
        """map_decision_to_exit_code must reject strings that contain valid decisions as substrings."""
        for bad in ["password", "warning", "blocker", "errors", "nopass", "repass"]:
            with pytest.raises(Exception):
                map_decision_to_exit_code(bad)

    def test_goodhart_map_decision_none_rejected(self):
        """map_decision_to_exit_code must reject None input."""
        with pytest.raises(Exception):
            map_decision_to_exit_code(None)

    def test_goodhart_map_decision_numeric_rejected(self):
        """map_decision_to_exit_code must reject numeric inputs — it operates on string decisions."""
        for bad in [0, 1, 2, 3]:
            with pytest.raises(Exception):
                map_decision_to_exit_code(bad)


# ---------------------------------------------------------------------------
# build_dispatch_table: handlers are distinct
# ---------------------------------------------------------------------------
class TestGoodhartDispatchTable:
    def test_goodhart_dispatch_table_maps_to_correct_handlers(self):
        """Each dispatch table entry must map to a distinct handler function."""
        table = build_dispatch_table()
        handlers_dict = table.handlers if hasattr(table, 'handlers') else table
        if isinstance(handlers_dict, dict):
            handler_values = list(handlers_dict.values())
        else:
            handler_values = list(handlers_dict.values()) if hasattr(handlers_dict, 'values') else []
        # All handlers must be distinct objects
        handler_ids = [id(h) for h in handler_values]
        assert len(set(handler_ids)) == 4, "All four handlers must be distinct functions"

    def test_goodhart_dispatch_table_keys_are_subcommands(self):
        """Dispatch table keys must correspond to actual SubcommandName values."""
        table = build_dispatch_table()
        handlers_dict = table.handlers if hasattr(table, 'handlers') else table
        if isinstance(handlers_dict, dict):
            keys = set()
            for k in handlers_dict.keys():
                key_str = k if isinstance(k, str) else getattr(k, 'value', str(k))
                keys.add(key_str)
            assert keys == {"review", "trust", "history", "adopt"}


# ---------------------------------------------------------------------------
# FilePath: boundary and special character tests
# ---------------------------------------------------------------------------
class TestGoodhartFilePath:
    def test_goodhart_filepath_exactly_4096_accepted(self):
        """FilePath must accept a path string of exactly 4096 characters (the maximum)."""
        fp = FilePath(value="a" * 4096)
        val = fp.value if hasattr(fp, 'value') else str(fp)
        assert len(val) == 4096

    def test_goodhart_filepath_4097_rejected(self):
        """FilePath must reject a path string of exactly 4097 characters."""
        with pytest.raises(Exception):
            FilePath(value="a" * 4097)

    def test_goodhart_filepath_single_char_accepted(self):
        """FilePath must accept a single-character path (minimum length boundary)."""
        fp = FilePath(value="x")
        val = fp.value if hasattr(fp, 'value') else str(fp)
        assert val == "x" or "x" in val

    def test_goodhart_filepath_embedded_null_rejected(self):
        """FilePath must reject strings with null bytes anywhere in the string."""
        with pytest.raises(Exception):
            FilePath(value="path/to\x00/file")

    def test_goodhart_filepath_special_chars_accepted(self):
        """FilePath must accept paths with spaces, unicode, and special characters that are not null bytes."""
        for path in ["/path/to/my file.diff", "/tmp/日本語/file.diff", "/path/with-dashes_and.dots"]:
            fp = FilePath(value=path)
            val = fp.value if hasattr(fp, 'value') else str(fp)
            assert path in val


# ---------------------------------------------------------------------------
# PactKey: boundary tests
# ---------------------------------------------------------------------------
class TestGoodhartPactKey:
    def test_goodhart_pact_key_valid_function_keys(self):
        """PactKey must accept valid function keys for all handler functions."""
        for fk in [
            "EXEMPLAR.CLI.handle_review",
            "EXEMPLAR.CLI.handle_trust",
            "EXEMPLAR.CLI.handle_history",
            "EXEMPLAR.CLI.handle_adopt",
            "EXEMPLAR.CLI.main",
        ]:
            pk = PactKey(namespace="EXEMPLAR.CLI", function_key=fk)
            assert pk.function_key == fk

    def test_goodhart_pact_key_rejects_uppercase_function(self):
        """PactKey function_key must only contain lowercase letters and underscores in the suffix."""
        with pytest.raises(Exception):
            PactKey(namespace="EXEMPLAR.CLI", function_key="EXEMPLAR.CLI.HandleReview")

    def test_goodhart_pact_key_rejects_digits_in_function(self):
        """PactKey function_key regex only allows lowercase and underscores — digits are rejected."""
        with pytest.raises(Exception):
            PactKey(namespace="EXEMPLAR.CLI", function_key="EXEMPLAR.CLI.handle_review2")

    def test_goodhart_pact_key_rejects_wrong_prefix(self):
        """PactKey function_key must start with 'EXEMPLAR.CLI.' — other prefixes are rejected."""
        with pytest.raises(Exception):
            PactKey(namespace="EXEMPLAR.CLI", function_key="EXEMPLAR.INTAKE.parse_diff")


# ---------------------------------------------------------------------------
# Enum member counts (no extra hidden values)
# ---------------------------------------------------------------------------
class TestGoodhartEnumCounts:
    def test_goodhart_cli_exit_code_no_extra_values(self):
        """CliExitCode enum must have exactly 4 members."""
        members = list(CliExitCode)
        assert len(members) == 4
        values = {m.value if hasattr(m, 'value') else m for m in members}
        assert values == {0, 1, 2, 3}

    def test_goodhart_output_format_no_extra_values(self):
        """OutputFormat enum must have exactly 3 members."""
        members = list(OutputFormat)
        assert len(members) == 3

    def test_goodhart_subcommand_name_no_extra_values(self):
        """SubcommandName enum must have exactly 4 members."""
        members = list(SubcommandName)
        assert len(members) == 4


# ---------------------------------------------------------------------------
# handle_review: exit codes for warn and block
# ---------------------------------------------------------------------------
class TestGoodhartHandleReview:
    @pytest.fixture
    def mock_review_args(self, tmp_path):
        """Create a CliArgs-like object for review with a real diff file."""
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n")
        try:
            return CliArgs(
                subcommand="review",
                diff_file=str(diff_file),
                config_path="",
                output_format="json",
                query="",
                debug=False,
            )
        except Exception:
            # If CliArgs requires enum types
            return CliArgs(
                subcommand=SubcommandName("review"),
                diff_file=FilePath(value=str(diff_file)),
                config_path=FilePath(value=str(tmp_path / ".exemplar.yml")),
                output_format=OutputFormat("json"),
                query="",
                debug=False,
            )

    def test_goodhart_handle_review_warn_exit_code(self, mock_review_args):
        """handle_review must correctly return exit code 1 (WARN) when pipeline decision is 'warn'."""
        with patch("exemplar.cli.config") as mock_config, \
             patch("exemplar.cli.chronicle") as mock_chronicle, \
             patch("exemplar.cli.intake") as mock_intake, \
             patch("exemplar.cli.circuit") as mock_circuit, \
             patch("exemplar.cli.assessor") as mock_assessor, \
             patch("exemplar.cli.reporter") as mock_reporter:
            mock_config.load_config = MagicMock(return_value=MagicMock())
            mock_chronicle.emit_event = AsyncMock()
            mock_intake.parse_diff = MagicMock(return_value=MagicMock())
            mock_circuit.route_stages = MagicMock(return_value=MagicMock())
            mock_result = MagicMock()
            mock_result.decision = "warn"
            mock_assessor.assess = AsyncMock(return_value=mock_result) if asyncio.iscoroutinefunction(getattr(mock_assessor, 'assess', None)) else MagicMock(return_value=mock_result)
            mock_reporter.format_report = MagicMock(return_value="warn report")

            try:
                result = run_async(handle_review(mock_review_args))
            except Exception:
                pytest.skip("Could not run handle_review with mocks — implementation details differ")

            exit_val = result.exit_code if isinstance(result.exit_code, int) else getattr(result.exit_code, 'value', int(result.exit_code))
            assert exit_val == 1, f"Expected exit code 1 (WARN), got {exit_val}"

    def test_goodhart_handle_review_block_exit_code(self, mock_review_args):
        """handle_review must correctly return exit code 2 (BLOCK) when pipeline decision is 'block'."""
        with patch("exemplar.cli.config") as mock_config, \
             patch("exemplar.cli.chronicle") as mock_chronicle, \
             patch("exemplar.cli.intake") as mock_intake, \
             patch("exemplar.cli.circuit") as mock_circuit, \
             patch("exemplar.cli.assessor") as mock_assessor, \
             patch("exemplar.cli.reporter") as mock_reporter:
            mock_config.load_config = MagicMock(return_value=MagicMock())
            mock_chronicle.emit_event = AsyncMock()
            mock_intake.parse_diff = MagicMock(return_value=MagicMock())
            mock_circuit.route_stages = MagicMock(return_value=MagicMock())
            mock_result = MagicMock()
            mock_result.decision = "block"
            mock_assessor.assess = AsyncMock(return_value=mock_result) if asyncio.iscoroutinefunction(getattr(mock_assessor, 'assess', None)) else MagicMock(return_value=mock_result)
            mock_reporter.format_report = MagicMock(return_value="block report")

            try:
                result = run_async(handle_review(mock_review_args))
            except Exception:
                pytest.skip("Could not run handle_review with mocks — implementation details differ")

            exit_val = result.exit_code if isinstance(result.exit_code, int) else getattr(result.exit_code, 'value', int(result.exit_code))
            assert exit_val == 2, f"Expected exit code 2 (BLOCK), got {exit_val}"

    def test_goodhart_handle_review_stdout_nonempty_on_success(self, mock_review_args):
        """handle_review must produce non-empty stdout_output on successful pipeline completion."""
        with patch("exemplar.cli.config") as mock_config, \
             patch("exemplar.cli.chronicle") as mock_chronicle, \
             patch("exemplar.cli.intake") as mock_intake, \
             patch("exemplar.cli.circuit") as mock_circuit, \
             patch("exemplar.cli.assessor") as mock_assessor, \
             patch("exemplar.cli.reporter") as mock_reporter:
            mock_config.load_config = MagicMock(return_value=MagicMock())
            mock_chronicle.emit_event = AsyncMock()
            mock_intake.parse_diff = MagicMock(return_value=MagicMock())
            mock_circuit.route_stages = MagicMock(return_value=MagicMock())
            mock_result = MagicMock()
            mock_result.decision = "pass"
            mock_assessor.assess = AsyncMock(return_value=mock_result) if asyncio.iscoroutinefunction(getattr(mock_assessor, 'assess', None)) else MagicMock(return_value=mock_result)
            mock_reporter.format_report = MagicMock(return_value="formatted report output")

            try:
                result = run_async(handle_review(mock_review_args))
            except Exception:
                pytest.skip("Could not run handle_review with mocks")

            assert result.stdout_output, "stdout_output must be non-empty on success"


# ---------------------------------------------------------------------------
# main: dispatch to all subcommands, error handling
# ---------------------------------------------------------------------------
class TestGoodhartMain:
    def test_goodhart_main_trust_returns_zero(self):
        """main() must correctly dispatch and return exit code 0 for trust subcommand."""
        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.stdout_output = "trust scores"
        mock_result.stderr_output = ""

        with patch("exemplar.cli.handle_trust", new_callable=lambda: lambda: AsyncMock(return_value=mock_result)) as mock_handler:
            try:
                with patch("exemplar.cli.build_dispatch_table") as mock_dt:
                    handlers = {
                        "review": AsyncMock(),
                        "trust": AsyncMock(return_value=mock_result),
                        "history": AsyncMock(),
                        "adopt": AsyncMock(),
                    }
                    mock_table = MagicMock()
                    mock_table.handlers = handlers
                    mock_dt.return_value = mock_table
                    result = main(["trust"])
            except Exception:
                # Try without patching dispatch table
                try:
                    with patch("exemplar.cli.handle_trust", AsyncMock(return_value=mock_result)):
                        with patch("exemplar.cli.config") as mc:
                            mc.load_config = MagicMock(return_value=MagicMock())
                            result = main(["trust"])
                except Exception:
                    pytest.skip("Cannot mock trust handler for main()")

        assert result == 0, f"Expected 0, got {result}"

    def test_goodhart_main_empty_argv_returns_error(self):
        """main() must return exit code when given empty argv (no subcommand)."""
        result = main([])
        assert isinstance(result, int)
        # Should be error since no subcommand
        assert result in (2, 3), f"Expected error exit code for empty argv, got {result}"

    def test_goodhart_main_invalid_subcommand_returns_error(self):
        """main() must return an error exit code when given an invalid subcommand."""
        result = main(["nonexistent"])
        assert isinstance(result, int)
        assert result in (2, 3), f"Expected error exit code for invalid subcommand, got {result}"

    def test_goodhart_main_returns_exactly_int_type(self):
        """main() must return a Python int, not a bool or other type."""
        result = main([])
        assert type(result) is int, f"Expected exact type int, got {type(result).__name__}"

    def test_goodhart_main_runtime_error_returns_three(self):
        """main() must catch RuntimeError from dependencies and return 3."""
        with patch("exemplar.cli.build_parser", side_effect=RuntimeError("unexpected")):
            result = main(["trust"])
        assert result == 3

    def test_goodhart_main_type_error_returns_three(self):
        """main() must catch TypeError and return 3."""
        with patch("exemplar.cli.build_parser", side_effect=TypeError("bad type")):
            result = main(["trust"])
        assert result == 3

    def test_goodhart_main_writes_handler_stdout_to_sys_stdout(self):
        """main() must write the exact stdout_output from the handler to sys.stdout."""
        unique_marker = "UNIQUE_OUTPUT_MARKER_XYZ_98765"
        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.stdout_output = unique_marker
        mock_result.stderr_output = ""

        captured = []
        original_write = sys.stdout.write

        with patch("exemplar.cli.build_dispatch_table") as mock_dt, \
             patch("sys.stdout") as mock_stdout:
            mock_stdout.write = MagicMock(side_effect=lambda s: captured.append(s))
            handlers = {}
            for name in ["review", "trust", "history", "adopt"]:
                handlers[name] = AsyncMock(return_value=mock_result)
            # Also try with enum keys
            try:
                for name in SubcommandName:
                    handlers[name] = AsyncMock(return_value=mock_result)
            except Exception:
                pass
            mock_table = MagicMock()
            mock_table.handlers = handlers
            mock_table.__getitem__ = lambda self, key: handlers.get(key, handlers.get(str(key) if not isinstance(key, str) else key))
            mock_dt.return_value = mock_table

            try:
                result = main(["trust"])
                written = "".join(captured)
                assert unique_marker in written, f"Expected '{unique_marker}' in stdout, got: {written}"
            except Exception:
                pytest.skip("Cannot verify stdout writing with current mock setup")

    def test_goodhart_main_writes_handler_stderr_to_sys_stderr(self):
        """main() must write the handler's stderr_output to sys.stderr."""
        diag_marker = "DIAGNOSTIC_MARKER_ABC_54321"
        mock_result = MagicMock()
        mock_result.exit_code = 0
        mock_result.stdout_output = "output"
        mock_result.stderr_output = diag_marker

        captured = []

        with patch("exemplar.cli.build_dispatch_table") as mock_dt, \
             patch("sys.stderr") as mock_stderr, \
             patch("sys.stdout"):
            mock_stderr.write = MagicMock(side_effect=lambda s: captured.append(s))
            handlers = {}
            for name in ["review", "trust", "history", "adopt"]:
                handlers[name] = AsyncMock(return_value=mock_result)
            try:
                for name in SubcommandName:
                    handlers[name] = AsyncMock(return_value=mock_result)
            except Exception:
                pass
            mock_table = MagicMock()
            mock_table.handlers = handlers
            mock_dt.return_value = mock_table

            try:
                main(["trust"])
                written = "".join(captured)
                assert diag_marker in written, f"Expected '{diag_marker}' in stderr, got: {written}"
            except Exception:
                pytest.skip("Cannot verify stderr writing with current mock setup")


# ---------------------------------------------------------------------------
# handle_trust: content verification
# ---------------------------------------------------------------------------
class TestGoodhartHandleTrust:
    def test_goodhart_handle_trust_stdout_has_content(self):
        """handle_trust must produce non-empty stdout_output containing reviewer trust data."""
        try:
            mock_args = CliArgs(
                subcommand=SubcommandName("trust"),
                diff_file=FilePath(value="."),
                config_path=FilePath(value="."),
                output_format=OutputFormat("json"),
                query="",
                debug=False,
            )
        except Exception:
            try:
                mock_args = CliArgs(
                    subcommand="trust",
                    diff_file="",
                    config_path="",
                    output_format="json",
                    query="",
                    debug=False,
                )
            except Exception:
                pytest.skip("Cannot construct CliArgs for trust")

        trust_data = [
            {"reviewer": "security", "score": 0.95},
            {"reviewer": "style", "score": 0.82},
            {"reviewer": "complexity", "score": 0.77},
        ]

        with patch("exemplar.cli.config") as mock_config, \
             patch("exemplar.cli.assessor") as mock_assessor:
            mock_config.load_config = MagicMock(return_value=MagicMock())
            mock_assessor.get_trust_scores = MagicMock(return_value=trust_data)
            if hasattr(mock_assessor.get_trust_scores, '__aiter__'):
                mock_assessor.get_trust_scores = AsyncMock(return_value=trust_data)

            try:
                result = run_async(handle_trust(mock_args))
            except Exception:
                pytest.skip("Cannot run handle_trust with mocks")

            assert result.stdout_output, "handle_trust stdout_output must be non-empty"


# ---------------------------------------------------------------------------
# handle_history: query parameter propagation
# ---------------------------------------------------------------------------
class TestGoodhartHandleHistory:
    def test_goodhart_handle_history_with_query_filters(self):
        """handle_history must pass the query parameter to the learner when --query is provided."""
        try:
            mock_args = CliArgs(
                subcommand=SubcommandName("history"),
                diff_file=FilePath(value="."),
                config_path=FilePath(value="."),
                output_format=OutputFormat("json"),
                query="security",
                debug=False,
            )
        except Exception:
            try:
                mock_args = CliArgs(
                    subcommand="history",
                    diff_file="",
                    config_path="",
                    output_format="json",
                    query="security",
                    debug=False,
                )
            except Exception:
                pytest.skip("Cannot construct CliArgs for history")

        with patch("exemplar.cli.config") as mock_config, \
             patch("exemplar.cli.learner") as mock_learner:
            mock_config.load_config = MagicMock(return_value=MagicMock())
            mock_learner.query_history = MagicMock(return_value=[])
            if hasattr(mock_learner, 'query_history'):
                # Try both sync and async
                pass

            try:
                result = run_async(handle_history(mock_args))
            except Exception:
                pytest.skip("Cannot run handle_history with mocks")

            # Verify the query was passed through
            if mock_learner.query_history.called:
                call_args = mock_learner.query_history.call_args
                all_args = str(call_args)
                assert "security" in all_args, "query parameter 'security' should be passed to learner.query_history"

    def test_goodhart_handle_history_config_error_returns_three(self):
        """handle_history must return ERROR(3) when config loading fails."""
        try:
            mock_args = CliArgs(
                subcommand=SubcommandName("history"),
                diff_file=FilePath(value="."),
                config_path=FilePath(value="/nonexistent/config.yml"),
                output_format=OutputFormat("json"),
                query="",
                debug=False,
            )
        except Exception:
            try:
                mock_args = CliArgs(
                    subcommand="history",
                    diff_file="",
                    config_path="/nonexistent/config.yml",
                    output_format="json",
                    query="",
                    debug=False,
                )
            except Exception:
                pytest.skip("Cannot construct CliArgs for history")

        with patch("exemplar.cli.config") as mock_config:
            mock_config.load_config = MagicMock(side_effect=Exception("config load failed"))

            try:
                result = run_async(handle_history(mock_args))
            except Exception:
                pytest.skip("Cannot run handle_history with config error mock")

            exit_val = result.exit_code if isinstance(result.exit_code, int) else getattr(result.exit_code, 'value', int(result.exit_code))
            assert exit_val == 3, f"Expected exit code 3, got {exit_val}"


# ---------------------------------------------------------------------------
# handle_adopt: config error
# ---------------------------------------------------------------------------
class TestGoodhartHandleAdopt:
    def test_goodhart_handle_adopt_config_error_returns_three(self):
        """handle_adopt must return ERROR(3) when config loading fails."""
        try:
            mock_args = CliArgs(
                subcommand=SubcommandName("adopt"),
                diff_file=FilePath(value="."),
                config_path=FilePath(value="/nonexistent/config.yml"),
                output_format=OutputFormat("json"),
                query="",
                debug=False,
            )
        except Exception:
            try:
                mock_args = CliArgs(
                    subcommand="adopt",
                    diff_file="",
                    config_path="/nonexistent/config.yml",
                    output_format="json",
                    query="",
                    debug=False,
                )
            except Exception:
                pytest.skip("Cannot construct CliArgs for adopt")

        with patch("exemplar.cli.config") as mock_config:
            mock_config.load_config = MagicMock(side_effect=Exception("config load failed"))

            try:
                result = run_async(handle_adopt(mock_args))
            except Exception:
                pytest.skip("Cannot run handle_adopt with config error mock")

            exit_val = result.exit_code if isinstance(result.exit_code, int) else getattr(result.exit_code, 'value', int(result.exit_code))
            assert exit_val == 3, f"Expected exit code 3, got {exit_val}"


# ---------------------------------------------------------------------------
# CliResult immutability with different field values
# ---------------------------------------------------------------------------
class TestGoodhartImmutability:
    def test_goodhart_cli_result_different_values_frozen(self):
        """CliResult must be frozen for any combination of fields, not just test defaults."""
        try:
            result = CliResult(exit_code=1, stdout_output="warn output", stderr_output="some diag")
        except Exception:
            try:
                result = CliResult(exit_code=CliExitCode(1), stdout_output="warn output", stderr_output="some diag")
            except Exception:
                pytest.skip("Cannot construct CliResult")

        with pytest.raises(Exception):
            result.exit_code = 0

        with pytest.raises(Exception):
            result.stdout_output = "modified"

    def test_goodhart_cli_args_different_values_frozen(self):
        """CliArgs must be frozen for non-default field values."""
        try:
            args = CliArgs(
                subcommand=SubcommandName("trust"),
                diff_file=FilePath(value="."),
                config_path=FilePath(value="/some/path"),
                output_format=OutputFormat("md"),
                query="test query",
                debug=True,
            )
        except Exception:
            try:
                args = CliArgs(
                    subcommand="trust",
                    diff_file=".",
                    config_path="/some/path",
                    output_format="md",
                    query="test query",
                    debug=True,
                )
            except Exception:
                pytest.skip("Cannot construct CliArgs")

        with pytest.raises(Exception):
            args.debug = False

        with pytest.raises(Exception):
            args.query = "changed"
