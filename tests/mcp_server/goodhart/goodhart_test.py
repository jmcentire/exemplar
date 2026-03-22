"""
Adversarial hidden acceptance tests for MCP Server component.
These tests target gaps in visible test coverage to catch implementations
that hardcode returns or take shortcuts rather than truly satisfying the contract.
"""
import asyncio
import json
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel, ValidationError

# defensive import — original had invalid syntax (ternary in import)
try:
    from exemplar.mcp_server import BuildToolError  # noqa: F401
except ImportError:
    BuildToolError = None

# Attempt flexible imports to handle different module structures
try:
    from exemplar.mcp_server import (
        OutputFormat,
        ReviewToolInput,
        TrustToolInput,
        HistoryToolInput,
        ToolError,
        FieldError,
        McpContentBlock,
        McpToolResult,
        ServerConfig,
        create_server,
        run_server,
        handle_review,
        handle_trust,
        handle_history,
        build_tool_error,
        build_success_result,
    )
except ImportError:
    # Some types may be in sub-modules
    from exemplar.mcp_server import *


# ── Helpers ──────────────────────────────────────────────────────────────


def make_mock_pipeline():
    """Create a mock pipeline satisfying PipelineProtocol."""
    pipeline = AsyncMock()
    pipeline.run_review = AsyncMock(return_value=MagicMock(spec=BaseModel))
    pipeline.get_trust_scores = AsyncMock(return_value=[])
    pipeline.query_history = AsyncMock(return_value=[])
    return pipeline


def make_valid_config(**overrides):
    """Create a valid ServerConfig with sensible defaults."""
    defaults = {
        "server_name": "test-server",
        "server_version": "1.0.0",
        "enable_chronicler": False,
        "max_diff_size_bytes": 2048,
    }
    defaults.update(overrides)
    return ServerConfig(**defaults)


def parse_result_json(result):
    """Parse the JSON content from an McpToolResult."""
    assert len(result.content) == 1
    assert result.content[0].type == "text"
    return json.loads(result.content[0].text)


# ── ReviewToolInput validation tests ─────────────────────────────────────


class TestGoodhartReviewValidation:
    def test_goodhart_review_empty_diff_text_rejected(self):
        """diff_text with empty string should fail min=1 length validation"""
        with pytest.raises((ValidationError, ValueError)):
            ReviewToolInput(diff_text="", file_path=None)

    def test_goodhart_review_empty_file_path_rejected(self):
        """file_path with empty string should fail min=1 length validation"""
        with pytest.raises((ValidationError, ValueError)):
            ReviewToolInput(diff_text=None, file_path="")

    def test_goodhart_review_file_path_exactly_4096(self):
        """file_path at exactly 4096 chars should be accepted by the length validator"""
        path = "a" * 4096
        # Should not raise for length; may still need diff_text
        try:
            inp = ReviewToolInput(diff_text="x", file_path=path)
            assert len(inp.file_path) == 4096
        except ValidationError as e:
            # Only acceptable if error is NOT about length
            error_str = str(e)
            assert "length" not in error_str.lower() or "too long" not in error_str.lower()

    def test_goodhart_review_diff_text_exactly_1048576(self):
        """diff_text at exactly 1048576 chars (max boundary) should be accepted"""
        big_text = "x" * 1048576
        inp = ReviewToolInput(diff_text=big_text)
        assert len(inp.diff_text) == 1048576

    def test_goodhart_review_format_default_is_json(self):
        """ReviewToolInput should default format to json when not specified"""
        inp = ReviewToolInput(diff_text="some diff")
        assert inp.format == OutputFormat.json or str(inp.format).endswith("json")

    def test_goodhart_review_json_schema_has_all_fields(self):
        """model_json_schema() should include all four fields in properties"""
        schema = ReviewToolInput.model_json_schema()
        props = schema.get("properties", {})
        for field_name in ["diff_text", "file_path", "config_overrides", "format"]:
            assert field_name in props, f"Missing {field_name} in JSON schema properties"


class TestGoodhartReviewHandler:
    @pytest.mark.asyncio
    async def test_goodhart_review_both_diff_and_file(self, tmp_path):
        """When both diff_text and file_path are provided, handler should succeed"""
        diff_file = tmp_path / "test.diff"
        diff_file.write_text("file diff content")

        pipeline = make_mock_pipeline()
        config = make_valid_config()
        server = create_server(pipeline, config)

        inp = ReviewToolInput(
            diff_text="inline diff", file_path=str(diff_file)
        )
        result = await handle_review(inp)
        assert isinstance(result, McpToolResult)
        # Should not be an error about having both
        # (it's valid to provide both)

    @pytest.mark.asyncio
    async def test_goodhart_review_config_overrides_forwarded(self):
        """config_overrides should be passed through to the pipeline, not silently dropped"""
        pipeline = make_mock_pipeline()
        config = make_valid_config()
        server = create_server(pipeline, config)

        overrides = {"severity_threshold": "high", "skip_patterns": ["*.test.*"]}
        inp = ReviewToolInput(diff_text="some diff", config_overrides=overrides)
        result = await handle_review(inp)

        # The pipeline's run_review should have been called
        assert pipeline.run_review.called
        # Check that config_overrides were passed in some form
        call_args = pipeline.run_review.call_args
        all_args = str(call_args)
        # At minimum the overrides dict or its values should appear in the call
        assert "severity_threshold" in all_args or overrides == call_args.kwargs.get("config_overrides")

    @pytest.mark.asyncio
    async def test_goodhart_review_diff_one_byte_over_max(self):
        """Diff exceeding max_diff_size_bytes by exactly 1 byte must be rejected"""
        pipeline = make_mock_pipeline()
        config = make_valid_config(max_diff_size_bytes=1024)
        server = create_server(pipeline, config)

        inp = ReviewToolInput(diff_text="x" * 1025)
        result = await handle_review(inp)
        assert result.isError is True
        error_data = parse_result_json(result)
        # Should indicate the diff is too large
        assert "too_large" in error_data.get("error_type", "") or "too_large" in error_data.get("message", "").lower() or error_data.get("error_type") == "io_error"

    @pytest.mark.asyncio
    async def test_goodhart_review_file_diff_too_large(self, tmp_path):
        """When file content exceeds max_diff_size_bytes, handler should return diff_too_large error"""
        pipeline = make_mock_pipeline()
        config = make_valid_config(max_diff_size_bytes=1024)
        server = create_server(pipeline, config)

        big_file = tmp_path / "big.diff"
        big_file.write_text("x" * 2048)

        inp = ReviewToolInput(file_path=str(big_file))
        result = await handle_review(inp)
        assert result.isError is True
        error_data = parse_result_json(result)
        # Must detect oversized content from file, not just from diff_text
        assert "too_large" in error_data.get("error_type", "") or "too_large" in error_data.get("message", "").lower() or error_data.get("error_type") == "io_error"

    @pytest.mark.asyncio
    async def test_goodhart_review_chronicler_failure_does_not_block(self):
        """Chronicler failure should not prevent successful review completion"""
        pipeline = make_mock_pipeline()
        config = make_valid_config(enable_chronicler=True)
        server = create_server(pipeline, config)

        inp = ReviewToolInput(diff_text="some diff content")
        # Even with chronicler failures, the review should complete
        result = await handle_review(inp)
        # The handler must not propagate chronicler exceptions
        assert isinstance(result, McpToolResult)
        # If pipeline succeeded, result should not be an error
        if not pipeline.run_review.side_effect:
            assert result.isError is False

    @pytest.mark.asyncio
    async def test_goodhart_review_success_json_sorted_keys(self):
        """Successful review response must have deterministic sorted-key JSON"""
        pipeline = make_mock_pipeline()
        config = make_valid_config()
        server = create_server(pipeline, config)

        inp = ReviewToolInput(diff_text="diff content here")
        result = await handle_review(inp)
        if not result.isError:
            text = result.content[0].text
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                keys = list(parsed.keys())
                assert keys == sorted(keys), "JSON keys must be sorted for determinism"

    @pytest.mark.asyncio
    async def test_goodhart_review_error_content_type_always_text(self):
        """Error responses from handle_review must have content block type='text'"""
        pipeline = make_mock_pipeline()
        config = make_valid_config()
        server = create_server(pipeline, config)

        # Trigger a pipeline failure
        pipeline.run_review.side_effect = RuntimeError("boom")
        inp = ReviewToolInput(diff_text="some diff")
        result = await handle_review(inp)
        assert result.isError is True
        assert result.content[0].type == "text"


# ── TrustToolInput validation tests ──────────────────────────────────────


class TestGoodhartTrustValidation:
    def test_goodhart_trust_empty_reviewer_id_rejected(self):
        """Empty string reviewer_id must be rejected (regex requires min 1 char)"""
        with pytest.raises((ValidationError, ValueError)):
            TrustToolInput(reviewer_id="")

    def test_goodhart_trust_reviewer_id_with_spaces_rejected(self):
        """Reviewer ID containing spaces must be rejected by the regex"""
        with pytest.raises((ValidationError, ValueError)):
            TrustToolInput(reviewer_id="john doe")

    def test_goodhart_trust_reviewer_id_with_at_sign_rejected(self):
        """Reviewer ID with @ character must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            TrustToolInput(reviewer_id="user@domain")

    def test_goodhart_trust_reviewer_id_with_slash_rejected(self):
        """Reviewer ID with / character must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            TrustToolInput(reviewer_id="org/user")

    def test_goodhart_trust_reviewer_id_single_char(self):
        """Single character reviewer_id should be accepted"""
        inp = TrustToolInput(reviewer_id="x")
        assert inp.reviewer_id == "x"

    def test_goodhart_trust_reviewer_id_numeric_only(self):
        """Purely numeric reviewer_id should be accepted"""
        inp = TrustToolInput(reviewer_id="12345")
        assert inp.reviewer_id == "12345"

    def test_goodhart_trust_reviewer_id_129_chars_rejected(self):
        """Reviewer ID of 129 chars should be rejected (adjacent to 128 boundary)"""
        with pytest.raises((ValidationError, ValueError)):
            TrustToolInput(reviewer_id="a" * 129)


class TestGoodhartTrustHandler:
    @pytest.mark.asyncio
    async def test_goodhart_trust_result_is_json_list(self):
        """Successful trust response content must deserialize to a JSON list"""
        pipeline = make_mock_pipeline()
        config = make_valid_config()
        server = create_server(pipeline, config)

        inp = TrustToolInput()
        result = await handle_trust(inp)
        if not result.isError:
            data = json.loads(result.content[0].text)
            assert isinstance(data, list)

    @pytest.mark.asyncio
    async def test_goodhart_trust_handler_catches_runtime_error(self):
        """Trust handler must catch RuntimeError (not just specific exception types)"""
        pipeline = make_mock_pipeline()
        pipeline.get_trust_scores.side_effect = RuntimeError("unexpected crash")
        config = make_valid_config()
        server = create_server(pipeline, config)

        inp = TrustToolInput()
        # Must not raise
        result = await handle_trust(inp)
        assert isinstance(result, McpToolResult)
        assert result.isError is True

    @pytest.mark.asyncio
    async def test_goodhart_trust_handler_catches_type_error(self):
        """Trust handler must catch TypeError (catch-all for unexpected exceptions)"""
        pipeline = make_mock_pipeline()
        pipeline.get_trust_scores.side_effect = TypeError("bad type")
        config = make_valid_config()
        server = create_server(pipeline, config)

        inp = TrustToolInput()
        result = await handle_trust(inp)
        assert isinstance(result, McpToolResult)
        assert result.isError is True


# ── HistoryToolInput validation tests ────────────────────────────────────


class TestGoodhartHistoryValidation:
    def test_goodhart_history_negative_offset_rejected(self):
        """Negative offset must be rejected by min=0 range validator"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=-1)

    def test_goodhart_history_negative_limit_rejected(self):
        """Negative limit must be rejected by min=1 range validator"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=-1, offset=0)

    def test_goodhart_history_date_from_date_only_accepted(self):
        """Date-only format YYYY-MM-DD should be accepted for date_from"""
        inp = HistoryToolInput(limit=10, offset=0, date_from="2024-06-15")
        assert inp.date_from == "2024-06-15"

    def test_goodhart_history_date_to_utc_z_accepted(self):
        """Date with UTC Z suffix should be accepted"""
        inp = HistoryToolInput(limit=10, offset=0, date_to="2024-01-15T10:30:00Z")
        assert inp.date_to == "2024-01-15T10:30:00Z"

    def test_goodhart_history_date_slash_format_rejected(self):
        """Dates in slash format must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, date_from="01/15/2024")

    def test_goodhart_history_date_partial_time_rejected(self):
        """Dates with partial time (missing minutes/seconds) must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, date_from="2024-01-15T10")

    def test_goodhart_history_date_missing_seconds_rejected(self):
        """Dates with hours and minutes but no seconds must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, date_from="2024-01-15T10:30")

    def test_goodhart_history_kind_65_chars_rejected(self):
        """Kind string of 65 characters must be rejected (max is 64)"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, kind="a" * 65)

    def test_goodhart_history_kind_64_chars_accepted(self):
        """Kind string of exactly 64 characters should be accepted"""
        inp = HistoryToolInput(limit=10, offset=0, kind="a" * 64)
        assert len(inp.kind) == 64

    def test_goodhart_history_kind_with_dot_rejected(self):
        """Kind with dot character must be rejected (dots not in regex)"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, kind="review.type")

    def test_goodhart_history_kind_with_space_rejected(self):
        """Kind with space character must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, kind="my kind")

    def test_goodhart_history_kind_empty_rejected(self):
        """Empty kind string must be rejected (regex requires min 1 char)"""
        with pytest.raises((ValidationError, ValueError)):
            HistoryToolInput(limit=10, offset=0, kind="")

    def test_goodhart_history_date_to_only(self):
        """date_to without date_from should be accepted (both are independently optional)"""
        inp = HistoryToolInput(limit=10, offset=0, date_to="2024-12-31")
        assert inp.date_to == "2024-12-31"
        assert inp.date_from is None

    def test_goodhart_history_date_from_only(self):
        """date_from without date_to should be accepted"""
        inp = HistoryToolInput(limit=10, offset=0, date_from="2024-01-01")
        assert inp.date_from == "2024-01-01"
        assert inp.date_to is None

    def test_goodhart_history_limit_2_accepted(self):
        """limit=2 (non-boundary valid value) should be accepted"""
        inp = HistoryToolInput(limit=2, offset=0)
        assert inp.limit == 2

    def test_goodhart_history_limit_250_accepted(self):
        """limit=250 (mid-range value) should be accepted"""
        inp = HistoryToolInput(limit=250, offset=50)
        assert inp.limit == 250
        assert inp.offset == 50

    def test_goodhart_history_limit_499_accepted(self):
        """limit=499 (one below max, adjacent boundary) should be accepted"""
        inp = HistoryToolInput(limit=499, offset=0)
        assert inp.limit == 499

    def test_goodhart_history_offset_99999_accepted(self):
        """offset=99999 (one below max) should be accepted"""
        inp = HistoryToolInput(limit=10, offset=99999)
        assert inp.offset == 99999

    def test_goodhart_history_date_with_negative_offset(self):
        """Date with negative timezone offset should be accepted"""
        inp = HistoryToolInput(limit=10, offset=0, date_from="2024-01-15T10:30:00-05:00")
        assert inp.date_from == "2024-01-15T10:30:00-05:00"

    def test_goodhart_history_date_with_positive_offset(self):
        """Date with positive timezone offset should be accepted"""
        inp = HistoryToolInput(limit=10, offset=0, date_to="2024-01-15T10:30:00+09:00")
        assert inp.date_to == "2024-01-15T10:30:00+09:00"


class TestGoodhartHistoryHandler:
    @pytest.mark.asyncio
    async def test_goodhart_history_handler_catches_type_error(self):
        """History handler must catch TypeError and return isError=True"""
        pipeline = make_mock_pipeline()
        pipeline.query_history.side_effect = TypeError("bad argument")
        config = make_valid_config()
        server = create_server(pipeline, config)

        inp = HistoryToolInput(limit=10, offset=0)
        result = await handle_history(inp)
        assert isinstance(result, McpToolResult)
        assert result.isError is True


# ── ServerConfig validation tests ────────────────────────────────────────


class TestGoodhartServerConfig:
    def test_goodhart_server_config_name_with_space_rejected(self):
        """ServerConfig server_name with space must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="my server",
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )

    def test_goodhart_server_config_name_with_dot_rejected(self):
        """ServerConfig server_name with dot must be rejected (dots not in regex)"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="my.server",
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )

    def test_goodhart_server_config_empty_name_rejected(self):
        """ServerConfig empty server_name must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="",
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )

    def test_goodhart_server_config_65_char_name_rejected(self):
        """ServerConfig server_name of 65 chars must be rejected (max is 64)"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="a" * 65,
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )

    def test_goodhart_server_config_64_char_name_accepted(self):
        """ServerConfig server_name of exactly 64 chars should be accepted"""
        config = ServerConfig(
            server_name="a" * 64,
            server_version="1.0.0",
            enable_chronicler=False,
            max_diff_size_bytes=2048,
        )
        assert len(config.server_name) == 64

    def test_goodhart_server_config_version_prerelease(self):
        """ServerConfig should accept semver with prerelease suffix"""
        config = ServerConfig(
            server_name="test",
            server_version="1.0.0-beta.1",
            enable_chronicler=False,
            max_diff_size_bytes=2048,
        )
        assert config.server_version == "1.0.0-beta.1"

    def test_goodhart_server_config_version_alpha(self):
        """ServerConfig should accept semver with alpha prerelease"""
        config = ServerConfig(
            server_name="test",
            server_version="2.1.3-alpha",
            enable_chronicler=False,
            max_diff_size_bytes=2048,
        )
        assert config.server_version == "2.1.3-alpha"

    def test_goodhart_server_config_max_diff_1023_rejected(self):
        """max_diff_size_bytes=1023 (one below min) must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="test",
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=1023,
            )

    def test_goodhart_server_config_max_diff_10485761_rejected(self):
        """max_diff_size_bytes=10485761 (one above max) must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="test",
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=10485761,
            )

    def test_goodhart_server_config_version_no_patch_rejected(self):
        """ServerConfig should reject version without patch number like '1.0'"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="test",
                server_version="1.0",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )

    def test_goodhart_server_config_version_just_number_rejected(self):
        """ServerConfig should reject version that's just a number like '1'"""
        with pytest.raises((ValidationError, ValueError)):
            ServerConfig(
                server_name="test",
                server_version="1",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )


# ── create_server tests ──────────────────────────────────────────────────


class TestGoodhartCreateServer:
    def test_goodhart_create_server_tool_names_exact(self):
        """Registered tools must be exactly exemplar_review, exemplar_trust, exemplar_history"""
        pipeline = make_mock_pipeline()
        config = make_valid_config()
        server = create_server(pipeline, config)

        # Get registered tool names (implementation-dependent access)
        # Try common ways to inspect registered tools
        tools = None
        if hasattr(server, "list_tools"):
            # mcp.Server may expose tools via list_tools
            tools_result = server.list_tools()
            if asyncio.iscoroutine(tools_result):
                tools_result = asyncio.get_event_loop().run_until_complete(tools_result)
            if hasattr(tools_result, 'tools'):
                tools = {t.name for t in tools_result.tools}
            elif isinstance(tools_result, list):
                tools = {t.name if hasattr(t, 'name') else t for t in tools_result}
        
        if tools is not None:
            expected = {"exemplar_review", "exemplar_trust", "exemplar_history"}
            assert tools == expected, f"Expected tools {expected}, got {tools}"

    def test_goodhart_create_server_pipeline_missing_query_history(self):
        """Pipeline missing query_history method must be rejected"""
        pipeline = MagicMock()
        pipeline.run_review = AsyncMock()
        pipeline.get_trust_scores = AsyncMock()
        # Deliberately remove query_history
        if hasattr(pipeline, "query_history"):
            delattr(pipeline, "query_history")
        pipeline.spec = None

        config = make_valid_config()
        with pytest.raises(Exception):
            create_server(pipeline, config)

    def test_goodhart_create_server_pipeline_missing_run_review(self):
        """Pipeline missing run_review method must be rejected"""
        pipeline = MagicMock()
        pipeline.get_trust_scores = AsyncMock()
        pipeline.query_history = AsyncMock()
        if hasattr(pipeline, "run_review"):
            delattr(pipeline, "run_review")
        pipeline.spec = None

        config = make_valid_config()
        with pytest.raises(Exception):
            create_server(pipeline, config)

    def test_goodhart_create_server_pipeline_missing_get_trust_scores(self):
        """Pipeline missing get_trust_scores method must be rejected"""
        pipeline = MagicMock()
        pipeline.run_review = AsyncMock()
        pipeline.query_history = AsyncMock()
        if hasattr(pipeline, "get_trust_scores"):
            delattr(pipeline, "get_trust_scores")
        pipeline.spec = None

        config = make_valid_config()
        with pytest.raises(Exception):
            create_server(pipeline, config)


# ── build_tool_error tests ───────────────────────────────────────────────


class TestGoodhartBuildToolError:
    def test_goodhart_build_tool_error_all_error_types(self):
        """All four valid error_type values must be accepted"""
        for error_type in ("validation_error", "pipeline_error", "io_error", "internal_error"):
            result = build_tool_error(
                error_type=error_type,
                message=f"Test {error_type}",
                pact_key="mcp_server.test",
            )
            assert result.isError is True
            data = json.loads(result.content[0].text)
            assert data["error_type"] == error_type

    def test_goodhart_build_tool_error_invalid_error_type_rejected(self):
        """error_type not in the allowed set must cause an error"""
        with pytest.raises((ValidationError, ValueError, Exception)):
            build_tool_error(
                error_type="timeout_error",
                message="timed out",
                pact_key="mcp_server.test",
            )

    def test_goodhart_build_tool_error_unknown_error_type_rejected(self):
        """error_type='unknown_error' must be rejected"""
        with pytest.raises((ValidationError, ValueError, Exception)):
            build_tool_error(
                error_type="unknown_error",
                message="unknown",
                pact_key="mcp_server.test",
            )

    def test_goodhart_build_tool_error_empty_message_rejected(self):
        """Empty message string must be rejected by min=1 length validator"""
        with pytest.raises((ValidationError, ValueError, Exception)):
            build_tool_error(
                error_type="internal_error",
                message="",
                pact_key="mcp_server.test",
            )

    def test_goodhart_build_tool_error_preserves_field_error_details(self):
        """Field errors should preserve all detail fields: field, message, input_value"""
        field_errors = [
            FieldError(field="diff_text", message="too short", input_value=""),
            FieldError(field="limit", message="out of range", input_value="-1"),
        ]
        result = build_tool_error(
            error_type="validation_error",
            message="Validation failed",
            pact_key="mcp_server.handle_review",
            field_errors=field_errors,
        )
        data = json.loads(result.content[0].text)
        assert len(data["field_errors"]) == 2
        assert data["field_errors"][0]["field"] == "diff_text"
        assert data["field_errors"][1]["field"] == "limit"
        assert data["field_errors"][1]["input_value"] == "-1"


# ── build_success_result tests ───────────────────────────────────────────


class TestGoodhartBuildSuccessResult:
    def test_goodhart_build_success_result_empty_list(self):
        """Empty list of models should serialize to '[]'"""
        result = build_success_result([])
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert data == []

    def test_goodhart_build_success_result_deterministic_with_novel_model(self):
        """Deterministic sorted-key JSON must work for any Pydantic model, not just known ones"""

        class ZetaModel(BaseModel):
            z_field: str = "z"
            a_field: str = "a"
            m_field: str = "m"

        result = build_success_result(ZetaModel())
        text = result.content[0].text
        data = json.loads(text)
        keys = list(data.keys())
        assert keys == sorted(keys), f"Keys {keys} are not sorted"

    def test_goodhart_build_success_result_dict_rejected(self):
        """Plain dict (not Pydantic model) must be rejected"""
        with pytest.raises(Exception):
            build_success_result({"key": "value"})

    def test_goodhart_build_success_result_string_rejected(self):
        """Plain string must be rejected"""
        with pytest.raises(Exception):
            build_success_result("hello")

    def test_goodhart_build_success_result_none_rejected(self):
        """None must be rejected"""
        with pytest.raises(Exception):
            build_success_result(None)

    def test_goodhart_build_success_result_list_of_dicts_rejected(self):
        """List of plain dicts (not Pydantic models) must be rejected"""
        with pytest.raises(Exception):
            build_success_result([{"key": "value"}])


# ── McpContentBlock validation tests ─────────────────────────────────────


class TestGoodhartMcpContentBlock:
    def test_goodhart_content_block_type_json_rejected(self):
        """McpContentBlock with type='json' must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            McpContentBlock(type="json", text="{}")

    def test_goodhart_content_block_type_html_rejected(self):
        """McpContentBlock with type='html' must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            McpContentBlock(type="html", text="<p>hi</p>")

    def test_goodhart_content_block_type_image_rejected(self):
        """McpContentBlock with type='image' must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            McpContentBlock(type="image", text="base64data")

    def test_goodhart_content_block_type_empty_rejected(self):
        """McpContentBlock with type='' (empty) must be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            McpContentBlock(type="", text="content")


# ── OutputFormat enum tests ──────────────────────────────────────────────


class TestGoodhartOutputFormat:
    def test_goodhart_output_format_no_extra_values(self):
        """OutputFormat must have exactly 3 members, no hidden extras"""
        members = list(OutputFormat)
        assert len(members) == 3
        member_values = {m.value if hasattr(m, 'value') else str(m) for m in members}
        # Must contain json, md, github in some form
        assert any("json" in str(v).lower() for v in member_values)
        assert any("md" in str(v).lower() for v in member_values)
        assert any("github" in str(v).lower() for v in member_values)

    def test_goodhart_output_format_invalid_value_rejected(self):
        """OutputFormat should reject invalid format values like 'xml' or 'html'"""
        with pytest.raises((ValueError, KeyError)):
            OutputFormat("xml")


# ── Frozen model invariant tests ─────────────────────────────────────────


class TestGoodhartFrozenModels:
    def test_goodhart_frozen_history_tool_input_limit(self):
        """HistoryToolInput limit field must be immutable after construction"""
        inp = HistoryToolInput(limit=10, offset=0)
        with pytest.raises(Exception):
            inp.limit = 20

    def test_goodhart_frozen_history_tool_input_offset(self):
        """HistoryToolInput offset field must be immutable after construction"""
        inp = HistoryToolInput(limit=10, offset=0)
        with pytest.raises(Exception):
            inp.offset = 5

    def test_goodhart_frozen_review_tool_input_format(self):
        """ReviewToolInput format field must be immutable after construction"""
        inp = ReviewToolInput(diff_text="x")
        with pytest.raises(Exception):
            inp.format = OutputFormat.md

    def test_goodhart_frozen_tool_error(self):
        """ToolError must be frozen (immutable)"""
        err = ToolError(
            error_type="internal_error",
            message="test",
            pact_key="mcp_server.test",
        )
        with pytest.raises(Exception):
            err.message = "changed"

    def test_goodhart_frozen_server_config(self):
        """ServerConfig should be immutable if it follows the frozen pattern"""
        config = make_valid_config()
        # Attempt to mutate
        try:
            config.server_name = "hacked"
            # If this succeeds, ServerConfig might not be frozen
            # (not explicitly stated as frozen in contract, but worth checking)
        except Exception:
            pass  # Expected if frozen


# ── ToolError validation tests ───────────────────────────────────────────


class TestGoodhartToolError:
    def test_goodhart_tool_error_message_max_4096(self):
        """ToolError message at exactly 4096 chars should be accepted"""
        err = ToolError(
            error_type="internal_error",
            message="x" * 4096,
            pact_key="mcp_server.test",
        )
        assert len(err.message) == 4096

    def test_goodhart_tool_error_message_over_4096_rejected(self):
        """ToolError message exceeding 4096 chars should be rejected"""
        with pytest.raises((ValidationError, ValueError)):
            ToolError(
                error_type="internal_error",
                message="x" * 4097,
                pact_key="mcp_server.test",
            )
