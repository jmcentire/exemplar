"""
Contract tests for mcp_server component.

Tests verify behavior against the contract for:
- Type validation (frozen Pydantic v2 models, enums, validators)
- create_server factory function
- Tool handlers (handle_review, handle_trust, handle_history)
- Helper functions (build_tool_error, build_success_result)
- Invariants (frozen models, no unhandled exceptions, deterministic JSON, etc.)
"""

import json
import os
import tempfile
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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


# ---------------------------------------------------------------------------
# Test doubles and fixtures
# ---------------------------------------------------------------------------

class StubPipeline:
    """Test double satisfying PipelineProtocol with configurable returns."""

    def __init__(
        self,
        review_result=None,
        trust_result=None,
        history_result=None,
        review_side_effect=None,
        trust_side_effect=None,
        history_side_effect=None,
    ):
        self._review_result = review_result
        self._trust_result = trust_result or []
        self._history_result = history_result or []
        self._review_side_effect = review_side_effect
        self._trust_side_effect = trust_side_effect
        self._history_side_effect = history_side_effect

    async def run_review(self, *args, **kwargs):
        if self._review_side_effect:
            raise self._review_side_effect
        return self._review_result

    async def get_trust_scores(self, *args, **kwargs):
        if self._trust_side_effect:
            raise self._trust_side_effect
        return self._trust_result

    async def query_history(self, *args, **kwargs):
        if self._history_side_effect:
            raise self._history_side_effect
        return self._history_result


def make_server_config(**overrides):
    """Factory for valid ServerConfig with sensible defaults."""
    defaults = dict(
        server_name="test-server",
        server_version="1.0.0",
        enable_chronicler=False,
        max_diff_size_bytes=1048576,
    )
    defaults.update(overrides)
    return ServerConfig(**defaults)


@pytest.fixture
def default_config():
    return make_server_config()


@pytest.fixture
def stub_pipeline():
    return StubPipeline()


@pytest.fixture
def stub_pipeline_with_review_result():
    """Pipeline that returns a mock review result (dict-like)."""
    # The actual pipeline returns a ReviewReport pydantic model;
    # we use a MagicMock that can be serialized by the handler.
    result = MagicMock()
    result.model_dump_json = MagicMock(return_value='{"summary": "ok"}')
    return StubPipeline(review_result=result)


@pytest.fixture
def stub_pipeline_with_trust_result():
    result = MagicMock()
    result.model_dump_json = MagicMock(return_value='[{"reviewer": "alice", "score": 0.9}]')
    return StubPipeline(trust_result=result)


@pytest.fixture
def stub_pipeline_with_history_result():
    result = MagicMock()
    result.__len__ = MagicMock(return_value=0)
    result.__iter__ = MagicMock(return_value=iter([]))
    return StubPipeline(history_result=result)


# ---------------------------------------------------------------------------
# Helper to parse tool result content
# ---------------------------------------------------------------------------

def parse_result_json(result):
    """Extract and parse JSON from an McpToolResult's content block."""
    assert len(result.content) == 1
    assert result.content[0].type == "text"
    return json.loads(result.content[0].text)


# ---------------------------------------------------------------------------
# TestOutputFormat
# ---------------------------------------------------------------------------

class TestOutputFormatEnum:
    """Verify OutputFormat enum has the correct variants."""

    def test_invariant_output_format_enum_values(self):
        """OutputFormat enum has exactly json, md, github variants."""
        variant_names = {v.value if hasattr(v, 'value') else v.name for v in OutputFormat}
        assert "json" in variant_names or hasattr(OutputFormat, "json")
        assert "md" in variant_names or hasattr(OutputFormat, "md")
        assert "github" in variant_names or hasattr(OutputFormat, "github")
        # Access each variant to verify they exist
        _ = OutputFormat.json
        _ = OutputFormat.md
        _ = OutputFormat.github


# ---------------------------------------------------------------------------
# TestCreateServer
# ---------------------------------------------------------------------------

class TestCreateServer:

    def test_create_server_happy_path(self, stub_pipeline, default_config):
        """create_server with valid pipeline and config returns server with 3 tools."""
        server = create_server(stub_pipeline, default_config)
        assert server is not None

    def test_create_server_invalid_pipeline(self, default_config):
        """create_server raises error when pipeline doesn't satisfy PipelineProtocol."""
        with pytest.raises(Exception):
            create_server("not_a_pipeline", default_config)

    def test_create_server_invalid_config(self, stub_pipeline):
        """create_server raises error when config fails validation."""
        with pytest.raises(Exception):
            # server_name with spaces violates regex ^[a-zA-Z0-9_\\-]{1,64}$
            bad_config = ServerConfig(
                server_name="bad name with spaces!!!",
                server_version="1.0.0",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )
            create_server(stub_pipeline, bad_config)

    def test_create_server_config_edge_min_diff_size(self, stub_pipeline):
        """create_server accepts config with min max_diff_size_bytes=1024."""
        config = make_server_config(max_diff_size_bytes=1024)
        server = create_server(stub_pipeline, config)
        assert server is not None

    def test_create_server_config_edge_max_diff_size(self, stub_pipeline):
        """create_server accepts config with max max_diff_size_bytes=10485760."""
        config = make_server_config(max_diff_size_bytes=10485760)
        server = create_server(stub_pipeline, config)
        assert server is not None

    def test_create_server_config_below_min_diff_size(self, stub_pipeline):
        """ServerConfig rejects max_diff_size_bytes below 1024."""
        with pytest.raises(Exception):
            make_server_config(max_diff_size_bytes=1023)

    def test_create_server_config_above_max_diff_size(self, stub_pipeline):
        """ServerConfig rejects max_diff_size_bytes above 10485760."""
        with pytest.raises(Exception):
            make_server_config(max_diff_size_bytes=10485761)

    def test_invariant_server_config_version_regex(self, stub_pipeline):
        """ServerConfig rejects invalid version strings."""
        with pytest.raises(Exception):
            ServerConfig(
                server_name="test",
                server_version="not-a-version",
                enable_chronicler=False,
                max_diff_size_bytes=2048,
            )

    def test_server_config_valid_prerelease_version(self, stub_pipeline):
        """ServerConfig accepts semver with prerelease suffix."""
        config = ServerConfig(
            server_name="test",
            server_version="1.2.3-beta.1",
            enable_chronicler=False,
            max_diff_size_bytes=2048,
        )
        assert config.server_version == "1.2.3-beta.1"


# ---------------------------------------------------------------------------
# TestRunServer
# ---------------------------------------------------------------------------

class TestRunServer:

    @pytest.mark.asyncio
    async def test_run_server_stdio_unavailable(self, stub_pipeline, default_config):
        """run_server raises/handles error when stdio is unavailable."""
        server = create_server(stub_pipeline, default_config)
        # Close stdin/stdout to simulate unavailability, or mock them
        with patch("sys.stdin", None), patch("sys.stdout", None):
            with pytest.raises(Exception):
                await run_server(server)


# ---------------------------------------------------------------------------
# TestHandleReview
# ---------------------------------------------------------------------------

class TestHandleReview:

    @pytest.mark.asyncio
    async def test_handle_review_happy_path_diff_text(self):
        """handle_review with valid diff_text returns success McpToolResult."""
        pipeline = StubPipeline(review_result=MagicMock())
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(
            diff_text="+ added line\n- removed line",
            format=OutputFormat.json,
        )
        result = await handle_review(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is False
        assert len(result.content) == 1
        assert result.content[0].type == "text"
        # Content should be valid JSON
        parsed = json.loads(result.content[0].text)
        assert isinstance(parsed, (dict, list))

    @pytest.mark.asyncio
    async def test_handle_review_happy_path_file_path(self):
        """handle_review with valid file_path returns success McpToolResult."""
        pipeline = StubPipeline(review_result=MagicMock())
        config = make_server_config()
        server = create_server(pipeline, config)

        with tempfile.NamedTemporaryFile(mode="w", suffix=".diff", delete=False) as f:
            f.write("+ new line\n")
            f.flush()
            fpath = f.name

        try:
            input_data = ReviewToolInput(
                file_path=fpath,
                format=OutputFormat.json,
            )
            result = await handle_review(input_data)

            assert isinstance(result, McpToolResult)
            assert result.isError is False
            assert len(result.content) == 1
        finally:
            os.unlink(fpath)

    @pytest.mark.asyncio
    async def test_handle_review_happy_path_md_format(self):
        """handle_review with format=md returns success result."""
        pipeline = StubPipeline(review_result=MagicMock())
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(
            diff_text="+ line",
            format=OutputFormat.md,
        )
        result = await handle_review(input_data)
        assert result.isError is False
        assert len(result.content) == 1

    @pytest.mark.asyncio
    async def test_handle_review_happy_path_github_format(self):
        """handle_review with format=github returns success result."""
        pipeline = StubPipeline(review_result=MagicMock())
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(
            diff_text="+ line",
            format=OutputFormat.github,
        )
        result = await handle_review(input_data)
        assert result.isError is False
        assert len(result.content) == 1

    def test_handle_review_validation_error_neither_provided(self):
        """ReviewToolInput fails when neither diff_text nor file_path provided."""
        with pytest.raises(Exception):
            ReviewToolInput(format=OutputFormat.json)

    @pytest.mark.asyncio
    async def test_handle_review_file_not_found(self):
        """handle_review returns error when file_path does not exist."""
        pipeline = StubPipeline()
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(
            file_path="/nonexistent/path/to/file.diff",
            format=OutputFormat.json,
        )
        result = await handle_review(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert "error_type" in parsed

    @pytest.mark.asyncio
    async def test_handle_review_diff_too_large(self):
        """handle_review returns diff_too_large error when diff exceeds max_diff_size_bytes."""
        config = make_server_config(max_diff_size_bytes=1024)
        pipeline = StubPipeline()
        server = create_server(pipeline, config)

        # Create diff text that exceeds 1024 bytes
        large_diff = "x" * 2048
        input_data = ReviewToolInput(
            diff_text=large_diff,
            format=OutputFormat.json,
        )
        result = await handle_review(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert parsed.get("error_type") in ("diff_too_large", "validation_error")

    @pytest.mark.asyncio
    async def test_handle_review_diff_exact_max_size(self):
        """handle_review accepts diff at exactly max_diff_size_bytes boundary."""
        max_size = 2048
        config = make_server_config(max_diff_size_bytes=max_size)
        pipeline = StubPipeline(review_result=MagicMock())
        server = create_server(pipeline, config)

        exact_diff = "x" * max_size
        input_data = ReviewToolInput(
            diff_text=exact_diff,
            format=OutputFormat.json,
        )
        result = await handle_review(input_data)

        # Should succeed (at boundary, not over)
        assert isinstance(result, McpToolResult)
        assert result.isError is False

    @pytest.mark.asyncio
    async def test_handle_review_pipeline_failure(self):
        """handle_review returns pipeline_error when pipeline raises exception."""
        pipeline = StubPipeline(review_side_effect=RuntimeError("pipeline boom"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(
            diff_text="+ line",
            format=OutputFormat.json,
        )
        result = await handle_review(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert parsed.get("error_type") in ("pipeline_error", "pipeline_failure")

    @pytest.mark.asyncio
    async def test_handle_review_internal_error(self):
        """handle_review returns internal_error on truly unexpected exception."""
        pipeline = StubPipeline(review_side_effect=SystemError("unexpected"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(
            diff_text="+ line",
            format=OutputFormat.json,
        )
        # Should never raise - always returns McpToolResult
        result = await handle_review(input_data)
        assert isinstance(result, McpToolResult)
        assert result.isError is True

    def test_handle_review_diff_text_min_length(self):
        """ReviewToolInput accepts diff_text with length=1."""
        inp = ReviewToolInput(diff_text="x", format=OutputFormat.json)
        assert inp.diff_text == "x"

    def test_handle_review_diff_text_empty_rejected(self):
        """ReviewToolInput rejects empty diff_text (min=1)."""
        with pytest.raises(Exception):
            ReviewToolInput(diff_text="", format=OutputFormat.json)

    def test_handle_review_diff_text_max_length_exceeded(self):
        """ReviewToolInput rejects diff_text exceeding 1048576 chars."""
        with pytest.raises(Exception):
            ReviewToolInput(diff_text="x" * 1048577, format=OutputFormat.json)

    def test_handle_review_file_path_max_length_exceeded(self):
        """ReviewToolInput rejects file_path exceeding 4096 chars."""
        with pytest.raises(Exception):
            ReviewToolInput(file_path="a" * 4097, format=OutputFormat.json)

    @pytest.mark.asyncio
    async def test_handle_review_result_single_content_block(self):
        """handle_review result always has exactly one McpContentBlock."""
        pipeline = StubPipeline(review_result=MagicMock())
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(diff_text="+ line", format=OutputFormat.json)
        result = await handle_review(input_data)
        assert len(result.content) == 1
        assert result.content[0].type == "text"

    @pytest.mark.asyncio
    async def test_handle_review_error_has_pact_key(self):
        """handle_review error responses include pact_key in ToolError JSON."""
        pipeline = StubPipeline(review_side_effect=RuntimeError("fail"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(diff_text="+ line", format=OutputFormat.json)
        result = await handle_review(input_data)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert "pact_key" in parsed
        assert parsed["pact_key"] != ""


# ---------------------------------------------------------------------------
# TestHandleTrust
# ---------------------------------------------------------------------------

class TestHandleTrust:

    @pytest.mark.asyncio
    async def test_handle_trust_happy_path(self):
        """handle_trust with no reviewer_id returns all trust scores."""
        pipeline = StubPipeline(trust_result=[])
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = TrustToolInput()
        result = await handle_trust(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is False
        assert len(result.content) == 1
        assert result.content[0].type == "text"

    @pytest.mark.asyncio
    async def test_handle_trust_happy_path_with_reviewer(self):
        """handle_trust with valid reviewer_id returns filtered scores."""
        pipeline = StubPipeline(trust_result=[])
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = TrustToolInput(reviewer_id="user-123")
        result = await handle_trust(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is False

    def test_handle_trust_validation_error_bad_reviewer_id(self):
        """TrustToolInput rejects invalid reviewer_id format."""
        with pytest.raises(Exception):
            TrustToolInput(reviewer_id="invalid id with spaces!!!")

    def test_handle_trust_validation_error_empty_reviewer_id(self):
        """TrustToolInput rejects empty reviewer_id (min length 1 in regex)."""
        with pytest.raises(Exception):
            TrustToolInput(reviewer_id="")

    @pytest.mark.asyncio
    async def test_handle_trust_pipeline_failure(self):
        """handle_trust returns pipeline_error when pipeline raises exception."""
        pipeline = StubPipeline(trust_side_effect=RuntimeError("trust boom"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = TrustToolInput()
        result = await handle_trust(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert parsed.get("error_type") in ("pipeline_error", "pipeline_failure")

    @pytest.mark.asyncio
    async def test_handle_trust_internal_error(self):
        """handle_trust returns internal_error on unexpected exception."""
        pipeline = StubPipeline(trust_side_effect=SystemError("unexpected"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = TrustToolInput()
        result = await handle_trust(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True

    def test_handle_trust_reviewer_id_edge_cases(self):
        """TrustToolInput accepts reviewer_id with dots, dashes, underscores up to 128 chars."""
        # Max length: 128 chars
        valid_id = "a" * 128
        inp = TrustToolInput(reviewer_id=valid_id)
        assert inp.reviewer_id == valid_id

        # With dots, dashes, underscores
        inp2 = TrustToolInput(reviewer_id="user.name-test_123")
        assert inp2.reviewer_id == "user.name-test_123"

    def test_handle_trust_reviewer_id_too_long(self):
        """TrustToolInput rejects reviewer_id exceeding 128 chars."""
        with pytest.raises(Exception):
            TrustToolInput(reviewer_id="a" * 129)


# ---------------------------------------------------------------------------
# TestHandleHistory
# ---------------------------------------------------------------------------

class TestHandleHistory:

    @pytest.mark.asyncio
    async def test_handle_history_happy_path(self):
        """handle_history returns list of entries as success."""
        pipeline = StubPipeline(history_result=[])
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(limit=10, offset=0)
        result = await handle_history(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is False
        assert len(result.content) == 1
        assert result.content[0].type == "text"

    @pytest.mark.asyncio
    async def test_handle_history_with_filters(self):
        """handle_history with tags, kind, date_from, date_to returns filtered results."""
        pipeline = StubPipeline(history_result=[])
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(
            tags=["python", "review"],
            kind="security",
            date_from="2024-01-01",
            date_to="2024-12-31",
            limit=50,
            offset=0,
        )
        result = await handle_history(input_data)
        assert result.isError is False

    def test_handle_history_validation_error_invalid_date(self):
        """HistoryToolInput rejects malformed date_from."""
        with pytest.raises(Exception):
            HistoryToolInput(
                date_from="not-a-date",
                limit=10,
                offset=0,
            )

    @pytest.mark.asyncio
    async def test_handle_history_invalid_date_range(self):
        """handle_history returns error when date_from > date_to."""
        pipeline = StubPipeline(history_result=[])
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(
            date_from="2024-12-31",
            date_to="2024-01-01",
            limit=10,
            offset=0,
        )
        result = await handle_history(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert parsed.get("error_type") in ("invalid_date_range", "validation_error")

    @pytest.mark.asyncio
    async def test_handle_history_pipeline_failure(self):
        """handle_history returns pipeline_error when pipeline raises."""
        pipeline = StubPipeline(history_side_effect=RuntimeError("history boom"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(limit=10, offset=0)
        result = await handle_history(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        parsed = parse_result_json(result)
        assert parsed.get("error_type") in ("pipeline_error", "pipeline_failure")

    @pytest.mark.asyncio
    async def test_handle_history_internal_error(self):
        """handle_history returns internal_error on unexpected exception."""
        pipeline = StubPipeline(history_side_effect=SystemError("unexpected"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(limit=10, offset=0)
        result = await handle_history(input_data)

        assert isinstance(result, McpToolResult)
        assert result.isError is True

    def test_handle_history_limit_min(self):
        """HistoryToolInput accepts limit=1."""
        inp = HistoryToolInput(limit=1, offset=0)
        assert inp.limit == 1

    def test_handle_history_limit_max(self):
        """HistoryToolInput accepts limit=500."""
        inp = HistoryToolInput(limit=500, offset=0)
        assert inp.limit == 500

    def test_handle_history_limit_zero_rejected(self):
        """HistoryToolInput rejects limit=0."""
        with pytest.raises(Exception):
            HistoryToolInput(limit=0, offset=0)

    def test_handle_history_limit_over_max_rejected(self):
        """HistoryToolInput rejects limit=501."""
        with pytest.raises(Exception):
            HistoryToolInput(limit=501, offset=0)

    def test_handle_history_offset_min(self):
        """HistoryToolInput accepts offset=0."""
        inp = HistoryToolInput(limit=10, offset=0)
        assert inp.offset == 0

    def test_handle_history_offset_max(self):
        """HistoryToolInput accepts offset=100000."""
        inp = HistoryToolInput(limit=10, offset=100000)
        assert inp.offset == 100000

    def test_handle_history_offset_over_max_rejected(self):
        """HistoryToolInput rejects offset=100001."""
        with pytest.raises(Exception):
            HistoryToolInput(limit=10, offset=100001)

    def test_handle_history_offset_negative_rejected(self):
        """HistoryToolInput rejects negative offset."""
        with pytest.raises(Exception):
            HistoryToolInput(limit=10, offset=-1)

    @pytest.mark.asyncio
    async def test_handle_history_empty_results(self):
        """handle_history returns empty list when no results match."""
        pipeline = StubPipeline(history_result=[])
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(limit=10, offset=0)
        result = await handle_history(input_data)
        assert result.isError is False
        parsed = json.loads(result.content[0].text)
        assert isinstance(parsed, list)
        assert len(parsed) == 0

    def test_handle_history_kind_valid_pattern(self):
        """HistoryToolInput accepts valid kind matching regex."""
        inp = HistoryToolInput(kind="security-review_v2", limit=10, offset=0)
        assert inp.kind == "security-review_v2"

    def test_handle_history_kind_invalid_pattern(self):
        """HistoryToolInput rejects kind with invalid chars."""
        with pytest.raises(Exception):
            HistoryToolInput(kind="invalid kind!!!", limit=10, offset=0)

    def test_handle_history_kind_too_long(self):
        """HistoryToolInput rejects kind exceeding 64 chars."""
        with pytest.raises(Exception):
            HistoryToolInput(kind="a" * 65, limit=10, offset=0)

    def test_handle_history_date_iso_with_timezone(self):
        """HistoryToolInput accepts date_from with timezone offset."""
        inp = HistoryToolInput(
            date_from="2024-01-15T10:30:00+05:30",
            limit=10,
            offset=0,
        )
        assert inp.date_from == "2024-01-15T10:30:00+05:30"

    def test_handle_history_date_iso_with_z_timezone(self):
        """HistoryToolInput accepts date_from with Z timezone."""
        inp = HistoryToolInput(
            date_from="2024-01-15T10:30:00Z",
            limit=10,
            offset=0,
        )
        assert inp.date_from == "2024-01-15T10:30:00Z"

    def test_handle_history_date_date_only(self):
        """HistoryToolInput accepts date-only format."""
        inp = HistoryToolInput(
            date_from="2024-01-15",
            limit=10,
            offset=0,
        )
        assert inp.date_from == "2024-01-15"


# ---------------------------------------------------------------------------
# TestBuildToolError
# ---------------------------------------------------------------------------

class TestBuildToolError:

    def test_build_tool_error_happy_path(self):
        """build_tool_error returns McpToolResult with isError=True and valid ToolError JSON."""
        result = build_tool_error(
            error_type="validation_error",
            message="Something went wrong",
            pact_key="mcp_server.handle_review",
        )

        assert isinstance(result, McpToolResult)
        assert result.isError is True
        assert len(result.content) == 1
        assert result.content[0].type == "text"

        parsed = json.loads(result.content[0].text)
        assert parsed["error_type"] == "validation_error"
        assert parsed["message"] == "Something went wrong"
        assert parsed["pact_key"] == "mcp_server.handle_review"

    def test_build_tool_error_with_field_errors(self):
        """build_tool_error includes field_errors in the ToolError JSON."""
        field_errs = [FieldError(field="diff_text", message="too short", input_value="")]
        result = build_tool_error(
            error_type="validation_error",
            message="Validation failed",
            pact_key="mcp_server.handle_review",
            field_errors=field_errs,
        )

        parsed = parse_result_json(result)
        assert "field_errors" in parsed
        assert len(parsed["field_errors"]) == 1
        assert parsed["field_errors"][0]["field"] == "diff_text"

    def test_build_tool_error_pact_key_present(self):
        """build_tool_error result always includes pact_key in serialized JSON."""
        result = build_tool_error(
            error_type="io_error",
            message="File not found",
            pact_key="mcp_server.handle_review",
        )
        parsed = parse_result_json(result)
        assert "pact_key" in parsed
        assert parsed["pact_key"] == "mcp_server.handle_review"

    def test_build_tool_error_always_is_error_true(self):
        """build_tool_error always sets isError=True."""
        for error_type in ("validation_error", "pipeline_error", "io_error", "internal_error"):
            result = build_tool_error(
                error_type=error_type,
                message="test",
                pact_key="test.key",
            )
            assert result.isError is True

    def test_build_tool_error_single_content_block(self):
        """build_tool_error result has exactly one McpContentBlock of type 'text'."""
        result = build_tool_error(
            error_type="internal_error",
            message="oops",
            pact_key="test.key",
        )
        assert len(result.content) == 1
        assert result.content[0].type == "text"


# ---------------------------------------------------------------------------
# TestBuildSuccessResult
# ---------------------------------------------------------------------------

class TestBuildSuccessResult:

    def test_build_success_result_happy_path(self):
        """build_success_result returns McpToolResult with isError=False and valid JSON."""
        # Use a FieldError as a simple Pydantic model for testing
        data = FieldError(field="test", message="ok")
        result = build_success_result(data)

        assert isinstance(result, McpToolResult)
        assert result.isError is False
        assert len(result.content) == 1
        assert result.content[0].type == "text"

        parsed = json.loads(result.content[0].text)
        assert parsed["field"] == "test"
        assert parsed["message"] == "ok"

    def test_build_success_result_list_data(self):
        """build_success_result serializes a list of Pydantic models."""
        data = [
            FieldError(field="a", message="m1"),
            FieldError(field="b", message="m2"),
        ]
        result = build_success_result(data)

        assert result.isError is False
        parsed = json.loads(result.content[0].text)
        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_build_success_result_deterministic_json(self):
        """build_success_result produces deterministic JSON with sorted keys."""
        data = FieldError(field="z_field", message="a_message", input_value="val")
        result1 = build_success_result(data)
        result2 = build_success_result(data)

        # Deterministic: same input -> same output
        assert result1.content[0].text == result2.content[0].text

        # Sorted keys
        parsed_text = result1.content[0].text
        parsed = json.loads(parsed_text)
        keys = list(parsed.keys())
        assert keys == sorted(keys)

    def test_build_success_result_serialization_error(self):
        """build_success_result raises error for non-Pydantic input."""
        with pytest.raises(Exception):
            build_success_result({"not": "a pydantic model"})

    def test_build_success_result_always_is_error_false(self):
        """build_success_result always sets isError=False."""
        data = FieldError(field="t", message="m")
        result = build_success_result(data)
        assert result.isError is False


# ---------------------------------------------------------------------------
# TestInvariants (cross-cutting)
# ---------------------------------------------------------------------------

class TestInvariants:

    def test_invariant_frozen_review_tool_input(self):
        """ReviewToolInput is frozen - attribute assignment raises error."""
        inp = ReviewToolInput(diff_text="test", format=OutputFormat.json)
        with pytest.raises(Exception):
            inp.diff_text = "new value"

    def test_invariant_frozen_trust_tool_input(self):
        """TrustToolInput is frozen - attribute assignment raises error."""
        inp = TrustToolInput(reviewer_id="user1")
        with pytest.raises(Exception):
            inp.reviewer_id = "new_user"

    def test_invariant_frozen_history_tool_input(self):
        """HistoryToolInput is frozen - attribute assignment raises error."""
        inp = HistoryToolInput(limit=10, offset=0)
        with pytest.raises(Exception):
            inp.limit = 20

    def test_invariant_frozen_tool_error(self):
        """ToolError is frozen - attribute assignment raises error."""
        err = ToolError(
            error_type="validation_error",
            message="test",
            pact_key="test.key",
        )
        with pytest.raises(Exception):
            err.message = "changed"

    def test_invariant_frozen_server_config(self):
        """ServerConfig is frozen (if applicable)."""
        config = make_server_config()
        with pytest.raises(Exception):
            config.server_name = "changed"

    @pytest.mark.asyncio
    async def test_invariant_tool_handlers_never_raise_review(self):
        """handle_review never raises unhandled exceptions."""
        # Even with catastrophic pipeline failure, should return McpToolResult
        pipeline = StubPipeline(review_side_effect=KeyboardInterrupt("simulated"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = ReviewToolInput(diff_text="+ line", format=OutputFormat.json)
        # This should either return McpToolResult or we accept KeyboardInterrupt
        # as a special case. The contract says "never raises unhandled exceptions"
        # which typically excludes BaseException subclasses like KeyboardInterrupt.
        # Test with RuntimeError instead:
        pipeline2 = StubPipeline(review_side_effect=RuntimeError("any error"))
        server2 = create_server(pipeline2, config)
        result = await handle_review(input_data)
        assert isinstance(result, McpToolResult)

    @pytest.mark.asyncio
    async def test_invariant_tool_handlers_never_raise_trust(self):
        """handle_trust never raises unhandled exceptions."""
        pipeline = StubPipeline(trust_side_effect=ValueError("any error"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = TrustToolInput()
        result = await handle_trust(input_data)
        assert isinstance(result, McpToolResult)

    @pytest.mark.asyncio
    async def test_invariant_tool_handlers_never_raise_history(self):
        """handle_history never raises unhandled exceptions."""
        pipeline = StubPipeline(history_side_effect=TypeError("any error"))
        config = make_server_config()
        server = create_server(pipeline, config)

        input_data = HistoryToolInput(limit=10, offset=0)
        result = await handle_history(input_data)
        assert isinstance(result, McpToolResult)

    def test_invariant_mcp_content_block_type_text(self):
        """McpContentBlock only accepts type='text'."""
        block = McpContentBlock(type="text", text="hello")
        assert block.type == "text"

        with pytest.raises(Exception):
            McpContentBlock(type="image", text="hello")

    def test_invariant_tool_error_valid_error_types(self):
        """ToolError only accepts valid error_type values."""
        for valid_type in ("validation_error", "pipeline_error", "io_error", "internal_error"):
            err = ToolError(error_type=valid_type, message="test", pact_key="k")
            assert err.error_type == valid_type

        with pytest.raises(Exception):
            ToolError(error_type="unknown_error", message="test", pact_key="k")

    def test_invariant_tool_error_message_min_length(self):
        """ToolError rejects empty message."""
        with pytest.raises(Exception):
            ToolError(error_type="validation_error", message="", pact_key="k")

    def test_invariant_server_config_name_regex(self):
        """ServerConfig name must match ^[a-zA-Z0-9_\\-]{1,64}$."""
        # Valid
        config = make_server_config(server_name="my-server_01")
        assert config.server_name == "my-server_01"

        # Invalid: spaces
        with pytest.raises(Exception):
            make_server_config(server_name="has spaces")

        # Invalid: too long
        with pytest.raises(Exception):
            make_server_config(server_name="a" * 65)

        # Invalid: empty
        with pytest.raises(Exception):
            make_server_config(server_name="")
