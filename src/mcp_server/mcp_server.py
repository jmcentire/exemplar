"""MCP Server for Exemplar — exposes review, trust, and history tools over JSON-RPC/stdio.

Module invariants:
  - stdout is exclusively reserved for JSON-RPC protocol traffic
  - All logging output is written to stderr via Python logging module
  - Tool handlers never raise unhandled exceptions; all errors are caught and returned as McpToolResult with isError=True
  - All tool input models are frozen Pydantic v2 models (frozen=True)
  - All public functions carry a PACT key for Sentinel attribution
  - Chronicler event emission is fire-and-forget
  - Tool JSON schemas are generated from Pydantic model_json_schema() and are deterministic
  - JSON serialization in tool responses is deterministic (sorted keys)
  - The MCP server holds no mutable state between requests; all state is in the injected pipeline
  - ReviewToolInput requires at least one of diff_text or file_path to be non-None
"""

from __future__ import annotations

import json
import logging
import sys
from enum import Enum
from typing import Any, Literal, Optional, Protocol, runtime_checkable

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    model_validator,
)

# ---------------------------------------------------------------------------
# Logging — stderr only
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    _stderr_handler = logging.StreamHandler(sys.stderr)
    _stderr_handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    logger.addHandler(_stderr_handler)

# ---------------------------------------------------------------------------
# PACT keys
# ---------------------------------------------------------------------------

_PACT_CREATE_SERVER = "PACT:exemplar:mcp_server:create_server"
_PACT_RUN_SERVER = "PACT:exemplar:mcp_server:run_server"
_PACT_HANDLE_REVIEW = "PACT:exemplar:mcp_server:handle_review"
_PACT_HANDLE_TRUST = "PACT:exemplar:mcp_server:handle_trust"
_PACT_HANDLE_HISTORY = "PACT:exemplar:mcp_server:handle_history"
_PACT_BUILD_TOOL_ERROR = "PACT:exemplar:mcp_server:build_tool_error"
_PACT_BUILD_SUCCESS = "PACT:exemplar:mcp_server:build_success_result"

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class OutputFormat(str, Enum):
    """Supported report output formats."""
    json = "json"
    md = "md"
    github = "github"


# ---------------------------------------------------------------------------
# Pydantic v2 frozen models — tool inputs
# ---------------------------------------------------------------------------


class ReviewToolInput(BaseModel):
    """Frozen Pydantic v2 input model for the exemplar_review tool."""
    model_config = ConfigDict(frozen=True)

    diff_text: Optional[str] = Field(None, min_length=1, max_length=1048576)
    file_path: Optional[str] = Field(None, min_length=1, max_length=4096)
    config_overrides: Optional[dict] = None
    format: OutputFormat = OutputFormat.json

    @model_validator(mode="after")
    def _at_least_one_source(self) -> "ReviewToolInput":
        if self.diff_text is None and self.file_path is None:
            raise ValueError(
                "At least one of diff_text or file_path must be provided"
            )
        return self


class TrustToolInput(BaseModel):
    """Frozen Pydantic v2 input model for the exemplar_trust tool."""
    model_config = ConfigDict(frozen=True)

    reviewer_id: Optional[str] = Field(
        None, pattern=r"^[a-zA-Z0-9_\-\.]{1,128}$"
    )


class HistoryToolInput(BaseModel):
    """Frozen Pydantic v2 input model for the exemplar_history tool."""
    model_config = ConfigDict(frozen=True)

    tags: Optional[list[str]] = None
    kind: Optional[str] = Field(
        None, pattern=r"^[a-zA-Z0-9_\-]{1,64}$"
    )
    date_from: Optional[str] = Field(
        None,
        pattern=r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$",
    )
    date_to: Optional[str] = Field(
        None,
        pattern=r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})?)?$",
    )
    limit: int = Field(50, ge=1, le=500)
    offset: int = Field(0, ge=0, le=100000)


# ---------------------------------------------------------------------------
# Pydantic v2 frozen models — tool outputs / errors
# ---------------------------------------------------------------------------


class FieldError(BaseModel):
    """Per-field validation error detail within a ToolError."""
    model_config = ConfigDict(frozen=True)

    field: str
    message: str
    input_value: Optional[str] = None


class ToolError(BaseModel):
    """Frozen Pydantic v2 model for structured MCP tool error responses."""
    model_config = ConfigDict(frozen=True)

    error_type: Literal[
        "validation_error", "pipeline_error", "io_error", "internal_error"
    ]
    message: str = Field(..., min_length=1, max_length=4096)
    field_errors: Optional[list[FieldError]] = None
    pact_key: str


class McpContentBlock(BaseModel):
    """A single MCP tool result content block."""
    model_config = ConfigDict(frozen=True)

    type: Literal["text"]
    text: str


class McpToolResult(BaseModel):
    """MCP tool call result shape returned from tool handlers."""
    model_config = ConfigDict(frozen=True)

    content: list[McpContentBlock]
    isError: bool = False


# ---------------------------------------------------------------------------
# Protocol & config
# ---------------------------------------------------------------------------


@runtime_checkable
class PipelineProtocol(Protocol):
    """Runtime-checkable Protocol defining the core pipeline interface."""

    async def run_review(self, *args: Any, **kwargs: Any) -> Any: ...
    async def get_trust_scores(self, *args: Any, **kwargs: Any) -> Any: ...
    async def query_history(self, *args: Any, **kwargs: Any) -> Any: ...


class ServerConfig(BaseModel):
    """Configuration subset relevant to the MCP server."""
    model_config = ConfigDict(frozen=True)

    server_name: str = Field(
        "exemplar", pattern=r"^[a-zA-Z0-9_\-]{1,64}$"
    )
    server_version: str = Field(
        "0.1.0", pattern=r"^\d+\.\d+\.\d+(-[a-zA-Z0-9\.]+)?$"
    )
    enable_chronicler: bool = True
    max_diff_size_bytes: int = Field(1048576, ge=1024, le=10485760)


# ---------------------------------------------------------------------------
# Module-level state (set by create_server)
# ---------------------------------------------------------------------------

_pipeline: Any = None
_server_config: ServerConfig | None = None


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def build_tool_error(
    error_type: str,
    message: str,
    pact_key: str,
    field_errors: list[FieldError] | None = None,
) -> McpToolResult:
    """PACT:exemplar:mcp_server:build_tool_error"""
    tool_error = ToolError(
        error_type=error_type,
        message=message,
        pact_key=pact_key,
        field_errors=field_errors,
    )
    text = json.dumps(
        tool_error.model_dump(exclude_none=True), sort_keys=True
    )
    return McpToolResult(
        content=[McpContentBlock(type="text", text=text)],
        isError=True,
    )


def build_success_result(data: Any) -> McpToolResult:
    """PACT:exemplar:mcp_server:build_success_result"""
    if isinstance(data, list):
        if not all(isinstance(item, BaseModel) for item in data):
            raise TypeError(
                "Data must be a Pydantic BaseModel or list of BaseModel instances"
            )
        text = json.dumps(
            [item.model_dump() for item in data], sort_keys=True
        )
    elif isinstance(data, BaseModel):
        text = json.dumps(data.model_dump(), sort_keys=True)
    else:
        raise TypeError(
            "Data must be a Pydantic BaseModel or list of BaseModel instances"
        )
    return McpToolResult(
        content=[McpContentBlock(type="text", text=text)],
        isError=False,
    )


# ---------------------------------------------------------------------------
# Internal serialisation helper (handles MagicMock / duck-typed objects)
# ---------------------------------------------------------------------------


def _serialize_pipeline_result(data: Any) -> str:
    """Best-effort serialisation of pipeline return values."""
    # Real Pydantic model
    if isinstance(data, BaseModel):
        try:
            return json.dumps(data.model_dump(), sort_keys=True)
        except (TypeError, ValueError):
            pass

    # List (may contain Pydantic models, dicts, or other)
    if isinstance(data, list):
        items = []
        for item in data:
            if isinstance(item, BaseModel):
                items.append(item.model_dump())
            elif isinstance(item, dict):
                items.append(item)
            else:
                items.append(str(item))
        return json.dumps(items, sort_keys=True)

    # Duck-typed object with model_dump (e.g. test mocks)
    if hasattr(data, "model_dump"):
        try:
            d = data.model_dump()
            if isinstance(d, dict):
                return json.dumps(d, sort_keys=True)
        except Exception:
            pass

    # Last resort — wrap in a dict so json.loads always yields dict|list
    return json.dumps({"result": str(data)}, sort_keys=True)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def create_server(
    pipeline: PipelineProtocol,
    config: ServerConfig = ServerConfig(),
) -> Any:
    """PACT:exemplar:mcp_server:create_server"""
    global _pipeline, _server_config

    if not isinstance(pipeline, PipelineProtocol):
        raise TypeError(
            "pipeline must implement PipelineProtocol "
            "(run_review, get_trust_scores, query_history)"
        )
    if not isinstance(config, ServerConfig):
        raise TypeError("ServerConfig validation failed")

    _pipeline = pipeline
    _server_config = config

    return {
        "pipeline": pipeline,
        "config": config,
        "tools": [
            "exemplar_review",
            "exemplar_trust",
            "exemplar_history",
        ],
    }


# ---------------------------------------------------------------------------
# run_server
# ---------------------------------------------------------------------------


async def run_server(server: Any) -> None:
    """PACT:exemplar:mcp_server:run_server"""
    if sys.stdin is None or sys.stdout is None:
        raise OSError("stdio transport requires open stdin and stdout")
    # In production this would start the JSON-RPC message loop over stdio.
    raise RuntimeError("MCP transport not implemented")


# ---------------------------------------------------------------------------
# Tool handlers
# ---------------------------------------------------------------------------


async def handle_review(input: ReviewToolInput) -> McpToolResult:
    """PACT:exemplar:mcp_server:handle_review"""
    try:
        # --- resolve diff content ---
        diff_text = input.diff_text
        if diff_text is None and input.file_path is not None:
            try:
                with open(input.file_path, "r") as f:
                    diff_text = f.read()
            except (FileNotFoundError, PermissionError, OSError):
                return build_tool_error(
                    error_type="io_error",
                    message="Diff file not found or not readable",
                    pact_key=_PACT_HANDLE_REVIEW,
                )

        # --- size check ---
        if diff_text is not None:
            size = len(diff_text.encode("utf-8"))
            if size > _server_config.max_diff_size_bytes:
                return build_tool_error(
                    error_type="validation_error",
                    message="Diff too_large: exceeds maximum allowed size",
                    pact_key=_PACT_HANDLE_REVIEW,
                )

        # --- run pipeline ---
        try:
            report = await _pipeline.run_review(
                diff_text, _server_config, config_overrides=input.config_overrides
            )
        except Exception as exc:
            return build_tool_error(
                error_type="pipeline_error",
                message=f"Review pipeline failed: {exc}",
                pact_key=_PACT_HANDLE_REVIEW,
            )

        # --- serialise ---
        text = _serialize_pipeline_result(report)
        return McpToolResult(
            content=[McpContentBlock(type="text", text=text)],
            isError=False,
        )
    except Exception as exc:
        logger.exception("handle_review internal error")
        return build_tool_error(
            error_type="internal_error",
            message=f"Unexpected internal error: {exc}",
            pact_key=_PACT_HANDLE_REVIEW,
        )


async def handle_trust(input: TrustToolInput) -> McpToolResult:
    """PACT:exemplar:mcp_server:handle_trust"""
    try:
        # --- call pipeline ---
        try:
            scores = await _pipeline.get_trust_scores(input.reviewer_id)
        except Exception as exc:
            return build_tool_error(
                error_type="pipeline_error",
                message=f"Trust score retrieval failed: {exc}",
                pact_key=_PACT_HANDLE_TRUST,
            )

        # --- serialise ---
        if isinstance(scores, list):
            items = []
            for item in scores:
                if isinstance(item, BaseModel):
                    items.append(item.model_dump())
                elif isinstance(item, dict):
                    items.append(item)
                else:
                    items.append(str(item))
            text = json.dumps(items, sort_keys=True)
        else:
            text = _serialize_pipeline_result(scores)

        return McpToolResult(
            content=[McpContentBlock(type="text", text=text)],
            isError=False,
        )
    except Exception as exc:
        logger.exception("handle_trust internal error")
        return build_tool_error(
            error_type="internal_error",
            message=f"Unexpected internal error: {exc}",
            pact_key=_PACT_HANDLE_TRUST,
        )


async def handle_history(input: HistoryToolInput) -> McpToolResult:
    """PACT:exemplar:mcp_server:handle_history"""
    try:
        # --- date-range sanity check ---
        if (
            input.date_from is not None
            and input.date_to is not None
            and input.date_from > input.date_to
        ):
            return build_tool_error(
                error_type="validation_error",
                message="date_from must not be after date_to",
                pact_key=_PACT_HANDLE_HISTORY,
            )

        # --- call pipeline ---
        try:
            results = await _pipeline.query_history(
                tags=input.tags,
                kind=input.kind,
                date_from=input.date_from,
                date_to=input.date_to,
                limit=input.limit,
                offset=input.offset,
            )
        except Exception as exc:
            return build_tool_error(
                error_type="pipeline_error",
                message=f"History query failed: {exc}",
                pact_key=_PACT_HANDLE_HISTORY,
            )

        # --- serialise (enforce limit) ---
        if isinstance(results, list):
            results = results[: input.limit]
            items = []
            for item in results:
                if isinstance(item, BaseModel):
                    items.append(item.model_dump())
                elif isinstance(item, dict):
                    items.append(item)
                else:
                    items.append(str(item))
            text = json.dumps(items, sort_keys=True)
        else:
            text = _serialize_pipeline_result(results)

        return McpToolResult(
            content=[McpContentBlock(type="text", text=text)],
            isError=False,
        )
    except Exception as exc:
        logger.exception("handle_history internal error")
        return build_tool_error(
            error_type="internal_error",
            message=f"Unexpected internal error: {exc}",
            pact_key=_PACT_HANDLE_HISTORY,
        )


# ---------------------------------------------------------------------------
# Emission wrapper
# ---------------------------------------------------------------------------

def _classify_inputs(*args, **kwargs) -> list:
    """Classify input types for PACT event emission."""
    result = []
    for a in args:
        result.append(type(a).__name__)
    for k, v in kwargs.items():
        result.append(f"{k}:{type(v).__name__}")
    return result


class McpServer:
    """Unified MCP server class with optional PACT event emission."""

    def __init__(self, event_handler=None):
        self._handler = event_handler

    def _emit_event(self, pact_key: str, event: str, **extra):
        if self._handler:
            payload = {"pact_key": pact_key, "event": event}
            payload.update(extra)
            self._handler(payload)

    def _wrap(self, method_name: str, fn, *args, **kwargs):
        pact_key = f"PACT:mcp_server:{method_name}"
        self._emit_event(
            pact_key, "invoked",
            input_classification=_classify_inputs(*args, **kwargs),
        )
        try:
            result = fn(*args, **kwargs)
            self._emit_event(pact_key, "completed")
            return result
        except Exception as e:
            self._emit_event(pact_key, "error", error=str(e))
            raise

    def create_server(self, *args, **kwargs):
        return self._wrap("create_server", create_server, *args, **kwargs)

    def run_server(self, *args, **kwargs):
        return self._wrap("run_server", run_server, *args, **kwargs)

    def handle_review(self, *args, **kwargs):
        return self._wrap("handle_review", handle_review, *args, **kwargs)

    def handle_trust(self, *args, **kwargs):
        return self._wrap("handle_trust", handle_trust, *args, **kwargs)

    def handle_history(self, *args, **kwargs):
        return self._wrap("handle_history", handle_history, *args, **kwargs)

    def build_tool_error(self, *args, **kwargs):
        return self._wrap("build_tool_error", build_tool_error, *args, **kwargs)

    def build_success_result(self, *args, **kwargs):
        return self._wrap("build_success_result", build_success_result, *args, **kwargs)


# ---------------------------------------------------------------------------
# Script entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import asyncio

    async def _main() -> None:
        raise NotImplementedError(
            "MCP server should be started via CLI or MCP client"
        )

    asyncio.run(_main())
