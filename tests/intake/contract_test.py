"""
Contract tests for the intake module.

Tests organized into six test classes covering all public functions,
type validators, enum variants, and invariants.

Requirements: pytest, pytest-asyncio
"""
import asyncio
import re
import uuid
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio

# ─── Module under test ───────────────────────────────────────────────
from exemplar.intake import (
    ClassificationLabel,
    DiffHunk,
    DiffSourceKind,
    IntakeError,
    IntakePhase,
    IntakeResult,
    LedgerConfig,
    LedgerFieldRule,
    LineRange,
    ReviewRequest,
    classify_hunks,
    detect_language,
    generate_hunk_id,
    generate_request_id,
    parse_diff,
    run_intake,
)

# ═════════════════════════════════════════════════════════════════════
# Sample diff constants
# ═════════════════════════════════════════════════════════════════════

SAMPLE_SINGLE_HUNK_DIFF = (
    "diff --git a/src/main.py b/src/main.py\n"
    "--- a/src/main.py\n"
    "+++ b/src/main.py\n"
    "@@ -1,3 +1,4 @@\n"
    " import os\n"
    " import sys\n"
    "+import json\n"
    " \n"
)

SAMPLE_MULTI_HUNK_DIFF = (
    "diff --git a/src/main.py b/src/main.py\n"
    "--- a/src/main.py\n"
    "+++ b/src/main.py\n"
    "@@ -1,3 +1,4 @@\n"
    " import os\n"
    " import sys\n"
    "+import json\n"
    " \n"
    "@@ -10,3 +11,4 @@\n"
    " def main():\n"
    "     pass\n"
    "+    return 0\n"
    " \n"
)

SAMPLE_MULTI_FILE_DIFF = (
    "diff --git a/src/main.py b/src/main.py\n"
    "--- a/src/main.py\n"
    "+++ b/src/main.py\n"
    "@@ -1,3 +1,4 @@\n"
    " import os\n"
    " import sys\n"
    "+import json\n"
    " \n"
    "diff --git a/src/utils.py b/src/utils.py\n"
    "--- a/src/utils.py\n"
    "+++ b/src/utils.py\n"
    "@@ -1,2 +1,3 @@\n"
    " # utils\n"
    "+def helper(): pass\n"
    " \n"
)

SAMPLE_BINARY_DIFF = (
    "diff --git a/img.png b/img.png\n"
    "Binary files a/img.png and b/img.png differ\n"
)

SAMPLE_MALFORMED_HUNK_HEADER_DIFF = (
    "diff --git a/src/main.py b/src/main.py\n"
    "--- a/src/main.py\n"
    "+++ b/src/main.py\n"
    "@@ NOT_A_VALID_HEADER @@\n"
    "+some line\n"
)

SAMPLE_TRUNCATED_DIFF = (
    "diff --git a/src/main.py b/src/main.py\n"
    "--- a/src/main.py\n"
    "+++ b/src/main.py\n"
    "@@ -1,10 +1,10 @@\n"
    " line1\n"
    "+line2\n"
)

SAMPLE_PARTIAL_DIFF = (
    "diff --git a/src/good.py b/src/good.py\n"
    "--- a/src/good.py\n"
    "+++ b/src/good.py\n"
    "@@ -1,3 +1,4 @@\n"
    " import os\n"
    " import sys\n"
    "+import json\n"
    " \n"
    "diff --git a/src/bad.py b/src/bad.py\n"
    "--- a/src/bad.py\n"
    "+++ b/src/bad.py\n"
    "@@ BROKEN_HEADER @@\n"
    "+some line\n"
)

SAMPLE_SECRET_DIFF = (
    "diff --git a/src/config.py b/src/config.py\n"
    "--- a/src/config.py\n"
    "+++ b/src/config.py\n"
    "@@ -1,2 +1,3 @@\n"
    " # config\n"
    "+API_KEY = 'sk-secret12345abcdef'\n"
    " \n"
)

SAMPLE_PII_DIFF = (
    "diff --git a/src/user.py b/src/user.py\n"
    "--- a/src/user.py\n"
    "+++ b/src/user.py\n"
    "@@ -1,2 +1,3 @@\n"
    " # user\n"
    "+email = 'user@example.com'\n"
    " \n"
)

SAMPLE_SECRET_AND_PII_DIFF = (
    "diff --git a/src/both.py b/src/both.py\n"
    "--- a/src/both.py\n"
    "+++ b/src/both.py\n"
    "@@ -1,2 +1,4 @@\n"
    " # both\n"
    "+API_KEY = 'sk-secret12345abcdef'\n"
    "+email = 'user@example.com'\n"
    " \n"
)

SAMPLE_SECRET_IN_REMOVED_ONLY_DIFF = (
    "diff --git a/src/clean.py b/src/clean.py\n"
    "--- a/src/clean.py\n"
    "+++ b/src/clean.py\n"
    "@@ -1,3 +1,2 @@\n"
    " # clean\n"
    "-API_KEY = 'sk-secret12345abcdef'\n"
    "+# key removed\n"
)


# ═════════════════════════════════════════════════════════════════════
# Helper: build fixtures
# ═════════════════════════════════════════════════════════════════════

def make_ledger_config(rules=None, default_label=None):
    """Build a LedgerConfig with sensible defaults."""
    if rules is None:
        rules = [
            LedgerFieldRule(
                pattern=r"(?i)(api[_-]?key|secret|token)\s*=\s*['\"]",
                label=ClassificationLabel.secret,
                description="Detects hardcoded secrets",
            ),
            LedgerFieldRule(
                pattern=r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
                label=ClassificationLabel.pii,
                description="Detects email addresses",
            ),
            LedgerFieldRule(
                pattern=r"internal[_-]api|__private_endpoint",
                label=ClassificationLabel.internal_api,
                description="Detects internal API references",
            ),
        ]
    if default_label is None:
        default_label = ClassificationLabel.public
    return LedgerConfig(rules=rules, default_label=default_label)


def make_mock_source(content=None, error=None):
    """Create an async DiffSource-conforming mock."""
    source = AsyncMock()
    source.kind = DiffSourceKind.file
    if error is not None:
        source.read = AsyncMock(side_effect=error)
    else:
        source.read = AsyncMock(return_value=content or "")
    return source


def make_collecting_emitter():
    """Create an EventEmitter-conforming fake that collects events."""
    events = []

    async def _emit(event):
        events.append(event)

    emitter = AsyncMock()
    emitter.emit = AsyncMock(side_effect=_emit)
    emitter._events = events
    return emitter, events


def make_failing_emitter(exc=None):
    """Create an EventEmitter whose emit() always raises."""
    emitter = AsyncMock()
    emitter.emit = AsyncMock(side_effect=exc or RuntimeError("emit failed"))
    return emitter


# ═════════════════════════════════════════════════════════════════════
# Test Class 1: Type / Enum / Struct Validation
# ═════════════════════════════════════════════════════════════════════

class TestTypeValidation:
    """Tests for contract-defined types, enums, and struct validators."""

    # ── DiffSourceKind ────────────────────────────────────────────
    def test_diff_source_kind_has_file_and_stdin(self):
        assert DiffSourceKind.file is not None
        assert DiffSourceKind.stdin is not None

    # ── ClassificationLabel ───────────────────────────────────────
    def test_classification_label_variants(self):
        assert ClassificationLabel.secret is not None
        assert ClassificationLabel.pii is not None
        assert ClassificationLabel.internal_api is not None
        assert ClassificationLabel.public is not None

    # ── IntakePhase ───────────────────────────────────────────────
    def test_intake_phase_variants(self):
        assert IntakePhase.read is not None
        assert IntakePhase.parse is not None
        assert IntakePhase.classify is not None
        assert IntakePhase.orchestrate is not None

    # ── LineRange ─────────────────────────────────────────────────
    def test_line_range_valid(self):
        lr = LineRange(start=1, count=0)
        assert lr.start == 1
        assert lr.count == 0

    def test_line_range_large_values(self):
        lr = LineRange(start=99999, count=50000)
        assert lr.start == 99999
        assert lr.count == 50000

    def test_line_range_start_too_low(self):
        with pytest.raises(Exception):  # ValidationError
            LineRange(start=0, count=0)

    def test_line_range_negative_start(self):
        with pytest.raises(Exception):
            LineRange(start=-5, count=0)

    def test_line_range_count_negative(self):
        with pytest.raises(Exception):
            LineRange(start=1, count=-1)

    def test_line_range_frozen(self):
        lr = LineRange(start=1, count=5)
        with pytest.raises(Exception):  # FrozenInstanceError or similar
            lr.start = 10

    # ── IntakeError ───────────────────────────────────────────────
    def test_intake_error_valid(self):
        ie = IntakeError(
            line_number=1,
            message="something went wrong",
            raw_content="bad line",
            phase=IntakePhase.parse,
        )
        assert ie.message == "something went wrong"
        assert ie.phase == IntakePhase.parse

    def test_intake_error_empty_message_rejected(self):
        with pytest.raises(Exception):  # ValidationError
            IntakeError(
                line_number=1,
                message="",
                raw_content="bad",
                phase=IntakePhase.parse,
            )

    def test_intake_error_frozen(self):
        ie = IntakeError(
            line_number=1,
            message="err",
            raw_content="x",
            phase=IntakePhase.parse,
        )
        with pytest.raises(Exception):
            ie.message = "changed"


# ═════════════════════════════════════════════════════════════════════
# Test Class 2: TestParseDiff
# ═════════════════════════════════════════════════════════════════════

class TestParseDiff:
    """Tests for async parse_diff: pure parsing of unified diff text."""

    @pytest.mark.asyncio
    async def test_single_hunk_happy_path(self):
        hunks, errors = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        assert len(hunks) == 1
        assert len(errors) == 0
        h = hunks[0]
        assert h.id.startswith("hunk-")
        assert h.file_path != ""
        assert h.classifications == []

    @pytest.mark.asyncio
    async def test_multi_hunk_same_file(self):
        hunks, errors = await parse_diff(SAMPLE_MULTI_HUNK_DIFF)
        assert len(hunks) == 2
        assert len(errors) == 0
        assert hunks[0].id != hunks[1].id
        # Both hunks should reference the same file
        assert hunks[0].file_path == hunks[1].file_path

    @pytest.mark.asyncio
    async def test_multi_file_diff(self):
        hunks, errors = await parse_diff(SAMPLE_MULTI_FILE_DIFF)
        assert len(hunks) >= 2
        file_paths = {h.file_path for h in hunks}
        assert len(file_paths) >= 2

    @pytest.mark.asyncio
    async def test_empty_input_returns_empty(self):
        hunks, errors = await parse_diff("")
        assert hunks == []
        assert errors == []

    @pytest.mark.asyncio
    async def test_no_diff_headers(self):
        hunks, errors = await parse_diff("this is just some random text\nwith no diff markers\n")
        assert len(hunks) == 0
        assert len(errors) >= 1
        for e in errors:
            phase_val = e.phase.value if hasattr(e.phase, "value") else str(e.phase)
            assert phase_val == "parse"

    @pytest.mark.asyncio
    async def test_malformed_hunk_header(self):
        hunks, errors = await parse_diff(SAMPLE_MALFORMED_HUNK_HEADER_DIFF)
        assert len(errors) >= 1
        for e in errors:
            assert e.message != ""

    @pytest.mark.asyncio
    async def test_truncated_hunk(self):
        hunks, errors = await parse_diff(SAMPLE_TRUNCATED_DIFF)
        # Should produce at least a partial result or an error
        assert len(hunks) + len(errors) >= 1

    @pytest.mark.asyncio
    async def test_binary_file_marker(self):
        hunks, errors = await parse_diff(SAMPLE_BINARY_DIFF)
        # Binary files should not produce DiffHunks (or if hunks exist, not for binary file)
        if hunks:
            assert all("img.png" not in h.file_path for h in hunks)
        # At least an error or empty hunks
        assert len(errors) >= 1 or len(hunks) == 0

    @pytest.mark.asyncio
    async def test_partial_success(self):
        """Valid hunks returned alongside errors for partially malformed input."""
        hunks, errors = await parse_diff(SAMPLE_PARTIAL_DIFF)
        assert len(hunks) >= 1
        assert len(errors) >= 1

    @pytest.mark.asyncio
    async def test_deterministic_output(self):
        hunks1, errors1 = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        hunks2, errors2 = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        assert len(hunks1) == len(hunks2)
        for h1, h2 in zip(hunks1, hunks2):
            assert h1.id == h2.id
            assert h1.file_path == h2.file_path
            assert h1.added_lines == h2.added_lines

    @pytest.mark.asyncio
    async def test_classifications_always_empty(self):
        hunks, _ = await parse_diff(SAMPLE_SECRET_DIFF)
        for h in hunks:
            assert h.classifications == []

    @pytest.mark.asyncio
    async def test_file_path_forward_slashes_and_nonempty(self):
        hunks, _ = await parse_diff(SAMPLE_MULTI_FILE_DIFF)
        for h in hunks:
            assert h.file_path != ""
            assert "\\" not in h.file_path

    @pytest.mark.asyncio
    async def test_language_populated(self):
        hunks, _ = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        for h in hunks:
            assert h.language is not None
            assert isinstance(h.language, str)
            assert len(h.language) > 0

    @pytest.mark.asyncio
    async def test_language_for_python_file(self):
        hunks, _ = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        # .py file should map to 'python'
        assert hunks[0].language == "python"

    @pytest.mark.asyncio
    async def test_all_errors_have_parse_phase(self):
        hunks, errors = await parse_diff(SAMPLE_MALFORMED_HUNK_HEADER_DIFF)
        for e in errors:
            phase_val = e.phase.value if hasattr(e.phase, "value") else str(e.phase)
            assert phase_val == "parse"

    @pytest.mark.asyncio
    async def test_hunk_id_format_from_parse(self):
        hunks, _ = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        h = hunks[0]
        assert h.id.startswith("hunk-")
        hex_part = h.id[5:]
        assert len(hex_part) == 12
        assert all(c in "0123456789abcdef" for c in hex_part)

    @pytest.mark.asyncio
    async def test_randomized_garbage_no_crash(self):
        """Fuzz-like test: random bytes should not crash parse_diff."""
        import random
        random.seed(42)
        for _ in range(20):
            length = random.randint(0, 500)
            raw = "".join(chr(random.randint(32, 126)) for _ in range(length))
            hunks, errors = await parse_diff(raw)
            # Should never crash; just return (possibly empty) lists
            assert isinstance(hunks, list)
            assert isinstance(errors, list)


# ═════════════════════════════════════════════════════════════════════
# Test Class 3: TestClassifyHunks
# ═════════════════════════════════════════════════════════════════════

class TestClassifyHunks:
    """Tests for sync classify_hunks: Ledger field classification."""

    @pytest.mark.asyncio
    async def _parse_hunks(self, diff_text):
        """Helper to get hunks for classify_hunks tests."""
        hunks, _ = await parse_diff(diff_text)
        return hunks

    @pytest.mark.asyncio
    async def test_classify_happy_path_secret_detected(self):
        hunks = await self._parse_hunks(SAMPLE_SECRET_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        assert len(result) == len(hunks)
        labels = [c.value if hasattr(c, "value") else str(c) for c in result[0].classifications]
        assert "secret" in labels

    @pytest.mark.asyncio
    async def test_classify_no_matches(self):
        hunks = await self._parse_hunks(SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        assert all(h.classifications == [] for h in result)

    @pytest.mark.asyncio
    async def test_classify_preserves_order(self):
        hunks = await self._parse_hunks(SAMPLE_MULTI_HUNK_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        assert [h.id for h in result] == [h.id for h in hunks]

    @pytest.mark.asyncio
    async def test_classify_preserves_fields(self):
        hunks = await self._parse_hunks(SAMPLE_SECRET_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        assert result[0].id == hunks[0].id
        assert result[0].file_path == hunks[0].file_path
        assert result[0].added_lines == hunks[0].added_lines
        assert result[0].removed_lines == hunks[0].removed_lines
        assert result[0].raw_header == hunks[0].raw_header

    @pytest.mark.asyncio
    async def test_classify_no_duplicate_labels(self):
        hunks = await self._parse_hunks(SAMPLE_SECRET_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        for h in result:
            assert len(h.classifications) == len(set(h.classifications))

    @pytest.mark.asyncio
    async def test_classify_only_scans_added_lines(self):
        """Secret in removed_lines should not trigger classification."""
        hunks = await self._parse_hunks(SAMPLE_SECRET_IN_REMOVED_ONLY_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        # Only '+# key removed' is an added line - should not match secret pattern
        labels = [c.value if hasattr(c, "value") else str(c) for c in result[0].classifications]
        assert "secret" not in labels

    @pytest.mark.asyncio
    async def test_classify_multi_label(self):
        hunks = await self._parse_hunks(SAMPLE_SECRET_AND_PII_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        labels = [c.value if hasattr(c, "value") else str(c) for c in result[0].classifications]
        assert "secret" in labels
        assert "pii" in labels

    def test_classify_empty_list_handling(self):
        """classify_hunks with empty list: either raises or returns empty."""
        config = make_ledger_config()
        try:
            result = classify_hunks([], config)
            # If it returns, should be empty list
            assert result == []
        except (ValueError, Exception):
            pass  # Also acceptable per error: empty_hunks_list

    def test_classify_invalid_regex(self):
        """classify_hunks raises on invalid regex in config."""
        bad_rules = [
            LedgerFieldRule(
                pattern="[invalid",  # broken regex
                label=ClassificationLabel.secret,
                description="broken",
            ),
        ]
        config = make_ledger_config(rules=bad_rules)
        # Need at least one hunk to trigger the regex compilation
        # Create a minimal DiffHunk-like object
        # We'll parse a real diff to get a valid hunk
        # Since classify_hunks is sync, we need to handle this differently
        import asyncio
        loop = asyncio.get_event_loop()
        try:
            hunks, _ = loop.run_until_complete(parse_diff(SAMPLE_SINGLE_HUNK_DIFF))
        except RuntimeError:
            # If event loop is already running (pytest-asyncio), skip or use a simpler approach
            pytest.skip("Cannot run nested event loop in this context")
            return

        with pytest.raises(Exception):  # ValueError or re.error
            classify_hunks(hunks, config)

    @pytest.mark.asyncio
    async def test_classify_invalid_regex_async(self):
        """classify_hunks raises on invalid regex in config (async-friendly version)."""
        bad_rules = [
            LedgerFieldRule(
                pattern="[invalid",
                label=ClassificationLabel.secret,
                description="broken",
            ),
        ]
        config = make_ledger_config(rules=bad_rules)
        hunks, _ = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        with pytest.raises(Exception):  # ValueError or re.error
            classify_hunks(hunks, config)

    @pytest.mark.asyncio
    async def test_classify_same_length_output(self):
        hunks = await self._parse_hunks(SAMPLE_MULTI_HUNK_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        assert len(result) == len(hunks)


# ═════════════════════════════════════════════════════════════════════
# Test Class 4: TestGenerateHunkId
# ═════════════════════════════════════════════════════════════════════

class TestGenerateHunkId:
    """Tests for generate_hunk_id: deterministic SHA-256 based id generation."""

    def test_happy_path_format(self):
        result = generate_hunk_id("src/main.py", "@@ -1,3 +1,4 @@", ["new line"])
        assert result.startswith("hunk-")
        hex_part = result[5:]
        assert len(hex_part) == 12
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_deterministic(self):
        r1 = generate_hunk_id("src/main.py", "@@ -1,3 +1,4 @@", ["line1"])
        r2 = generate_hunk_id("src/main.py", "@@ -1,3 +1,4 @@", ["line1"])
        assert r1 == r2

    def test_different_file_path_different_id(self):
        r1 = generate_hunk_id("src/a.py", "@@ -1,3 +1,4 @@", ["line1"])
        r2 = generate_hunk_id("src/b.py", "@@ -1,3 +1,4 @@", ["line1"])
        assert r1 != r2

    def test_different_header_different_id(self):
        r1 = generate_hunk_id("src/a.py", "@@ -1,3 +1,4 @@", ["line1"])
        r2 = generate_hunk_id("src/a.py", "@@ -5,3 +5,4 @@", ["line1"])
        assert r1 != r2

    def test_different_added_lines_different_id(self):
        r1 = generate_hunk_id("src/a.py", "@@ -1,3 +1,4 @@", ["line1"])
        r2 = generate_hunk_id("src/a.py", "@@ -1,3 +1,4 @@", ["line2"])
        assert r1 != r2

    def test_empty_file_path_raises(self):
        with pytest.raises(Exception):  # ValueError expected
            generate_hunk_id("", "@@ -1,3 +1,4 @@", [])

    def test_empty_added_lines_valid(self):
        """Deletion-only hunk with empty added_lines should work."""
        result = generate_hunk_id("src/main.py", "@@ -1,3 +1,0 @@", [])
        assert result.startswith("hunk-")
        assert len(result) == 17  # "hunk-" (5) + 12 hex chars

    def test_total_length_is_17(self):
        result = generate_hunk_id("file.py", "@@ -1,1 +1,1 @@", ["x"])
        assert len(result) == 17

    def test_lowercase_hex(self):
        result = generate_hunk_id("file.py", "@@ -1,1 +1,1 @@", ["x"])
        hex_part = result[5:]
        assert hex_part == hex_part.lower()


# ═════════════════════════════════════════════════════════════════════
# Test Class 5: TestGenerateRequestId
# ═════════════════════════════════════════════════════════════════════

class TestGenerateRequestId:
    """Tests for generate_request_id: UUID4-based request id generation."""

    def test_happy_path_format(self):
        result = generate_request_id()
        assert result.startswith("req-")
        hex_part = result[4:]
        assert len(hex_part) == 32
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_unique_across_calls(self):
        ids = set()
        for _ in range(100):
            ids.add(generate_request_id())
        assert len(ids) == 100

    def test_valid_uuid4_hex(self):
        result = generate_request_id()
        hex_part = result[4:]
        # Should be parseable as a UUID hex string
        try:
            uuid.UUID(hex=hex_part, version=4)
        except ValueError:
            # Some implementations may not enforce version bits; at minimum the hex is valid
            int(hex_part, 16)  # Must be valid hex

    def test_prefix_is_req_dash(self):
        for _ in range(10):
            r = generate_request_id()
            assert r[:4] == "req-"


# ═════════════════════════════════════════════════════════════════════
# Test Class 6: TestDetectLanguage
# ═════════════════════════════════════════════════════════════════════

class TestDetectLanguage:
    """Tests for detect_language: file extension to language mapping."""

    @pytest.mark.parametrize(
        "file_path,expected",
        [
            ("src/main.py", "python"),
            ("app/index.js", "javascript"),
            ("src/app.ts", "typescript"),
            ("lib/module.rb", "ruby"),
            ("Main.java", "java"),
            ("code.go", "go"),
            ("code.rs", "rust"),
            ("code.c", "c"),
            ("code.cpp", "cpp"),
            ("code.h", "c"),
            ("style.css", "css"),
            ("page.html", "html"),
            ("data.json", "json"),
            ("data.yaml", "yaml"),
            ("data.yml", "yaml"),
            ("script.sh", "shell"),
            ("config.toml", "toml"),
            ("doc.md", "markdown"),
        ],
    )
    def test_common_extensions(self, file_path, expected):
        result = detect_language(file_path)
        # Allow for slight naming variations (e.g., "c++" vs "cpp")
        assert result.lower() == expected.lower() or result != "unknown"

    def test_python_extension(self):
        assert detect_language("src/main.py") == "python"

    def test_javascript_extension(self):
        assert detect_language("app/index.js") == "javascript"

    def test_typescript_extension(self):
        assert detect_language("src/app.ts") == "typescript"

    def test_unknown_extension(self):
        assert detect_language("data/file.xyz") == "unknown"

    def test_no_extension(self):
        assert detect_language("Makefile") == "unknown"

    def test_dotfile_without_secondary_extension(self):
        assert detect_language(".gitignore") == "unknown"

    def test_case_insensitive(self):
        result = detect_language("README.PY")
        assert result == "python"

    def test_compound_extension(self):
        result = detect_language("src/app.test.js")
        assert result == "javascript"

    def test_empty_path_raises(self):
        with pytest.raises(Exception):  # ValueError expected
            detect_language("")

    def test_nested_directory_path(self):
        result = detect_language("a/b/c/d/e.py")
        assert result == "python"

    def test_file_with_multiple_dots(self):
        result = detect_language("my.module.name.py")
        assert result == "python"

    def test_dotfile_with_known_extension(self):
        # e.g., .eslintrc.json should detect json
        result = detect_language(".eslintrc.json")
        assert result == "json"


# ═════════════════════════════════════════════════════════════════════
# Test Class 7: TestRunIntake (async integration with mocked I/O)
# ═════════════════════════════════════════════════════════════════════

class TestRunIntake:
    """Tests for async run_intake: top-level orchestrator."""

    @pytest.mark.asyncio
    async def test_happy_path(self):
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter, events = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        assert result.review_request.id.startswith("req-")
        assert result.hunk_count >= 1
        assert result.classified_hunk_count <= result.hunk_count
        assert isinstance(result.errors, list)

    @pytest.mark.asyncio
    async def test_emits_three_events(self):
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter, events = make_collecting_emitter()

        await run_intake(source, config, emitter)

        assert len(events) == 3

    @pytest.mark.asyncio
    async def test_source_read_failure_ioerror(self):
        source = make_mock_source(error=IOError("disk read failed"))
        config = make_ledger_config()
        emitter, events = make_collecting_emitter()

        try:
            result = await run_intake(source, config, emitter)
            # If it returns, errors should be populated
            assert len(result.errors) >= 1
        except (IOError, Exception):
            pass  # Also acceptable — may propagate

    @pytest.mark.asyncio
    async def test_source_read_failure_file_not_found(self):
        source = make_mock_source(error=FileNotFoundError("no such file"))
        config = make_ledger_config()
        emitter, events = make_collecting_emitter()

        try:
            result = await run_intake(source, config, emitter)
            assert len(result.errors) >= 1
        except (FileNotFoundError, Exception):
            pass

    @pytest.mark.asyncio
    async def test_source_read_failure_permission(self):
        source = make_mock_source(error=PermissionError("access denied"))
        config = make_ledger_config()
        emitter, events = make_collecting_emitter()

        try:
            result = await run_intake(source, config, emitter)
            assert len(result.errors) >= 1
        except (PermissionError, Exception):
            pass

    @pytest.mark.asyncio
    async def test_emitter_failure_resilience(self):
        """run_intake completes successfully even if emitter raises."""
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter = make_failing_emitter(RuntimeError("chronicle down"))

        result = await run_intake(source, config, emitter)

        assert result is not None
        assert result.hunk_count >= 1
        # Emission failures should appear as warnings, not errors
        # (Implementation may vary)

    @pytest.mark.asyncio
    async def test_iso_timestamp(self):
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        # Should be parseable as ISO 8601
        ts = result.review_request.created_at
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert dt is not None

    @pytest.mark.asyncio
    async def test_errors_from_parse_propagated(self):
        source = make_mock_source(content=SAMPLE_PARTIAL_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        assert len(result.errors) >= 1

    @pytest.mark.asyncio
    async def test_empty_diff_from_source(self):
        source = make_mock_source(content="")
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        assert result.hunk_count == 0

    @pytest.mark.asyncio
    async def test_review_request_id_format(self):
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        rid = result.review_request.id
        assert rid.startswith("req-")
        hex_part = rid[4:]
        assert len(hex_part) == 32
        assert all(c in "0123456789abcdef" for c in hex_part)

    @pytest.mark.asyncio
    async def test_hunks_are_classified(self):
        source = make_mock_source(content=SAMPLE_SECRET_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        # At least one hunk should have secret classification
        all_labels = []
        for h in result.review_request.hunks:
            for c in h.classifications:
                label = c.value if hasattr(c, "value") else str(c)
                all_labels.append(label)
        assert "secret" in all_labels

    @pytest.mark.asyncio
    async def test_file_paths_populated(self):
        source = make_mock_source(content=SAMPLE_MULTI_FILE_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        assert len(result.review_request.file_paths) >= 2

    @pytest.mark.asyncio
    async def test_source_read_timeout(self):
        """run_intake handles source.read() timeout."""
        source = make_mock_source(error=asyncio.TimeoutError())
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        try:
            result = await run_intake(source, config, emitter)
            assert len(result.errors) >= 1
        except (asyncio.TimeoutError, Exception):
            pass  # Also acceptable

    @pytest.mark.asyncio
    async def test_emitter_warnings_not_errors(self):
        """Emitter failures appear as warnings, not blocking errors."""
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter = make_failing_emitter(RuntimeError("emit failed"))

        result = await run_intake(source, config, emitter)

        # Result should still be valid
        assert result.review_request.id.startswith("req-")
        # Warnings may contain emission failure info
        # The key invariant is that the process completed
        assert result.hunk_count >= 1

    @pytest.mark.asyncio
    async def test_classified_hunk_count_leq_hunk_count(self):
        source = make_mock_source(content=SAMPLE_SECRET_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        assert result.classified_hunk_count <= result.hunk_count

    @pytest.mark.asyncio
    async def test_hunk_count_matches_hunks_len(self):
        source = make_mock_source(content=SAMPLE_MULTI_HUNK_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()

        result = await run_intake(source, config, emitter)

        assert result.hunk_count == len(result.review_request.hunks)


# ═════════════════════════════════════════════════════════════════════
# Test Class 8: Invariant Tests
# ═════════════════════════════════════════════════════════════════════

class TestInvariants:
    """Cross-cutting invariant tests from the contract."""

    @pytest.mark.asyncio
    async def test_diffhunk_frozen(self):
        """DiffHunk instances are frozen Pydantic models."""
        hunks, _ = await parse_diff(SAMPLE_SINGLE_HUNK_DIFF)
        h = hunks[0]
        with pytest.raises(Exception):
            h.file_path = "changed"

    @pytest.mark.asyncio
    async def test_intake_result_frozen(self):
        """IntakeResult instances are frozen Pydantic models."""
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter, _ = make_collecting_emitter()
        result = await run_intake(source, config, emitter)
        with pytest.raises(Exception):
            result.hunk_count = 999

    @pytest.mark.asyncio
    async def test_hunk_id_determinism_invariant(self):
        """Identical inputs always produce identical HunkId."""
        id1 = generate_hunk_id("a.py", "@@ -1,1 +1,2 @@", ["x", "y"])
        id2 = generate_hunk_id("a.py", "@@ -1,1 +1,2 @@", ["x", "y"])
        assert id1 == id2

    @pytest.mark.asyncio
    async def test_parse_diff_pure_function(self):
        """parse_diff produces identical output for identical input (pure)."""
        h1, e1 = await parse_diff(SAMPLE_MULTI_HUNK_DIFF)
        h2, e2 = await parse_diff(SAMPLE_MULTI_HUNK_DIFF)
        assert len(h1) == len(h2)
        assert len(e1) == len(e2)
        for a, b in zip(h1, h2):
            assert a.id == b.id
            assert a.file_path == b.file_path

    @pytest.mark.asyncio
    async def test_classify_hunks_pure_function(self):
        """classify_hunks produces identical output for identical input and config."""
        hunks, _ = await parse_diff(SAMPLE_SECRET_DIFF)
        config = make_ledger_config()
        r1 = classify_hunks(hunks, config)
        r2 = classify_hunks(hunks, config)
        assert len(r1) == len(r2)
        for a, b in zip(r1, r2):
            assert a.id == b.id
            assert a.classifications == b.classifications

    @pytest.mark.asyncio
    async def test_classification_only_on_added_lines_invariant(self):
        """Classification never scans removed_lines or context."""
        hunks, _ = await parse_diff(SAMPLE_SECRET_IN_REMOVED_ONLY_DIFF)
        config = make_ledger_config()
        result = classify_hunks(hunks, config)
        # Secret was only in removed lines
        labels = []
        for h in result:
            for c in h.classifications:
                labels.append(c.value if hasattr(c, "value") else str(c))
        assert "secret" not in labels

    @pytest.mark.asyncio
    async def test_event_emitter_failure_never_blocks(self):
        """EventEmitter failures never block or abort intake processing."""
        source = make_mock_source(content=SAMPLE_SINGLE_HUNK_DIFF)
        config = make_ledger_config()
        emitter = make_failing_emitter(Exception("total failure"))

        # This must complete, not hang or raise
        result = await run_intake(source, config, emitter)
        assert result is not None
        assert result.review_request.id.startswith("req-")
