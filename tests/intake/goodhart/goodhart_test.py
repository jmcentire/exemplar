"""
Adversarial hidden acceptance tests for the Diff Intake & Classification component.
These tests catch implementations that pass visible tests through shortcuts
(hardcoded returns, incomplete validation, etc.) rather than truly satisfying the contract.
"""
import asyncio
import hashlib
import re
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from exemplar.intake import (
    parse_diff,
    classify_hunks,
    run_intake,
    generate_hunk_id,
    generate_request_id,
    detect_language,
    LineRange,
    IntakeError,
    IntakePhase,
    DiffSourceKind,
    ClassificationLabel,
    LedgerConfig,
    LedgerFieldRule,
    DiffHunk,
)


# ============================================================
# Helpers
# ============================================================

def make_simple_diff(file_path="src/app.py", old_start=1, old_count=3, new_start=1, new_count=5,
                     context_before=None, removed=None, added=None, context_after=None,
                     section_header=""):
    """Build a minimal valid unified diff string."""
    cb = context_before or [" existing line"]
    rm = removed or ["-old line"]
    ad = added or ["+new line 1", "+new line 2", "+new line 3"]
    ca = context_after or [" trailing context"]

    lines = [
        f"diff --git a/{file_path} b/{file_path}",
        f"--- a/{file_path}",
        f"+++ b/{file_path}",
        f"@@ -{old_start},{old_count} +{new_start},{new_count} @@ {section_header}",
    ]
    lines.extend(cb)
    lines.extend(rm)
    lines.extend(ad)
    lines.extend(ca)
    return "\n".join(lines) + "\n"


def make_mock_source(content, kind=DiffSourceKind.file):
    """Create a mock DiffSource."""
    source = AsyncMock()
    source.kind = kind
    source.read = AsyncMock(return_value=content)
    return source


def make_failing_source(exc_type=IOError, kind=DiffSourceKind.file):
    """Create a mock DiffSource that raises on read."""
    source = AsyncMock()
    source.kind = kind
    source.read = AsyncMock(side_effect=exc_type("test error"))
    return source


def make_config(rules=None):
    """Create a LedgerConfig with optional rules."""
    if rules is None:
        rules = []
    return LedgerConfig(rules=rules, default_label=ClassificationLabel.public)


def make_secret_config():
    return make_config(rules=[
        LedgerFieldRule(pattern=r"API_KEY\s*=", label=ClassificationLabel.secret, description="API key detection"),
    ])


def make_pii_config():
    return make_config(rules=[
        LedgerFieldRule(pattern=r"SSN\s*[:=]", label=ClassificationLabel.pii, description="SSN detection"),
    ])


def make_multi_rule_config():
    return make_config(rules=[
        LedgerFieldRule(pattern=r"API_KEY", label=ClassificationLabel.secret, description="secret"),
        LedgerFieldRule(pattern=r"SSN", label=ClassificationLabel.pii, description="pii"),
        LedgerFieldRule(pattern=r"__internal_api", label=ClassificationLabel.internal_api, description="internal api"),
        LedgerFieldRule(pattern=r"public_docs", label=ClassificationLabel.public, description="public"),
    ])


def make_mock_emitter():
    emitter = AsyncMock()
    emitter.emit = AsyncMock()
    return emitter


def make_recording_emitter():
    """Emitter that records all events."""
    events = []
    emitter = AsyncMock()
    async def record_event(event):
        events.append(event)
    emitter.emit = AsyncMock(side_effect=record_event)
    emitter._recorded_events = events
    return emitter


# ============================================================
# generate_hunk_id tests
# ============================================================

class TestGoodhartGenerateHunkId:

    def test_goodhart_hunk_id_sha256_verification(self):
        """generate_hunk_id must compute its output using SHA-256 over the concatenation of file_path, raw_header, and joined added_lines"""
        fp = "src/controllers/auth.rb"
        rh = "@@ -50,7 +50,9 @@ def authenticate"
        al = ["  token = generate_jwt(user)", "  cache.set(token, user.id)"]

        result = generate_hunk_id(fp, rh, al)

        assert result.startswith("hunk-")
        assert len(result) == 17  # 5 + 12
        assert re.match(r'^[0-9a-f]{12}$', result[5:])

        # Independently compute SHA-256
        content = fp + rh + "\n".join(al)
        expected_hash = hashlib.sha256(content.encode()).hexdigest()[:12]
        assert result[5:] == expected_hash, (
            f"Hunk ID hash portion {result[5:]} does not match independently computed SHA-256 {expected_hash}"
        )

    def test_goodhart_hunk_id_added_lines_order_matters(self):
        """generate_hunk_id must produce different IDs when the same added_lines are provided in different order"""
        fp = "app.py"
        rh = "@@ -1,3 +1,5 @@"

        id_a = generate_hunk_id(fp, rh, ["line_alpha", "line_beta"])
        id_b = generate_hunk_id(fp, rh, ["line_beta", "line_alpha"])

        assert id_a != id_b, "Hunk IDs should differ when added_lines order differs"

    def test_goodhart_hunk_id_empty_raw_header_error(self):
        """generate_hunk_id must reject empty raw_header since the precondition requires it to be non-empty"""
        with pytest.raises((ValueError, TypeError, Exception)):
            generate_hunk_id("somefile.py", "", ["x"])

    def test_goodhart_hunk_id_special_characters(self):
        """generate_hunk_id must handle unicode and special characters in inputs without crashing"""
        fp = "src/日本語/файл.py"
        rh = "@@ -1,2 +1,3 @@ функция"
        al = ["  résultat = données + 'émoji 🎉'"]

        result = generate_hunk_id(fp, rh, al)
        assert result.startswith("hunk-")
        assert re.match(r'^[0-9a-f]{12}$', result[5:])

        # Deterministic
        assert result == generate_hunk_id(fp, rh, al)

    def test_goodhart_hunk_id_whitespace_sensitivity(self):
        """generate_hunk_id must be sensitive to whitespace differences in added_lines"""
        fp = "f.py"
        rh = "@@ -1,1 +1,1 @@"

        id_a = generate_hunk_id(fp, rh, ["  x = 1"])
        id_b = generate_hunk_id(fp, rh, ["x = 1"])

        assert id_a != id_b, "IDs should differ when added lines differ only by leading whitespace"


# ============================================================
# generate_request_id tests
# ============================================================

class TestGoodhartGenerateRequestId:

    def test_goodhart_request_id_uuid4_hex_no_hyphens(self):
        """generate_request_id must produce a 32-char hex string after 'req-' with no hyphens"""
        result = generate_request_id()
        assert result.startswith("req-")
        assert len(result) == 36, f"Expected length 36, got {len(result)}"
        hex_part = result[4:]
        assert re.match(r'^[0-9a-f]{32}$', hex_part), f"Hex part {hex_part!r} does not match expected format"
        assert "-" not in result[4:], "Hex portion should not contain hyphens"

    def test_goodhart_request_id_bulk_uniqueness(self):
        """generate_request_id must produce unique values across many calls"""
        ids = {generate_request_id() for _ in range(100)}
        assert len(ids) == 100, f"Expected 100 unique IDs, got {len(ids)}"


# ============================================================
# detect_language tests
# ============================================================

class TestGoodhartDetectLanguage:

    def test_goodhart_detect_language_java(self):
        """detect_language must correctly map .java extension"""
        assert detect_language("com/example/Main.java") == "java"

    def test_goodhart_detect_language_go(self):
        """detect_language must correctly map .go extension"""
        assert detect_language("cmd/server/main.go") == "go"

    def test_goodhart_detect_language_rust(self):
        """detect_language must correctly map .rs extension"""
        assert detect_language("src/lib.rs") == "rust"

    def test_goodhart_detect_language_cpp(self):
        """detect_language must handle C++ file extensions like .cpp"""
        result = detect_language("src/engine.cpp")
        assert result != "unknown", ".cpp should be recognized"
        assert result.lower() in ("cpp", "c++"), f"Expected cpp or c++, got {result}"

    def test_goodhart_detect_language_ruby(self):
        """detect_language must correctly map .rb extension"""
        assert detect_language("app/models/user.rb") == "ruby"

    def test_goodhart_detect_language_mixed_case_PY(self):
        """detect_language must be case-insensitive — .PY should map same as .py"""
        assert detect_language("script.PY") == detect_language("script.py")

    def test_goodhart_detect_language_path_with_dots(self):
        """detect_language must use only the final extension for language detection"""
        result = detect_language("my.module.config.json")
        assert result != "unknown", ".json should be recognized"

    def test_goodhart_detect_language_result_always_lowercase(self):
        """detect_language must always return a lowercase string"""
        result = detect_language("DIR/FILE.Py")
        assert result == result.lower(), f"Result {result!r} is not lowercase"

    def test_goodhart_detect_language_hidden_dotfile_with_extension(self):
        """detect_language should detect language from secondary extension on dotfiles"""
        result = detect_language(".config.yml")
        # .yml should be recognized as yaml
        assert result != "unknown", ".yml secondary extension should be recognized"

    def test_goodhart_detect_language_c_header(self):
        """detect_language must handle .h extension"""
        result = detect_language("include/types.h")
        assert result != "unknown", ".h should be recognized"

    def test_goodhart_detect_language_yaml(self):
        """detect_language must handle .yml extension"""
        result = detect_language("config/settings.yml")
        assert result != "unknown", ".yml should be recognized"

    def test_goodhart_detect_language_markdown(self):
        """detect_language must handle .md extension"""
        result = detect_language("README.md")
        assert result != "unknown", ".md should be recognized"


# ============================================================
# parse_diff tests
# ============================================================

class TestGoodhartParseDiff:

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_context_lines_separated(self):
        """parse_diff must correctly separate context lines from added/removed lines"""
        diff = (
            "diff --git a/hello.py b/hello.py\n"
            "--- a/hello.py\n"
            "+++ b/hello.py\n"
            "@@ -1,5 +1,6 @@\n"
            " first context\n"
            " second context\n"
            "-removed line\n"
            "+added line A\n"
            "+added line B\n"
            " trailing context\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        hunk = hunks[0]
        # Context should not be in added or removed
        for line in hunk.added_lines:
            assert "first context" not in line
            assert "trailing context" not in line
        for line in hunk.removed_lines:
            assert "first context" not in line
            assert "trailing context" not in line
        # Added lines should contain the additions
        added_text = "\n".join(hunk.added_lines)
        assert "added line A" in added_text
        assert "added line B" in added_text
        # Removed lines should contain the removal
        removed_text = "\n".join(hunk.removed_lines)
        assert "removed line" in removed_text

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_line_numbers_consistency(self):
        """parse_diff must set line number fields from @@ header accurately"""
        diff = (
            "diff --git a/x.py b/x.py\n"
            "--- a/x.py\n"
            "+++ b/x.py\n"
            "@@ -10,5 +12,8 @@ def foo\n"
            " context\n"
            "-old\n"
            "+new1\n"
            "+new2\n"
            " context\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        hunk = hunks[0]
        assert hunk.start_line_old == 10
        assert hunk.count_old == 5
        assert hunk.start_line_new == 12
        assert hunk.count_new == 8

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_hunk_id_matches_generate_hunk_id(self):
        """DiffHunk.id from parse_diff must match generate_hunk_id called independently"""
        diff = make_simple_diff(file_path="verify/test.py")
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        for hunk in hunks:
            expected_id = generate_hunk_id(hunk.file_path, hunk.raw_header, hunk.added_lines)
            assert hunk.id == expected_id, (
                f"Hunk ID {hunk.id} does not match generate_hunk_id result {expected_id}"
            )

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_git_format_header(self):
        """parse_diff must handle 'diff --git a/path b/path' format headers"""
        diff = (
            "diff --git a/lib/util.js b/lib/util.js\n"
            "--- a/lib/util.js\n"
            "+++ b/lib/util.js\n"
            "@@ -1,3 +1,4 @@\n"
            " const x = 1;\n"
            "+const y = 2;\n"
            " module.exports = x;\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        assert hunks[0].file_path == "lib/util.js"
        assert hunks[0].language == "javascript"

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_new_file_mode(self):
        """parse_diff must handle newly created files where old side is /dev/null"""
        diff = (
            "diff --git a/new_file.py b/new_file.py\n"
            "--- /dev/null\n"
            "+++ b/new_file.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+line 1\n"
            "+line 2\n"
            "+line 3\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        assert hunks[0].file_path != "/dev/null"
        assert "new_file.py" in hunks[0].file_path

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_deleted_file(self):
        """parse_diff must handle deleted files where new side is /dev/null"""
        diff = (
            "diff --git a/old_file.py b/old_file.py\n"
            "--- a/old_file.py\n"
            "+++ /dev/null\n"
            "@@ -1,3 +0,0 @@\n"
            "-line 1\n"
            "-line 2\n"
            "-line 3\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        hunk = hunks[0]
        assert hunk.file_path != "/dev/null"
        assert "old_file.py" in hunk.file_path
        assert len(hunk.removed_lines) > 0
        assert len(hunk.added_lines) == 0

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_no_newline_at_eof(self):
        """parse_diff must handle 'No newline at end of file' marker gracefully"""
        diff = (
            "diff --git a/f.py b/f.py\n"
            "--- a/f.py\n"
            "+++ b/f.py\n"
            "@@ -1,2 +1,2 @@\n"
            "-old line\n"
            "\\ No newline at end of file\n"
            "+new line\n"
            "\\ No newline at end of file\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        hunk = hunks[0]
        # The marker should not appear in content
        for line in hunk.added_lines + hunk.removed_lines:
            assert "No newline at end of file" not in line

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_multiple_errors_for_multiple_bad_hunks(self):
        """parse_diff must produce separate IntakeError records for each malformed section"""
        diff = (
            "diff --git a/a.py b/a.py\n"
            "--- a/a.py\n"
            "+++ b/a.py\n"
            "@@ INVALID HEADER 1 @@\n"
            "+content\n"
            "diff --git a/b.py b/b.py\n"
            "--- a/b.py\n"
            "+++ b/b.py\n"
            "@@ ALSO INVALID @@\n"
            "+more content\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(errors) >= 2, f"Expected at least 2 errors, got {len(errors)}"
        for err in errors:
            assert err.phase == IntakePhase.parse or str(err.phase) == "parse"
            assert err.message and len(err.message) > 0

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_large_line_numbers(self):
        """parse_diff must handle very large line numbers without overflow"""
        diff = (
            "diff --git a/big.py b/big.py\n"
            "--- a/big.py\n"
            "+++ b/big.py\n"
            "@@ -99999,3 +100001,5 @@ class Huge\n"
            " context\n"
            "-old\n"
            "+new1\n"
            "+new2\n"
            "+new3\n"
            " context\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        assert hunks[0].start_line_old == 99999
        assert hunks[0].start_line_new == 100001

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_only_additions(self):
        """parse_diff must handle a hunk with only additions and no removals"""
        diff = (
            "diff --git a/add.py b/add.py\n"
            "--- a/add.py\n"
            "+++ b/add.py\n"
            "@@ -5,2 +5,5 @@\n"
            " context\n"
            "+added1\n"
            "+added2\n"
            "+added3\n"
            " context\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        assert len(hunks[0].removed_lines) == 0
        assert len(hunks[0].added_lines) >= 3

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_only_removals(self):
        """parse_diff must handle a hunk with only removals and no additions"""
        diff = (
            "diff --git a/rm.py b/rm.py\n"
            "--- a/rm.py\n"
            "+++ b/rm.py\n"
            "@@ -1,5 +1,2 @@\n"
            " context\n"
            "-removed1\n"
            "-removed2\n"
            "-removed3\n"
            " context\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        assert len(hunks[0].added_lines) == 0
        assert len(hunks[0].removed_lines) >= 3

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_file_path_with_spaces(self):
        """parse_diff must handle file paths containing spaces"""
        diff = (
            "diff --git a/my folder/my file.py b/my folder/my file.py\n"
            "--- a/my folder/my file.py\n"
            "+++ b/my folder/my file.py\n"
            "@@ -1,2 +1,3 @@\n"
            " ctx\n"
            "+new\n"
            " ctx\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        assert " " in hunks[0].file_path
        assert "/" in hunks[0].file_path

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_crlf_line_endings(self):
        """parse_diff must handle CRLF line endings without errors or mangled output"""
        diff = (
            "diff --git a/crlf.py b/crlf.py\r\n"
            "--- a/crlf.py\r\n"
            "+++ b/crlf.py\r\n"
            "@@ -1,3 +1,4 @@\r\n"
            " context\r\n"
            "-old line\r\n"
            "+new line\r\n"
            "+extra line\r\n"
            " context\r\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        # Added lines should not have trailing \r
        for line in hunks[0].added_lines:
            assert not line.endswith("\r"), f"Line should not end with \\r: {line!r}"

    @pytest.mark.asyncio
    async def test_goodhart_parse_diff_classifications_always_empty_novel_input(self):
        """parse_diff must never populate classifications, verified with a novel diff input"""
        diff = (
            "diff --git a/secret.py b/secret.py\n"
            "--- a/secret.py\n"
            "+++ b/secret.py\n"
            "@@ -1,1 +1,2 @@\n"
            " x\n"
            "+API_KEY = 'super_secret_value_12345'\n"
        )
        hunks, errors = await parse_diff(diff)
        assert len(hunks) >= 1
        for hunk in hunks:
            assert hunk.classifications == [], "parse_diff must never populate classifications"


# ============================================================
# classify_hunks tests
# ============================================================

class TestGoodhartClassifyHunks:

    def _make_hunk(self, added_lines, removed_lines=None, context_before=None,
                   context_after=None, file_path="test.py", hunk_id=None):
        """Create a minimal DiffHunk-like object for testing."""
        if removed_lines is None:
            removed_lines = []
        if context_before is None:
            context_before = []
        if context_after is None:
            context_after = []
        raw_header = "@@ -1,3 +1,5 @@"
        if hunk_id is None:
            hunk_id = generate_hunk_id(file_path, raw_header, added_lines)
        return DiffHunk(
            id=hunk_id,
            file_path=file_path,
            start_line_old=1,
            count_old=3,
            start_line_new=1,
            count_new=5,
            context_before=context_before,
            added_lines=added_lines,
            removed_lines=removed_lines,
            context_after=context_after,
            raw_header=raw_header,
            classifications=[],
            language="python",
        )

    def test_goodhart_classify_context_lines_ignored(self):
        """classify_hunks must not scan context_before or context_after for classification"""
        hunk = self._make_hunk(
            added_lines=["x = 1"],
            context_before=["API_KEY = secret123"],
            context_after=["SSN: 123-45-6789"],
        )
        config = make_config(rules=[
            LedgerFieldRule(pattern=r"API_KEY", label=ClassificationLabel.secret, description="secret"),
            LedgerFieldRule(pattern=r"SSN", label=ClassificationLabel.pii, description="pii"),
        ])
        result = classify_hunks([hunk], config)
        assert len(result) == 1
        assert result[0].classifications == [], (
            "Context lines should not trigger classification"
        )

    def test_goodhart_classify_same_label_multiple_lines_no_dup(self):
        """classify_hunks must not produce duplicate labels even when same pattern matches multiple lines"""
        hunk = self._make_hunk(
            added_lines=[
                "API_KEY = 'key1'",
                "API_KEY = 'key2'",
                "API_KEY = 'key3'",
            ]
        )
        config = make_config(rules=[
            LedgerFieldRule(pattern=r"API_KEY", label=ClassificationLabel.secret, description="secret"),
        ])
        result = classify_hunks([hunk], config)
        assert len(result) == 1
        labels = result[0].classifications
        assert labels.count(ClassificationLabel.secret) == 1, (
            f"Expected exactly one 'secret' label, got {labels}"
        )

    def test_goodhart_classify_evidence_matches_classifications_length(self):
        """classification_evidence must have same length as classifications"""
        hunks = [
            self._make_hunk(added_lines=["nothing here"], file_path="a.py"),
            self._make_hunk(added_lines=["API_KEY=x"], file_path="b.py"),
            self._make_hunk(added_lines=["API_KEY=x", "SSN: 123"], file_path="c.py"),
        ]
        config = make_config(rules=[
            LedgerFieldRule(pattern=r"API_KEY", label=ClassificationLabel.secret, description="secret"),
            LedgerFieldRule(pattern=r"SSN", label=ClassificationLabel.pii, description="pii"),
        ])
        result = classify_hunks(hunks, config)
        assert len(result) == 3
        for h in result:
            if hasattr(h, 'classification_evidence'):
                assert len(h.classification_evidence) == len(h.classifications), (
                    f"Evidence length {len(h.classification_evidence)} != classifications length {len(h.classifications)}"
                )

    def test_goodhart_classify_preserves_id_exactly(self):
        """classify_hunks must preserve exact hunk IDs from input"""
        hunk = self._make_hunk(added_lines=["API_KEY=secret"], file_path="id_test.py")
        original_id = hunk.id
        config = make_secret_config()
        result = classify_hunks([hunk], config)
        assert result[0].id == original_id

    def test_goodhart_classify_preserves_language(self):
        """classify_hunks must preserve the language field"""
        hunk = self._make_hunk(added_lines=["x"], file_path="test.py")
        config = make_config()
        result = classify_hunks([hunk], config)
        assert result[0].language == hunk.language

    def test_goodhart_classify_all_four_labels_possible(self):
        """classify_hunks must be able to assign any of the four ClassificationLabel values"""
        hunks = [
            self._make_hunk(added_lines=["API_KEY=x"], file_path="1.py"),
            self._make_hunk(added_lines=["SSN: 123-45-6789"], file_path="2.py"),
            self._make_hunk(added_lines=["__internal_api.call()"], file_path="3.py"),
            self._make_hunk(added_lines=["public_docs link"], file_path="4.py"),
        ]
        config = make_multi_rule_config()
        result = classify_hunks(hunks, config)

        all_labels = set()
        for h in result:
            for label in h.classifications:
                all_labels.add(label)

        assert ClassificationLabel.secret in all_labels, "secret label missing"
        assert ClassificationLabel.pii in all_labels, "pii label missing"
        assert ClassificationLabel.internal_api in all_labels, "internal_api label missing"
        assert ClassificationLabel.public in all_labels, "public label missing"

    def test_goodhart_classify_new_hunk_instances(self):
        """classify_hunks must return new DiffHunk instances, not the same objects"""
        hunk = self._make_hunk(added_lines=["API_KEY=x"])
        config = make_secret_config()
        result = classify_hunks([hunk], config)
        assert result[0] is not hunk, "Output hunk should be a new instance, not the same object"

    def test_goodhart_classify_regex_anchoring(self):
        """classify_hunks must apply regex patterns correctly including anchors"""
        hunk = self._make_hunk(
            added_lines=["MY_SECRET=foo", "SECRET=bar"]
        )
        config = make_config(rules=[
            LedgerFieldRule(pattern=r"^SECRET=", label=ClassificationLabel.secret, description="anchored secret"),
        ])
        result = classify_hunks([hunk], config)
        assert len(result) == 1
        # The pattern should match the line starting with SECRET= but the test is that
        # regex semantics are properly applied (not just substring search)
        assert ClassificationLabel.secret in result[0].classifications


# ============================================================
# run_intake tests
# ============================================================

class TestGoodhartRunIntake:

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_file_paths_deduped(self):
        """run_intake must populate file_paths with unique paths from parsed hunks"""
        diff = (
            "diff --git a/file1.py b/file1.py\n"
            "--- a/file1.py\n"
            "+++ b/file1.py\n"
            "@@ -1,2 +1,3 @@\n"
            " ctx\n"
            "+add1\n"
            " ctx\n"
            "@@ -10,2 +11,3 @@\n"
            " ctx\n"
            "+add2\n"
            " ctx\n"
            "diff --git a/file2.js b/file2.js\n"
            "--- a/file2.js\n"
            "+++ b/file2.js\n"
            "@@ -1,2 +1,3 @@\n"
            " ctx\n"
            "+add3\n"
            " ctx\n"
        )
        source = make_mock_source(diff)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        fps = result.review_request.file_paths
        assert len(fps) == 2, f"Expected 2 file paths, got {len(fps)}: {fps}"
        assert len(set(fps)) == len(fps), "file_paths should be unique"

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_hunk_count_equals_hunks_length(self):
        """IntakeResult.hunk_count must equal the actual length of review_request.hunks"""
        diff = make_simple_diff()
        source = make_mock_source(diff)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        assert result.hunk_count == len(result.review_request.hunks)

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_classified_count_lte_hunk_count(self):
        """IntakeResult.classified_hunk_count must be <= hunk_count"""
        diff = make_simple_diff()
        source = make_mock_source(diff)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        assert result.classified_hunk_count <= result.hunk_count

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_emitter_partial_failure_warnings(self):
        """When emitter fails on some calls, failures appear in warnings, not errors"""
        diff = make_simple_diff()
        source = make_mock_source(diff)
        config = make_config()
        call_count = 0
        emitter = AsyncMock()

        async def partial_fail(event):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise RuntimeError("emit failed")

        emitter.emit = AsyncMock(side_effect=partial_fail)

        result = await run_intake(source, config, emitter)
        assert len(result.warnings) > 0, "Emitter failure should appear in warnings"
        # Errors should not contain emitter failures
        for err in result.errors:
            if hasattr(err, 'phase'):
                assert str(err.phase) != "orchestrate" or "emit" not in str(err.message).lower()
        assert len(result.review_request.hunks) > 0, "Hunks should still be present"

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_permission_error(self):
        """run_intake must handle PermissionError from source.read() gracefully"""
        source = make_failing_source(PermissionError)
        config = make_config()
        emitter = make_mock_emitter()

        # Should not raise an unhandled exception
        result = await run_intake(source, config, emitter)
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_file_not_found_error(self):
        """run_intake must handle FileNotFoundError from source.read() gracefully"""
        source = make_failing_source(FileNotFoundError)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_totally_unparseable(self):
        """run_intake must handle completely unparseable input producing empty hunks with errors"""
        source = make_mock_source("this is not a diff at all\njust random text\n")
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        assert len(result.review_request.hunks) == 0
        assert result.hunk_count == 0
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_request_id_format_deep(self):
        """review_request.id must be exactly 'req-' + 32 lowercase hex chars with no hyphens"""
        diff = make_simple_diff()
        source = make_mock_source(diff)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        rid = result.review_request.id
        assert rid.startswith("req-")
        assert len(rid) == 36
        hex_part = rid[4:]
        assert re.match(r'^[0-9a-f]{32}$', hex_part), f"Hex part {hex_part!r} invalid"
        assert "-" not in rid[4:]

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_created_at_has_timezone(self):
        """created_at timestamp must include UTC timezone indicator"""
        diff = make_simple_diff()
        source = make_mock_source(diff)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        ts = result.review_request.created_at
        assert ts.endswith("Z") or ts.endswith("+00:00"), (
            f"Timestamp {ts!r} must end with Z or +00:00"
        )
        # Also verify it's parseable
        from datetime import datetime
        try:
            # Try parsing ISO format
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            pytest.fail(f"Timestamp {ts!r} is not valid ISO 8601")

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_hunks_are_classified(self):
        """Hunks in result must have been through classify_hunks (classifications populated when rules match)"""
        diff = (
            "diff --git a/secret.py b/secret.py\n"
            "--- a/secret.py\n"
            "+++ b/secret.py\n"
            "@@ -1,1 +1,2 @@\n"
            " x\n"
            "+API_KEY = 'super_secret_value'\n"
        )
        source = make_mock_source(diff)
        config = make_secret_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        assert len(result.review_request.hunks) >= 1
        classified = [h for h in result.review_request.hunks if len(h.classifications) > 0]
        assert len(classified) > 0, "At least one hunk should be classified with secret"
        assert ClassificationLabel.secret in classified[0].classifications

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_source_kind_file(self):
        """run_intake must set source field matching DiffSource kind 'file'"""
        diff = make_simple_diff()
        source = make_mock_source(diff, kind=DiffSourceKind.file)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        # The source field should reflect the kind
        src = result.review_request.source
        assert "file" in str(src).lower() or src == "file" or src == DiffSourceKind.file

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_source_kind_stdin(self):
        """run_intake must set source field matching DiffSource kind 'stdin'"""
        diff = make_simple_diff()
        source = make_mock_source(diff, kind=DiffSourceKind.stdin)
        config = make_config()
        emitter = make_mock_emitter()

        result = await run_intake(source, config, emitter)
        src = result.review_request.source
        assert "stdin" in str(src).lower() or src == "stdin" or src == DiffSourceKind.stdin

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_events_have_review_request_id(self):
        """All emitted events must reference the same review_request_id as the final result"""
        diff = make_simple_diff()
        source = make_mock_source(diff)
        config = make_config()
        emitter = make_recording_emitter()

        result = await run_intake(source, config, emitter)
        events = emitter._recorded_events

        rid = result.review_request.id
        for event in events:
            assert event.review_request_id == rid, (
                f"Event review_request_id {event.review_request_id!r} != result id {rid!r}"
            )

    @pytest.mark.asyncio
    async def test_goodhart_run_intake_multiple_calls_unique_ids(self):
        """Multiple calls to run_intake must produce different review_request.id values"""
        diff = make_simple_diff()
        config = make_config()
        emitter = make_mock_emitter()

        source1 = make_mock_source(diff)
        result1 = await run_intake(source1, config, emitter)

        source2 = make_mock_source(diff)
        result2 = await run_intake(source2, config, emitter)

        assert result1.review_request.id != result2.review_request.id, (
            "Two run_intake calls should produce different request IDs"
        )


# ============================================================
# LineRange / IntakeError additional tests
# ============================================================

class TestGoodhartModels:

    def test_goodhart_line_range_start_exactly_one(self):
        """LineRange must accept start=1 as the boundary minimum"""
        lr = LineRange(start=1, count=0)
        assert lr.start == 1
        assert lr.count == 0

    def test_goodhart_line_range_start_zero_rejected(self):
        """LineRange must reject start=0"""
        with pytest.raises(Exception):
            LineRange(start=0, count=5)

    def test_goodhart_line_range_large_values(self):
        """LineRange must accept large valid values"""
        lr = LineRange(start=999999, count=999999)
        assert lr.start == 999999
        assert lr.count == 999999

    def test_goodhart_intake_error_all_phases(self):
        """IntakeError must accept all four IntakePhase values"""
        for phase in [IntakePhase.read, IntakePhase.parse, IntakePhase.classify, IntakePhase.orchestrate]:
            err = IntakeError(line_number=1, message="test", raw_content="x", phase=phase)
            assert err.phase == phase
