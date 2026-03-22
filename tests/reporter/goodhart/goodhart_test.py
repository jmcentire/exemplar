"""
Adversarial hidden acceptance tests for the Report Formatter & Sealer component.
These tests catch implementations that pass visible tests through shortcuts
(hardcoded returns, incomplete logic, etc.) rather than truly satisfying the contract.
"""
import hashlib
import json
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock

from exemplar.reporter import (
    canonicalize,
    seal_report,
    verify_seal,
    format_report,
    render_json,
    render_markdown,
    render_github,
    ReviewReport,
    ReviewDecision,
    Finding,
    Assessment,
    Confidence,
    TrustScore,
    TesseraSeal,
    Severity,
    ReviewStage,
    OutputFormat,
    FormattedReport,
    SealVerificationResult,
    ReportId,
    Iso8601Timestamp,
    Sha256Hex,
    SealerId,
    GithubCharLimit,
)


# ---- Helpers ----

def make_finding(
    id="f1",
    hunk_id="h1",
    file_path="src/main.py",
    line_number=10,
    severity="medium",
    confidence="high",
    title="Test Finding",
    description="A test finding",
    suggestion=None,
    rule_id="R001",
    stage="security",
):
    return Finding(
        id=id,
        hunk_id=hunk_id,
        file_path=file_path,
        line_number=line_number,
        severity=severity,
        confidence=confidence,
        title=title,
        description=description,
        suggestion=suggestion,
        rule_id=rule_id,
        stage=stage,
    )


def make_assessment(
    id="a1",
    review_request_id="rr1",
    stage="security",
    reviewer_id="rev1",
    decision="pass",
    findings=None,
    confidence="high",
    is_partial=False,
    error_message=None,
    duration_ms=100,
    created_at="2024-01-01T00:00:00Z",
):
    return Assessment(
        id=id,
        review_request_id=review_request_id,
        stage=stage,
        reviewer_id=reviewer_id,
        decision=decision,
        findings=findings or [],
        confidence=confidence,
        is_partial=is_partial,
        error_message=error_message,
        duration_ms=duration_ms,
        created_at=created_at,
    )


def make_report(
    id="report-adv-001",
    review_request_id="rr-adv-001",
    decision="pass",
    findings=None,
    assessments=None,
    confidence="high",
    trust_scores=None,
    conflict_notes=None,
    summary="Adversarial test report",
    seal=None,
    created_at="2024-06-15T12:00:00Z",
    metadata=None,
):
    return ReviewReport(
        id=id,
        review_request_id=review_request_id,
        decision=decision,
        findings=findings or [],
        assessments=assessments or [],
        confidence=confidence,
        trust_scores=trust_scores or [],
        conflict_notes=conflict_notes or [],
        summary=summary,
        seal=seal,
        created_at=created_at,
        metadata=metadata or {},
    )


def make_chain_store(previous_hash=None):
    """Create a mock chain store that returns the given previous hash."""
    store = MagicMock()
    store.get_previous_hash = MagicMock(return_value=previous_hash)
    store.append_seal = MagicMock()
    return store


FIXED_TIMESTAMP = "2024-07-01T10:30:00Z"


# ---- Canonicalize Tests ----

class TestGoodhartCanonicalize:
    def test_goodhart_canonicalize_different_reports_different_bytes(self):
        """Canonicalize must produce distinct byte outputs for reports that differ in any field"""
        report1 = make_report(summary="Summary Alpha")
        report2 = make_report(summary="Summary Beta")
        report3 = make_report(decision="block")
        report4 = make_report(decision="warn")

        bytes1 = canonicalize(report1)
        bytes2 = canonicalize(report2)
        bytes3 = canonicalize(report3)
        bytes4 = canonicalize(report4)

        assert bytes1 != bytes2, "Different summaries must produce different canonical bytes"
        assert bytes3 != bytes4, "Different decisions must produce different canonical bytes"
        assert bytes1 != bytes3, "Different fields must produce different canonical bytes"

    def test_goodhart_canonicalize_sorted_keys_nested(self):
        """Canonical output must have lexicographically sorted keys at all nesting levels"""
        finding = make_finding(id="f-nested", file_path="z_file.py", severity="critical")
        report = make_report(findings=[finding])
        raw = canonicalize(report)
        parsed = json.loads(raw)

        def check_sorted_keys(obj, path="root"):
            if isinstance(obj, dict):
                keys = list(obj.keys())
                assert keys == sorted(keys), f"Keys not sorted at {path}: {keys}"
                for k, v in obj.items():
                    check_sorted_keys(v, path=f"{path}.{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_sorted_keys(item, path=f"{path}[{i}]")

        check_sorted_keys(parsed)

    def test_goodhart_canonicalize_no_whitespace(self):
        """Canonical byte representation must use compact separators with zero whitespace"""
        finding = make_finding()
        report = make_report(findings=[finding], metadata={"key": "value"})
        raw = canonicalize(report)
        text = raw.decode("utf-8")

        # Compact JSON should have no ": " (colon-space) or ", " (comma-space)
        # but we need to be careful about values containing these patterns.
        # Instead, re-serialize to verify compact form matches.
        parsed = json.loads(text)
        expected = json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert text == expected, "Canonical output must use compact separators"
        assert "\n" not in text, "Canonical output must not contain newlines"

    def test_goodhart_canonicalize_unicode_content(self):
        """Canonicalize must handle non-ASCII unicode without escaping (ensure_ascii=False)"""
        report = make_report(
            summary="审查报告 — résumé with émojis 🔍 and ñ"
        )
        raw = canonicalize(report)
        text = raw.decode("utf-8")
        assert "审查报告" in text, "Chinese characters must appear unescaped"
        assert "résumé" in text, "Accented characters must appear unescaped"
        assert "🔍" in text, "Emoji must appear unescaped"
        assert "\\u" not in text.replace("\\u0000", ""), "Unicode should not be escaped"

    def test_goodhart_canonicalize_metadata_ordering(self):
        """Canonical output must sort metadata dictionary keys regardless of insertion order"""
        report1 = make_report(metadata={"zebra": "1", "alpha": "2", "middle": "3"})
        raw = canonicalize(report1)
        text = raw.decode("utf-8")

        # Find the metadata section and check key ordering
        parsed = json.loads(text)
        meta_keys = list(parsed["metadata"].keys())
        assert meta_keys == sorted(meta_keys), f"Metadata keys must be sorted: {meta_keys}"

    def test_goodhart_canonicalize_with_conflict_notes(self):
        """Canonicalize must include conflict_notes and produce different bytes when they differ"""
        report_with = make_report(conflict_notes=["note1", "note2"])
        report_without = make_report(conflict_notes=[])
        bytes_with = canonicalize(report_with)
        bytes_without = canonicalize(report_without)
        assert bytes_with != bytes_without, "conflict_notes changes must affect canonical bytes"
        text = bytes_with.decode("utf-8")
        assert "note1" in text, "conflict_notes content must be in canonical output"

    def test_goodhart_canonicalize_with_metadata_changes(self):
        """Canonicalize must reflect metadata changes in output"""
        report1 = make_report(metadata={"key": "value1"})
        report2 = make_report(metadata={"key": "value2"})
        assert canonicalize(report1) != canonicalize(report2), "Metadata changes must produce different bytes"


# ---- Seal Report Tests ----

class TestGoodhartSealReport:
    @pytest.fixture
    def event_loop(self):
        loop = asyncio.new_event_loop()
        yield loop
        loop.close()

    def test_goodhart_seal_report_content_hash_is_sha256_of_canonical(self):
        """The seal's content_hash must be the actual SHA-256 of canonicalize output"""
        report = make_report(
            id="rpt-hash-verify-001",
            summary="Verify hash computation independently"
        )
        chain_store = make_chain_store(previous_hash=None)

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "test-sealer", FIXED_TIMESTAMP, None)
        )

        canonical_bytes = canonicalize(report)
        expected_hash = hashlib.sha256(canonical_bytes).hexdigest()
        assert sealed.seal.content_hash == expected_hash, \
            f"content_hash must be SHA-256 of canonical bytes: expected {expected_hash}, got {sealed.seal.content_hash}"

    def test_goodhart_seal_report_chain_hash_genesis_computation(self):
        """Genesis chain_hash must be SHA-256 of (content_hash + '|GENESIS')"""
        report = make_report(id="rpt-genesis-verify")
        chain_store = make_chain_store(previous_hash=None)

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer-g", FIXED_TIMESTAMP, None)
        )

        content_hash = sealed.seal.content_hash
        expected_chain = hashlib.sha256(
            (content_hash + "|GENESIS").encode()
        ).hexdigest()
        assert sealed.seal.chain_hash == expected_chain, \
            f"Genesis chain_hash mismatch: expected {expected_chain}, got {sealed.seal.chain_hash}"
        assert sealed.seal.previous_hash is None, "Genesis seal should have None previous_hash"

    def test_goodhart_seal_report_chain_hash_with_specific_previous(self):
        """Chain hash with a specific previous hash must use that exact value in computation"""
        report = make_report(id="rpt-chain-specific")
        specific_prev = "abcd1234" * 8  # 64-char hex string
        chain_store = make_chain_store(previous_hash=specific_prev)

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer-c", FIXED_TIMESTAMP, None)
        )

        content_hash = sealed.seal.content_hash
        expected_chain = hashlib.sha256(
            (content_hash + "|" + specific_prev).encode()
        ).hexdigest()
        assert sealed.seal.chain_hash == expected_chain, \
            f"Chained chain_hash mismatch: expected {expected_chain}, got {sealed.seal.chain_hash}"
        assert sealed.seal.previous_hash == specific_prev

    def test_goodhart_seal_report_sealer_id_preserved(self):
        """seal.sealer_id must exactly match the provided sealer_id"""
        report = make_report(id="rpt-sealer-id-test")
        chain_store = make_chain_store()
        unusual_sealer = "sealer-with-special_chars.v2"

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, unusual_sealer, FIXED_TIMESTAMP, None)
        )

        assert sealed.seal.sealer_id == unusual_sealer

    def test_goodhart_seal_report_timestamp_preserved(self):
        """seal.sealed_at must exactly match the injected timestamp"""
        report = make_report(id="rpt-ts-test")
        chain_store = make_chain_store()
        unusual_ts = "2099-12-31T23:59:59Z"

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", unusual_ts, None)
        )

        assert sealed.seal.sealed_at == unusual_ts

    def test_goodhart_seal_report_append_seal_called_once(self):
        """seal_report must call chain_store.append_seal exactly once"""
        report = make_report(id="rpt-append-test")
        chain_store = make_chain_store()

        asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )

        assert chain_store.append_seal.call_count == 1, \
            f"append_seal should be called exactly once, was called {chain_store.append_seal.call_count} times"

    def test_goodhart_seal_report_all_non_seal_fields_preserved(self):
        """Every field except seal must be identical between input and output"""
        findings = [
            make_finding(id="f1", severity="critical", file_path="a.py"),
            make_finding(id="f2", severity="low", file_path="b.py"),
        ]
        assessments = [make_assessment(id="a1")]
        trust_scores = [
            TrustScore(
                reviewer_id="rev1", stage="security", weight=0.8,
                accepted_count=5, dismissed_count=1, updated_at="2024-01-01T00:00:00Z"
            )
        ]
        report = make_report(
            id="rpt-field-preserve",
            findings=findings,
            assessments=assessments,
            trust_scores=trust_scores,
            conflict_notes=["conflict A", "conflict B"],
            metadata={"custom_key": "custom_value"},
            decision="block",
            confidence="low",
            summary="Detailed summary for field preservation test",
        )
        chain_store = make_chain_store()

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )

        assert sealed.id == report.id
        assert sealed.review_request_id == report.review_request_id
        assert sealed.decision == report.decision
        assert sealed.confidence == report.confidence
        assert sealed.summary == report.summary
        assert sealed.created_at == report.created_at
        assert sealed.metadata == report.metadata
        assert sealed.conflict_notes == report.conflict_notes
        assert len(sealed.findings) == len(report.findings)
        assert len(sealed.assessments) == len(report.assessments)
        assert len(sealed.trust_scores) == len(report.trust_scores)
        for i, (sf, rf) in enumerate(zip(sealed.findings, report.findings)):
            assert sf.id == rf.id, f"Finding {i} id mismatch"

    def test_goodhart_seal_report_no_callback_still_works(self):
        """seal_report must work correctly when chronicler_callback is None"""
        report = make_report(id="rpt-no-callback")
        chain_store = make_chain_store()

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )

        assert sealed.seal is not None
        assert sealed.seal.content_hash != ""
        assert sealed.seal.chain_hash != ""

    def test_goodhart_seal_report_returns_new_instance(self):
        """seal_report must return a distinct object, not the same reference"""
        report = make_report(id="rpt-new-instance")
        chain_store = make_chain_store()

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )

        assert sealed is not report, "Must return a new instance"
        assert report.seal is None, "Original must remain unsealed"
        assert sealed.seal is not None, "New instance must be sealed"

    def test_goodhart_seal_report_chain_hash_pipe_separator(self):
        """Chain hash must use '|' as separator, not another delimiter"""
        report = make_report(id="rpt-pipe-sep")
        prev_hash = "1111111111111111111111111111111111111111111111111111111111111111"
        chain_store = make_chain_store(previous_hash=prev_hash)

        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )

        content_hash = sealed.seal.content_hash
        # Correct: pipe separator
        correct_chain = hashlib.sha256((content_hash + "|" + prev_hash).encode()).hexdigest()
        # Wrong: other separators
        wrong_dash = hashlib.sha256((content_hash + "-" + prev_hash).encode()).hexdigest()
        wrong_none = hashlib.sha256((content_hash + prev_hash).encode()).hexdigest()

        assert sealed.seal.chain_hash == correct_chain
        assert sealed.seal.chain_hash != wrong_dash, "Must not use '-' separator"
        assert sealed.seal.chain_hash != wrong_none, "Must not concatenate without separator"


# ---- Verify Seal Tests ----

class TestGoodhartVerifySeal:
    def _make_sealed_report(self, **kwargs):
        """Helper to create a sealed report for verification tests."""
        report = make_report(**kwargs)
        chain_store = make_chain_store()
        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )
        return sealed

    def test_goodhart_verify_seal_missing_seal_result_fields(self):
        """Missing seal verification must set correct status and all boolean fields to False"""
        report = make_report(id="rpt-no-seal")
        result = verify_seal(report)

        assert result.status == "missing_seal"
        assert result.valid is False
        assert result.content_hash_match is False
        assert result.chain_hash_match is False

    def test_goodhart_verify_seal_expected_vs_actual_hash_fields(self):
        """Expected hashes come from seal, actual hashes are freshly recomputed"""
        sealed = self._make_sealed_report(id="rpt-hash-fields")
        result = verify_seal(sealed)

        # Expected comes from seal
        assert result.expected_content_hash == sealed.seal.content_hash
        assert result.expected_chain_hash == sealed.seal.chain_hash

        # Actual is independently computed
        canonical_bytes = canonicalize(sealed)
        independent_content_hash = hashlib.sha256(canonical_bytes).hexdigest()
        assert result.actual_content_hash == independent_content_hash

        prev = sealed.seal.previous_hash or "GENESIS"
        independent_chain_hash = hashlib.sha256(
            (independent_content_hash + "|" + prev).encode()
        ).hexdigest()
        assert result.actual_chain_hash == independent_chain_hash

    def test_goodhart_verify_seal_both_hashes_wrong(self):
        """When both hashes are wrong, status should be invalid_content_hash (content priority)"""
        sealed = self._make_sealed_report(id="rpt-both-wrong")
        # Create a copy with fabricated hashes
        fake_seal = TesseraSeal(
            content_hash="0000000000000000000000000000000000000000000000000000000000000000",
            previous_hash=sealed.seal.previous_hash,
            chain_hash="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            sealed_at=sealed.seal.sealed_at,
            sealer_id=sealed.seal.sealer_id,
        )
        tampered = sealed.model_copy(update={"seal": fake_seal})
        result = verify_seal(tampered)

        assert result.status == "invalid_content_hash"
        assert result.valid is False
        assert result.content_hash_match is False
        assert result.chain_hash_match is False

    def test_goodhart_verify_seal_only_chain_hash_wrong(self):
        """Correct content_hash but wrong chain_hash gives invalid_chain_hash status"""
        sealed = self._make_sealed_report(id="rpt-chain-only-wrong")
        # Keep content_hash correct, fabricate chain_hash
        fake_seal = TesseraSeal(
            content_hash=sealed.seal.content_hash,
            previous_hash=sealed.seal.previous_hash,
            chain_hash="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sealed_at=sealed.seal.sealed_at,
            sealer_id=sealed.seal.sealer_id,
        )
        tampered = sealed.model_copy(update={"seal": fake_seal})
        result = verify_seal(tampered)

        assert result.status == "invalid_chain_hash"
        assert result.valid is False
        assert result.content_hash_match is True
        assert result.chain_hash_match is False

    def test_goodhart_verify_seal_never_raises_on_weird_seal(self):
        """verify_seal must not raise even with unusual but technically valid seal data"""
        report = make_report(id="rpt-weird-seal")
        weird_seal = TesseraSeal(
            content_hash="b" * 64,
            previous_hash="c" * 64,
            chain_hash="d" * 64,
            sealed_at="2024-01-01T00:00:00Z",
            sealer_id="weird-sealer",
        )
        report_with_weird_seal = report.model_copy(update={"seal": weird_seal})

        # Should not raise
        result = verify_seal(report_with_weird_seal)
        assert result.valid is False
        assert isinstance(result.status, str)


# ---- Format Report Tests ----

class TestGoodhartFormatReport:
    def test_goodhart_format_report_json_truncated_always_false(self):
        """JSON format must never set truncated=True regardless of size"""
        # Create report with many findings to produce large output
        findings = [
            make_finding(id=f"f-{i}", description="x" * 500, severity="medium")
            for i in range(200)
        ]
        report = make_report(id="rpt-large-json", findings=findings)
        result = format_report(report, "json", FIXED_TIMESTAMP)
        assert result.truncated is False

    def test_goodhart_format_report_md_truncated_always_false(self):
        """Markdown format must never set truncated=True regardless of size"""
        findings = [
            make_finding(id=f"f-{i}", description="x" * 500, severity="high")
            for i in range(200)
        ]
        report = make_report(id="rpt-large-md", findings=findings)
        result = format_report(report, "md", FIXED_TIMESTAMP)
        assert result.truncated is False

    def test_goodhart_format_report_github_truncation_includes_notice(self):
        """Truncated GitHub output must end with the exact truncation notice"""
        findings = [
            make_finding(
                id=f"f-trunc-{i}",
                description="Very long description " * 100,
                severity="critical",
                stage="security",
            )
            for i in range(200)
        ]
        report = make_report(id="rpt-github-trunc", findings=findings)
        result = format_report(report, "github", FIXED_TIMESTAMP)

        if result.truncated:
            truncation_notice = "\n\n---\n⚠️ *Report truncated. Full report available in JSON format.*"
            assert result.content.endswith(truncation_notice), \
                "Truncated output must end with the exact truncation notice"

    def test_goodhart_format_report_deterministic_json(self):
        """Same inputs + same timestamp must produce identical JSON output"""
        report = make_report(id="rpt-det-json", summary="Determinism test JSON")
        r1 = format_report(report, "json", FIXED_TIMESTAMP)
        r2 = format_report(report, "json", FIXED_TIMESTAMP)
        assert r1.content == r2.content

    def test_goodhart_format_report_deterministic_md(self):
        """Same inputs + same timestamp must produce identical Markdown output"""
        report = make_report(
            id="rpt-det-md",
            findings=[make_finding()],
            summary="Determinism test MD"
        )
        r1 = format_report(report, "md", FIXED_TIMESTAMP)
        r2 = format_report(report, "md", FIXED_TIMESTAMP)
        assert r1.content == r2.content

    def test_goodhart_format_report_deterministic_github(self):
        """Same inputs + same timestamp must produce identical GitHub output"""
        report = make_report(
            id="rpt-det-gh",
            findings=[make_finding()],
            summary="Determinism test GH"
        )
        r1 = format_report(report, "github", FIXED_TIMESTAMP)
        r2 = format_report(report, "github", FIXED_TIMESTAMP)
        assert r1.content == r2.content

    def test_goodhart_format_report_rendered_at_matches_timestamp(self):
        """rendered_at must match the injected timestamp exactly"""
        report = make_report(id="rpt-rendered-at")
        unusual_ts = "2000-01-01T00:00:00.123456Z"
        result = format_report(report, "json", unusual_ts)
        assert result.rendered_at == unusual_ts

    def test_goodhart_format_report_report_id_matches_unusual_id(self):
        """FormattedReport.report_id must match report.id for unusual ids"""
        unusual_id = "rpt-adversarial-test-42-with-special"
        report = make_report(id=unusual_id)
        result = format_report(report, "json", FIXED_TIMESTAMP)
        assert result.report_id == unusual_id

    def test_goodhart_format_report_output_format_matches_all_variants(self):
        """output_format field must match requested format for every variant"""
        report = make_report(id="rpt-fmt-match", findings=[make_finding()])
        for fmt in ["json", "md", "github"]:
            result = format_report(report, fmt, FIXED_TIMESTAMP)
            assert result.output_format == fmt, f"output_format should be '{fmt}'"

    def test_goodhart_format_report_json_parseable_with_findings(self):
        """JSON output must be parseable and contain actual report data"""
        findings = [
            make_finding(id=f"f-parse-{i}", severity="high")
            for i in range(3)
        ]
        report = make_report(id="rpt-json-parse", findings=findings)
        result = format_report(report, "json", FIXED_TIMESTAMP)

        parsed = json.loads(result.content)
        assert parsed["id"] == "rpt-json-parse"
        assert len(parsed["findings"]) == 3

    def test_goodhart_format_report_character_count_various_formats(self):
        """character_count must equal len(content) for all format types with non-trivial content"""
        findings = [make_finding(id=f"f-cc-{i}") for i in range(5)]
        report = make_report(id="rpt-cc-test", findings=findings)

        for fmt in ["json", "md", "github"]:
            result = format_report(report, fmt, FIXED_TIMESTAMP)
            assert result.character_count == len(result.content), \
                f"character_count must equal len(content) for {fmt} format"

    def test_goodhart_format_report_metadata_pact_component_all_formats(self):
        """metadata must contain pact_component='reporter' for every format"""
        report = make_report(id="rpt-meta-all")
        for fmt in ["json", "md", "github"]:
            result = format_report(report, fmt, FIXED_TIMESTAMP)
            assert result.metadata.get("pact_component") == "reporter", \
                f"pact_component must be 'reporter' for {fmt} format"

    def test_goodhart_immutable_formatted_report(self):
        """FormattedReport must be frozen (immutable)"""
        report = make_report(id="rpt-frozen-fr")
        result = format_report(report, "json", FIXED_TIMESTAMP)
        with pytest.raises(Exception):  # ValidationError or AttributeError for frozen
            result.content = "tampered"
        with pytest.raises(Exception):
            result.truncated = True


# ---- Render JSON Tests ----

class TestGoodhartRenderJson:
    def test_goodhart_render_json_no_seal_includes_key(self):
        """render_json output must include the seal key even when seal is None"""
        report = make_report(id="rpt-json-noseal")
        output = render_json(report)
        parsed = json.loads(output)
        assert "seal" in parsed, "JSON output must include 'seal' key even when None"

    def test_goodhart_render_json_sorted_keys_deeply(self):
        """Keys must be sorted at all nesting levels in render_json output"""
        findings = [make_finding(id="f-deep-sort")]
        assessments = [make_assessment(id="a-deep-sort", findings=[make_finding(id="f-in-assess")])]
        report = make_report(id="rpt-deep-sort", findings=findings, assessments=assessments)
        output = render_json(report)
        parsed = json.loads(output)

        def check_sorted(obj, path="root"):
            if isinstance(obj, dict):
                keys = list(obj.keys())
                assert keys == sorted(keys), f"Keys not sorted at {path}: {keys}"
                for k, v in obj.items():
                    check_sorted(v, f"{path}.{k}")
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    check_sorted(item, f"{path}[{i}]")

        check_sorted(parsed)

    def test_goodhart_render_json_two_space_indent(self):
        """render_json must use 2-space indentation"""
        report = make_report(id="rpt-indent", findings=[make_finding()])
        output = render_json(report)
        lines = output.split("\n")
        # Find lines with indentation and verify they use 2-space multiples
        indented_lines = [l for l in lines if l.startswith(" ")]
        assert len(indented_lines) > 0, "Should have indented lines"
        for line in indented_lines:
            stripped = line.lstrip(" ")
            indent_count = len(line) - len(stripped)
            assert indent_count % 2 == 0, f"Indent must be multiple of 2, got {indent_count}"


# ---- Render Markdown Tests ----

class TestGoodhartRenderMarkdown:
    def test_goodhart_render_markdown_all_five_severity_badges(self):
        """All five severity emoji badges must appear for their respective findings"""
        findings = [
            make_finding(id="f-crit", severity="critical", file_path="a.py", stage="security"),
            make_finding(id="f-high", severity="high", file_path="b.py", stage="security"),
            make_finding(id="f-med", severity="medium", file_path="c.py", stage="security"),
            make_finding(id="f-low", severity="low", file_path="d.py", stage="security"),
            make_finding(id="f-info", severity="info", file_path="e.py", stage="security"),
        ]
        report = make_report(id="rpt-all-badges", findings=findings)
        output = render_markdown(report, FIXED_TIMESTAMP)

        assert "🔴" in output, "Must contain 🔴 for critical"
        assert "🟠" in output, "Must contain 🟠 for high"
        assert "🟡" in output, "Must contain 🟡 for medium"
        assert "🔵" in output, "Must contain 🔵 for low"
        assert "⚪" in output, "Must contain ⚪ for info"

    def test_goodhart_render_markdown_report_id_in_heading(self):
        """Report id must appear in a heading in the markdown output"""
        distinctive_id = "unique-report-id-xyz-789"
        report = make_report(id=distinctive_id)
        output = render_markdown(report, FIXED_TIMESTAMP)
        assert distinctive_id in output, "Report id must appear in output"
        # Check it's in a heading line
        heading_lines = [l for l in output.split("\n") if l.startswith("#")]
        id_in_heading = any(distinctive_id in l for l in heading_lines)
        assert id_in_heading, "Report id must be in a markdown heading"

    def test_goodhart_render_markdown_summary_table(self):
        """Markdown must include severity count summary information"""
        findings = [
            make_finding(id="f-c1", severity="critical", file_path="a.py", stage="security"),
            make_finding(id="f-c2", severity="critical", file_path="b.py", stage="security"),
            make_finding(id="f-h1", severity="high", file_path="c.py", stage="security"),
            make_finding(id="f-m1", severity="medium", file_path="d.py", stage="correctness"),
            make_finding(id="f-m2", severity="medium", file_path="e.py", stage="correctness"),
            make_finding(id="f-m3", severity="medium", file_path="f.py", stage="correctness"),
        ]
        report = make_report(id="rpt-summary-table", findings=findings)
        output = render_markdown(report, FIXED_TIMESTAMP)

        # Should contain severity names and counts in some tabular form
        assert "critical" in output.lower() or "Critical" in output
        assert "high" in output.lower() or "High" in output

    def test_goodhart_render_markdown_seal_section_present_when_sealed(self):
        """Sealed report markdown must include seal information"""
        report = make_report(id="rpt-seal-md")
        chain_store = make_chain_store()
        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )
        output = render_markdown(sealed, FIXED_TIMESTAMP)
        # Should mention seal-related content
        assert sealed.seal.content_hash[:16] in output or "seal" in output.lower(), \
            "Sealed report markdown must contain seal information"

    def test_goodhart_render_markdown_no_seal_section_when_unsealed(self):
        """Unsealed report markdown should not contain seal hash information"""
        report = make_report(id="rpt-noseal-md")
        output = render_markdown(report, FIXED_TIMESTAMP)
        # Should not contain arbitrary hex hash strings (64 chars) that would indicate seal data
        # Basic check: "content_hash" should not appear
        assert "content_hash" not in output, "Unsealed markdown should not mention content_hash"

    def test_goodhart_render_markdown_findings_grouped_by_stage(self):
        """Findings from different stages must appear under different stage headings"""
        findings = [
            make_finding(id="f-sec", stage="security", severity="high", file_path="a.py"),
            make_finding(id="f-cor", stage="correctness", severity="medium", file_path="b.py"),
            make_finding(id="f-sty", stage="style", severity="low", file_path="c.py"),
        ]
        report = make_report(id="rpt-stage-group", findings=findings)
        output = render_markdown(report, FIXED_TIMESTAMP)

        # All three stages should appear
        output_lower = output.lower()
        assert "security" in output_lower, "Security stage heading must appear"
        assert "correctness" in output_lower, "Correctness stage heading must appear"
        assert "style" in output_lower, "Style stage heading must appear"

    def test_goodhart_render_markdown_finding_ordering(self):
        """Within a stage, findings must be sorted by severity desc then file_path asc"""
        findings = [
            make_finding(id="f1", severity="medium", file_path="z_file.py", stage="security"),
            make_finding(id="f2", severity="critical", file_path="z_file.py", stage="security"),
            make_finding(id="f3", severity="critical", file_path="a_file.py", stage="security"),
        ]
        report = make_report(id="rpt-ordering", findings=findings)
        output = render_markdown(report, FIXED_TIMESTAMP)

        # f3 (critical, a_file) should come before f2 (critical, z_file) which should come before f1 (medium, z_file)
        pos_f3 = output.find("a_file.py")
        pos_f2_z = output.find("z_file.py")
        # Since critical should come before medium, and a_file before z_file at same severity
        assert pos_f3 < pos_f2_z, "critical a_file.py must appear before z_file.py findings"


# ---- Render GitHub Tests ----

class TestGoodhartRenderGithub:
    def test_goodhart_render_github_details_tags_structure(self):
        """GitHub output must have proper <details>/<summary> structure per stage"""
        findings = [
            make_finding(id="f-sec", stage="security", file_path="a.py"),
            make_finding(id="f-cor", stage="correctness", file_path="b.py"),
        ]
        report = make_report(id="rpt-details-struct", findings=findings)
        output = render_github(report, FIXED_TIMESTAMP)

        details_count = output.count("<details>") + output.count("<details ")
        close_details_count = output.count("</details>")
        assert details_count >= 2, "Should have at least 2 <details> sections for 2 stages"
        assert details_count == close_details_count, "Every <details> must have matching </details>"

        summary_count = output.count("<summary>") + output.count("<summary ")
        close_summary_count = output.count("</summary>")
        assert summary_count >= 2, "Should have at least 2 <summary> tags"
        assert summary_count == close_summary_count, "Every <summary> must have matching </summary>"

    def test_goodhart_render_github_truncation_notice_exact(self):
        """Truncation notice must match the exact specified constant"""
        findings = [
            make_finding(
                id=f"f-notice-{i}",
                description="Long description content " * 200,
                severity="critical",
                stage="security",
            )
            for i in range(200)
        ]
        report = make_report(id="rpt-notice-exact", findings=findings)
        output = render_github(report, FIXED_TIMESTAMP)

        truncation_notice = "\n\n---\n⚠️ *Report truncated. Full report available in JSON format.*"
        if len(output) > 65000:
            assert output.endswith(truncation_notice), \
                "Must end with exact truncation notice"

    def test_goodhart_render_github_truncated_body_is_65000(self):
        """When truncated, the body before notice must be exactly 65000 chars"""
        findings = [
            make_finding(
                id=f"f-body-{i}",
                description="Padding content for size " * 200,
                severity="high",
                stage="security",
            )
            for i in range(300)
        ]
        report = make_report(id="rpt-body-size", findings=findings)
        output = render_github(report, FIXED_TIMESTAMP)

        truncation_notice = "\n\n---\n⚠️ *Report truncated. Full report available in JSON format.*"
        if output.endswith(truncation_notice):
            body = output[: -len(truncation_notice)]
            assert len(body) == 65000, \
                f"Body before truncation notice must be 65000 chars, got {len(body)}"

    def test_goodhart_render_github_multiple_stages_separate_sections(self):
        """Each stage with findings must have its own <details> section"""
        findings = [
            make_finding(id="f-sec", stage="security", file_path="a.py"),
            make_finding(id="f-cor", stage="correctness", file_path="b.py"),
            make_finding(id="f-arc", stage="architecture", file_path="c.py"),
        ]
        report = make_report(id="rpt-multi-stage", findings=findings)
        output = render_github(report, FIXED_TIMESTAMP)

        # Count details sections - should be at least 3
        details_open = output.count("<details>") + output.count("<details ")
        assert details_open >= 3, f"Should have 3 <details> sections for 3 stages, got {details_open}"

    def test_goodhart_render_github_omits_empty_stages(self):
        """Stages with no findings must not have <details> sections"""
        # Only security findings
        findings = [make_finding(id="f-only-sec", stage="security", file_path="a.py")]
        report = make_report(id="rpt-one-stage", findings=findings)
        output = render_github(report, FIXED_TIMESTAMP)

        output_lower = output.lower()
        # Should not have sections for correctness, style, architecture
        # Check that those stage names don't appear in summary tags
        # (they might appear in other contexts, so be conservative)
        details_count = output.count("<details>") + output.count("<details ")
        assert details_count >= 1, "Should have at least 1 details section"
        # Shouldn't have 4 sections since only 1 stage has findings
        assert details_count < 4, "Should not have details for stages without findings"


# ---- Type Validation Tests ----

class TestGoodhartTypes:
    def test_goodhart_type_iso8601_with_fractional_seconds_various(self):
        """Iso8601Timestamp must accept various fractional second precisions"""
        # Single digit fraction
        ts1 = Iso8601Timestamp("2024-01-01T00:00:00.1Z")
        assert ts1 is not None

        # Milliseconds
        ts2 = Iso8601Timestamp("2024-01-01T00:00:00.123Z")
        assert ts2 is not None

        # Microseconds
        ts3 = Iso8601Timestamp("2024-01-01T00:00:00.123456Z")
        assert ts3 is not None

    def test_goodhart_type_sha256hex_empty_string(self):
        """Sha256Hex must accept empty string for unavailable hashes"""
        h = Sha256Hex("")
        assert h is not None

    def test_goodhart_type_report_id_boundary_256_chars(self):
        """ReportId must accept exactly 256 characters"""
        rid = ReportId("a" * 256)
        assert rid is not None

    def test_goodhart_type_report_id_boundary_1_char(self):
        """ReportId must accept exactly 1 character"""
        rid = ReportId("x")
        assert rid is not None

    def test_goodhart_type_sealer_id_boundary_128_chars(self):
        """SealerId must accept exactly 128 characters"""
        sid = SealerId("a" * 128)
        assert sid is not None

    def test_goodhart_type_sealer_id_too_long_129(self):
        """SealerId must reject 129 characters"""
        with pytest.raises(Exception):
            SealerId("a" * 129)

    def test_goodhart_type_report_id_boundary_257_rejected(self):
        """ReportId must reject exactly 257 characters"""
        with pytest.raises(Exception):
            ReportId("a" * 257)


# ---- Immutability Tests ----

class TestGoodhartImmutability:
    def test_goodhart_immutable_seal_verification_result(self):
        """SealVerificationResult must be frozen"""
        report = make_report(id="rpt-frozen-svr")
        result = verify_seal(report)
        with pytest.raises(Exception):
            result.status = "valid"
        with pytest.raises(Exception):
            result.valid = True


# ---- Integration-style Adversarial Tests ----

class TestGoodhartIntegration:
    def test_goodhart_seal_then_verify_different_report_content(self):
        """Seal+verify round trip must work for reports with varied content"""
        findings = [
            make_finding(id="f-int-1", severity="critical", stage="security", file_path="main.py"),
            make_finding(id="f-int-2", severity="info", stage="style", file_path="style.css"),
        ]
        report = make_report(
            id="rpt-integration-roundtrip",
            findings=findings,
            conflict_notes=["Some conflict"],
            metadata={"env": "test", "run": "42"},
            decision="warn",
            confidence="medium",
        )
        chain_store = make_chain_store()
        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "int-sealer", FIXED_TIMESTAMP, None)
        )
        result = verify_seal(sealed)
        assert result.status == "valid"
        assert result.valid is True
        assert result.content_hash_match is True
        assert result.chain_hash_match is True

    def test_goodhart_canonical_and_render_json_differ(self):
        """canonicalize output (compact) must differ from render_json output (indented)"""
        report = make_report(id="rpt-format-diff", findings=[make_finding()])
        canonical = canonicalize(report).decode("utf-8")
        rendered = render_json(report)

        # They should both be valid JSON but different strings
        assert canonical != rendered, "Compact canonical must differ from pretty-printed JSON"
        # Canonical has no newlines, rendered does
        assert "\n" not in canonical
        assert "\n" in rendered

    def test_goodhart_format_report_sealed_with_different_content(self):
        """is_sealed must correctly reflect seal presence for a report sealed with specific content"""
        report = make_report(id="rpt-sealed-check", summary="Check seal reflection")
        chain_store = make_chain_store()
        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )

        for fmt in ["json", "md", "github"]:
            result = format_report(sealed, fmt, FIXED_TIMESTAMP)
            assert result.is_sealed is True, f"is_sealed must be True for sealed report in {fmt}"

            result_unsealed = format_report(report, fmt, FIXED_TIMESTAMP)
            assert result_unsealed.is_sealed is False, f"is_sealed must be False for unsealed report in {fmt}"

    def test_goodhart_seal_with_many_findings_verifies(self):
        """Seal and verify must work correctly with many findings (not just small test reports)"""
        findings = [
            make_finding(
                id=f"f-many-{i}",
                severity=["critical", "high", "medium", "low", "info"][i % 5],
                file_path=f"src/file_{i}.py",
                stage=["security", "correctness", "style", "architecture"][i % 4],
                description=f"Finding number {i} with some description text"
            )
            for i in range(50)
        ]
        report = make_report(id="rpt-many-findings", findings=findings)
        chain_store = make_chain_store()
        sealed = asyncio.get_event_loop().run_until_complete(
            seal_report(report, chain_store, "sealer", FIXED_TIMESTAMP, None)
        )
        result = verify_seal(sealed)
        assert result.valid is True
        assert result.status == "valid"
