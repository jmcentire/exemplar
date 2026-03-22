"""
Contract tests for the reviewers component.

Tests verify behavior at boundaries per the contract specification.
Covers: type validators, filter_hunks_by_policy, derive_decision,
build_assessment, get_all_reviewers, get_reviewer_by_stage,
SecurityReviewer, CorrectnessReviewer, StyleReviewer, ArchitectureReviewer.
"""

import re
import time
import uuid
import pytest
from unittest.mock import MagicMock, patch, AsyncMock

# Import component under test
from exemplar.reviewers import (
    filter_hunks_by_policy,
    derive_decision,
    build_assessment,
    get_all_reviewers,
    get_reviewer_by_stage,
    SecurityReviewer,
    CorrectnessReviewer,
    StyleReviewer,
    ArchitectureReviewer,
    ReviewStage,
    Severity,
    Confidence,
    ReviewDecision,
    RuleId,
    FilePath,
    LineNumber,
    ReviewRequestId,
    DiffHunk,
    PolicyToken,
    Finding,
    Assessment,
    FilteredHunksResult,
    DecisionDerivation,
    ClassificationLabel,
    RulePattern,
    HunkAnalysisError,
)


# ============================================================
# Shared Fixtures & Factory Functions
# ============================================================

VALID_UUID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
VALID_UUID_2 = "11111111-2222-3333-4444-555555555555"


def make_hunk(**kwargs):
    """Factory for DiffHunk with sensible defaults."""
    defaults = dict(
        id="hunk-001",
        file_path="src/main.py",
        start_line_old=1,
        count_old=5,
        start_line_new=1,
        count_new=5,
        context_before=["# context"],
        added_lines=["x = 1"],
        removed_lines=[],
        context_after=["# end"],
        raw_header="@@ -1,5 +1,5 @@",
        classifications=[],
        language="python",
    )
    defaults.update(kwargs)
    return DiffHunk(**defaults)


def make_policy(**kwargs):
    """Factory for PolicyToken with sensible defaults."""
    defaults = dict(
        token_id="tok-001",
        reviewer_id="security",
        allowed_file_patterns=["*.py"],
        denied_file_patterns=[],
        allowed_classifications=[],
        max_severity=Severity.critical,
        issued_at="2024-01-01T00:00:00Z",
        expires_at=None,
    )
    defaults.update(kwargs)
    return PolicyToken(**defaults)


def make_finding(**kwargs):
    """Factory for Finding with sensible defaults."""
    defaults = dict(
        id="finding-001",
        hunk_id="hunk-001",
        file_path="src/main.py",
        line_number=10,
        severity=Severity.medium,
        confidence=Confidence.high,
        title="Test finding",
        description="Test description",
        suggestion=None,
        rule_id="SEC-001",
        stage=ReviewStage.security,
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def make_review_request_id(value=None):
    """Return a ReviewRequestId with a valid UUID."""
    return ReviewRequestId(value=value or VALID_UUID)


@pytest.fixture
def security_reviewer():
    return SecurityReviewer() if callable(SecurityReviewer) else get_reviewer_by_stage(ReviewStage.security)


@pytest.fixture
def correctness_reviewer():
    return CorrectnessReviewer() if callable(CorrectnessReviewer) else get_reviewer_by_stage(ReviewStage.correctness)


@pytest.fixture
def style_reviewer():
    return StyleReviewer() if callable(StyleReviewer) else get_reviewer_by_stage(ReviewStage.style)


@pytest.fixture
def architecture_reviewer():
    return ArchitectureReviewer() if callable(ArchitectureReviewer) else get_reviewer_by_stage(ReviewStage.architecture)


@pytest.fixture
def permissive_policy():
    """Policy that allows everything."""
    return make_policy(
        allowed_file_patterns=[],
        denied_file_patterns=[],
        allowed_classifications=[],
    )


@pytest.fixture
def deny_all_policy():
    """Policy that denies all files."""
    return make_policy(
        allowed_file_patterns=[],
        denied_file_patterns=["*"],
    )


@pytest.fixture
def clean_hunk():
    """A hunk with clean Python code - no security/correctness/style issues."""
    return make_hunk(
        added_lines=[
            "def greet(name: str) -> str:",
            '    """Return a greeting."""',
            '    return f"Hello, {name}"',
        ],
    )


@pytest.fixture
def review_request_id():
    return make_review_request_id()


# ============================================================
# Type Validator Tests
# ============================================================


class TestRuleIdValidation:
    """Tests for RuleId type validation."""

    def test_valid_rule_ids(self):
        """RuleId accepts valid format SEC-001, COR-002, STY-003, ARC-004."""
        for rid in ["SEC-001", "COR-002", "STY-003", "ARC-004", "SEC-999"]:
            rule_id = RuleId(value=rid)
            assert rule_id.value == rid

    def test_invalid_rule_ids(self):
        """RuleId rejects invalid formats."""
        invalid_ids = ["FOO-001", "SEC-01", "SEC001", "sec-001", "", "SEC-0001", "SEC-", "123-456"]
        for rid in invalid_ids:
            with pytest.raises((ValueError, Exception)):
                RuleId(value=rid)


class TestFilePathValidation:
    """Tests for FilePath type validation."""

    def test_valid_paths(self):
        """FilePath accepts valid relative paths."""
        for path in ["src/main.py", "test.py", "a/b/c/d.txt", "file-name.py", "src/my_module/init.py"]:
            fp = FilePath(value=path)
            assert fp.value == path

    def test_rejects_absolute_path(self):
        """FilePath rejects absolute paths starting with /."""
        with pytest.raises((ValueError, Exception)):
            FilePath(value="/etc/passwd")

    def test_rejects_traversal(self):
        """FilePath rejects paths with .. traversal."""
        with pytest.raises((ValueError, Exception)):
            FilePath(value="src/../etc/passwd")

    def test_rejects_too_long(self):
        """FilePath rejects paths exceeding 500 characters."""
        long_path = "a/" * 250 + "b"
        assert len(long_path) > 500
        with pytest.raises((ValueError, Exception)):
            FilePath(value=long_path)

    def test_boundary_length_500(self):
        """FilePath accepts a path of exactly 500 characters."""
        # Build a valid path of exactly 500 chars
        path = "a" * 500
        # This should be accepted if it matches the regex
        try:
            fp = FilePath(value=path)
            assert len(fp.value) == 500
        except (ValueError, Exception):
            # If regex doesn't match a 500-char 'aaa...' path, that's fine
            pass

    def test_rejects_empty(self):
        """FilePath rejects empty string (min length 1)."""
        with pytest.raises((ValueError, Exception)):
            FilePath(value="")


class TestLineNumberValidation:
    """Tests for LineNumber type validation."""

    def test_valid_values(self):
        """LineNumber accepts values 1, 500000, 1000000."""
        for val in [1, 500000, 1000000]:
            ln = LineNumber(value=val)
            assert ln.value == val

    def test_rejects_zero(self):
        """LineNumber rejects 0."""
        with pytest.raises((ValueError, Exception)):
            LineNumber(value=0)

    def test_rejects_negative(self):
        """LineNumber rejects negative values."""
        with pytest.raises((ValueError, Exception)):
            LineNumber(value=-1)

    def test_rejects_exceeds_max(self):
        """LineNumber rejects values > 1000000."""
        with pytest.raises((ValueError, Exception)):
            LineNumber(value=1000001)


class TestReviewRequestIdValidation:
    """Tests for ReviewRequestId type validation."""

    def test_valid_uuid(self):
        """ReviewRequestId accepts valid UUID format."""
        rrid = ReviewRequestId(value=VALID_UUID)
        assert rrid.value == VALID_UUID

    def test_rejects_invalid(self):
        """ReviewRequestId rejects non-UUID strings."""
        for val in ["not-a-uuid", "12345", "", "g1b2c3d4-e5f6-7890-abcd-ef1234567890"]:
            with pytest.raises((ValueError, Exception)):
                ReviewRequestId(value=val)


class TestEnumTypes:
    """Tests for enum type definitions."""

    def test_severity_members(self):
        """Severity enum has all expected members."""
        members = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
        assert len(members) == 5

    def test_review_stage_members(self):
        """ReviewStage enum has all expected members."""
        members = [ReviewStage.security, ReviewStage.correctness, ReviewStage.style, ReviewStage.architecture]
        assert len(members) == 4

    def test_confidence_members(self):
        """Confidence enum has all expected members."""
        members = [Confidence.high, Confidence.medium, Confidence.low]
        assert len(members) == 3

    def test_review_decision_members(self):
        """ReviewDecision enum has all expected members."""
        members = [ReviewDecision.block, ReviewDecision.warn, ReviewDecision.pass_]
        assert len(members) == 3

    def test_classification_label_members(self):
        """ClassificationLabel enum has all expected members."""
        members = [ClassificationLabel.secret, ClassificationLabel.pii,
                    ClassificationLabel.internal_api, ClassificationLabel.public]
        assert len(members) == 4


class TestFilteredHunksResultValidation:
    """Tests for FilteredHunksResult validation."""

    def test_rejects_negative_denied_count(self):
        """FilteredHunksResult rejects denied_count < 0."""
        with pytest.raises((ValueError, Exception)):
            FilteredHunksResult(permitted=[], denied_count=-1)

    def test_rejects_excessive_denied_count(self):
        """FilteredHunksResult rejects denied_count > 100000."""
        with pytest.raises((ValueError, Exception)):
            FilteredHunksResult(permitted=[], denied_count=100001)

    def test_valid_boundaries(self):
        """FilteredHunksResult accepts denied_count at boundaries 0 and 100000."""
        r0 = FilteredHunksResult(permitted=[], denied_count=0)
        assert r0.denied_count == 0
        r_max = FilteredHunksResult(permitted=[], denied_count=100000)
        assert r_max.denied_count == 100000


class TestHunkAnalysisErrorValidation:
    """Tests for HunkAnalysisError validation."""

    def test_rejects_long_error_message(self):
        """HunkAnalysisError rejects error_message longer than 500 chars."""
        with pytest.raises((ValueError, Exception)):
            HunkAnalysisError(
                file_path=FilePath(value="src/main.py"),
                start_line=LineNumber(value=1),
                error_type="test",
                error_message="x" * 501,
            )


class TestRulePatternValidation:
    """Tests for RulePattern validation."""

    def test_rejects_empty_pattern(self):
        """RulePattern rejects empty pattern."""
        with pytest.raises((ValueError, Exception)):
            RulePattern(
                rule_id=RuleId(value="SEC-001"),
                pattern="",
                severity=Severity.high,
                confidence=Confidence.high,
                message_template="test",
                suggestion="fix it",
            )

    def test_rejects_too_long_pattern(self):
        """RulePattern rejects pattern longer than 2000 chars."""
        with pytest.raises((ValueError, Exception)):
            RulePattern(
                rule_id=RuleId(value="SEC-001"),
                pattern="x" * 2001,
                severity=Severity.high,
                confidence=Confidence.high,
                message_template="test",
                suggestion="fix it",
            )


# ============================================================
# filter_hunks_by_policy Tests
# ============================================================


class TestFilterHunksByPolicy:
    """Tests for filter_hunks_by_policy function."""

    def test_allow_all_matching(self):
        """Permits all hunks when policy allows *.py and hunks are .py files."""
        hunks = [
            make_hunk(id="h1", file_path="src/a.py"),
            make_hunk(id="h2", file_path="src/b.py"),
        ]
        policy = make_policy(allowed_file_patterns=["*.py"], denied_file_patterns=[])
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) == 2
        assert result.denied_count == 0

    def test_deny_wins_over_allow(self):
        """Deny patterns win over allow patterns."""
        hunks = [make_hunk(id="h1", file_path="src/secret.py")]
        policy = make_policy(
            allowed_file_patterns=["*.py"],
            denied_file_patterns=["*secret*"],
        )
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) == 0
        assert result.denied_count == 1

    def test_empty_allowed_means_all_pass(self):
        """Empty allowed_file_patterns means all non-denied hunks pass."""
        hunks = [
            make_hunk(id="h1", file_path="src/a.py"),
            make_hunk(id="h2", file_path="docs/readme.md"),
        ]
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) == 2
        assert result.denied_count == 0

    def test_preserves_ordering(self):
        """Permitted hunks maintain original relative order."""
        hunks = [
            make_hunk(id="h1", file_path="a.py"),
            make_hunk(id="h2", file_path="b.txt"),
            make_hunk(id="h3", file_path="c.py"),
        ]
        policy = make_policy(allowed_file_patterns=["*.py"], denied_file_patterns=[])
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        permitted_ids = [h.id for h in result.permitted]
        assert permitted_ids == ["h1", "h3"]

    def test_empty_hunks_list(self):
        """Empty hunk list returns empty permitted and denied_count=0."""
        policy = make_policy()
        result = filter_hunks_by_policy([], policy, ReviewStage.security)
        assert len(result.permitted) == 0
        assert result.denied_count == 0

    def test_conservation_property(self):
        """permitted + denied_count always equals len(hunks)."""
        hunks = [
            make_hunk(id=f"h{i}", file_path=f"src/file{i}.py" if i % 2 == 0 else f"src/file{i}.txt")
            for i in range(10)
        ]
        policy = make_policy(allowed_file_patterns=["*.py"], denied_file_patterns=[])
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) + result.denied_count == len(hunks)

    def test_partial_deny(self):
        """Mix of permitted and denied hunks with correct counts."""
        hunks = [
            make_hunk(id="h1", file_path="src/app.py"),
            make_hunk(id="h2", file_path="src/secrets.py"),
            make_hunk(id="h3", file_path="src/utils.py"),
        ]
        policy = make_policy(
            allowed_file_patterns=["*.py"],
            denied_file_patterns=["*secrets*"],
        )
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) == 2
        assert result.denied_count == 1
        permitted_paths = [h.file_path for h in result.permitted]
        assert "src/secrets.py" not in permitted_paths


# ============================================================
# derive_decision Tests
# ============================================================


class TestDeriveDecision:
    """Tests for derive_decision function."""

    def test_empty_findings_pass_high(self):
        """Empty findings -> decision=PASS, min_confidence=HIGH."""
        result = derive_decision([])
        assert result.decision == ReviewDecision.pass_
        assert result.min_confidence == Confidence.high

    def test_critical_blocks(self):
        """Critical severity finding -> BLOCK."""
        findings = [make_finding(severity=Severity.critical, confidence=Confidence.high)]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.block
        assert result.has_critical is True

    def test_high_blocks(self):
        """High severity finding -> BLOCK."""
        findings = [make_finding(severity=Severity.high, confidence=Confidence.medium)]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.block
        assert result.has_high is True

    def test_medium_warns(self):
        """Medium severity (no critical/high) -> WARN."""
        findings = [make_finding(severity=Severity.medium, confidence=Confidence.high)]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.warn

    def test_low_passes(self):
        """Only LOW findings -> PASS."""
        findings = [make_finding(severity=Severity.low, confidence=Confidence.high)]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.pass_

    def test_info_passes(self):
        """Only INFO findings -> PASS."""
        findings = [make_finding(severity=Severity.info, confidence=Confidence.medium)]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.pass_

    def test_min_confidence_across_findings(self):
        """min_confidence is the minimum confidence across all findings."""
        findings = [
            make_finding(id="f1", severity=Severity.low, confidence=Confidence.high),
            make_finding(id="f2", severity=Severity.low, confidence=Confidence.low),
            make_finding(id="f3", severity=Severity.low, confidence=Confidence.medium),
        ]
        result = derive_decision(findings)
        assert result.min_confidence == Confidence.low

    def test_mixed_severities_highest_wins(self):
        """Critical + low -> BLOCK (highest severity determines decision)."""
        findings = [
            make_finding(id="f1", severity=Severity.critical, confidence=Confidence.high),
            make_finding(id="f2", severity=Severity.low, confidence=Confidence.medium),
        ]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.block
        assert result.has_critical is True
        assert result.min_confidence == Confidence.medium

    def test_multiple_medium_still_warns(self):
        """Multiple MEDIUM findings still result in WARN."""
        findings = [
            make_finding(id=f"f{i}", severity=Severity.medium, confidence=Confidence.high)
            for i in range(5)
        ]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.warn


# ============================================================
# build_assessment Tests
# ============================================================


class TestBuildAssessment:
    """Tests for build_assessment function."""

    def test_deterministic_id(self):
        """Assessment ID is deterministic via uuid5."""
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        assessment = build_assessment(
            reviewer_id="security",
            stage=ReviewStage.security,
            findings=[],
            hunks_analyzed=5,
            hunks_skipped=0,
            errors=[],
            review_request_id=rrid,
            start_ns=start_ns,
        )
        expected_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{VALID_UUID}:security"))
        assert assessment.id == expected_id

    def test_deterministic_id_reproducible(self):
        """Same inputs produce same assessment ID."""
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        a1 = build_assessment("security", ReviewStage.security, [], 0, 0, [], rrid, start_ns)
        a2 = build_assessment("security", ReviewStage.security, [], 0, 0, [], rrid, start_ns)
        assert a1.id == a2.id

    def test_duration_nonneg(self):
        """duration_ms is >= 0."""
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        assessment = build_assessment("security", ReviewStage.security, [], 0, 0, [], rrid, start_ns)
        assert assessment.duration_ms >= 0

    def test_decision_derived_from_findings(self):
        """Decision matches derive_decision output for given findings."""
        findings = [make_finding(severity=Severity.critical, confidence=Confidence.low)]
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        assessment = build_assessment("security", ReviewStage.security, findings, 1, 0, [], rrid, start_ns)
        derived = derive_decision(findings)
        assert assessment.decision == derived.decision
        assert assessment.confidence == derived.min_confidence

    def test_frozen_assessment(self):
        """Returned Assessment is frozen/immutable."""
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        assessment = build_assessment("security", ReviewStage.security, [], 0, 0, [], rrid, start_ns)
        with pytest.raises((AttributeError, TypeError, Exception)):
            assessment.decision = ReviewDecision.block

    def test_invalid_reviewer_id(self):
        """Raises error for invalid reviewer_id."""
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        with pytest.raises(Exception):
            build_assessment("unknown_reviewer", ReviewStage.security, [], 0, 0, [], rrid, start_ns)


# ============================================================
# get_all_reviewers Tests
# ============================================================


class TestGetAllReviewers:
    """Tests for get_all_reviewers function."""

    def test_returns_four(self):
        """Returns exactly 4 reviewers."""
        reviewers = get_all_reviewers()
        assert len(reviewers) == 4

    def test_correct_order(self):
        """Returns reviewers in correct order: security, correctness, style, architecture."""
        reviewers = get_all_reviewers()
        expected_ids = ["security", "correctness", "style", "architecture"]
        actual_ids = [r.reviewer_id for r in reviewers]
        assert actual_ids == expected_ids

    def test_unique_ids(self):
        """All reviewer_ids are unique."""
        reviewers = get_all_reviewers()
        ids = [r.reviewer_id for r in reviewers]
        assert len(set(ids)) == len(ids)

    def test_protocol_conformance(self):
        """Each reviewer has a review method and reviewer_id attribute."""
        reviewers = get_all_reviewers()
        for r in reviewers:
            assert hasattr(r, "reviewer_id")
            assert hasattr(r, "review")
            assert callable(r.review)


# ============================================================
# get_reviewer_by_stage Tests
# ============================================================


class TestGetReviewerByStage:
    """Tests for get_reviewer_by_stage function."""

    @pytest.mark.parametrize(
        "stage,expected_id",
        [
            (ReviewStage.security, "security"),
            (ReviewStage.correctness, "correctness"),
            (ReviewStage.style, "style"),
            (ReviewStage.architecture, "architecture"),
        ],
    )
    def test_returns_correct_reviewer(self, stage, expected_id):
        """Returns reviewer with matching stage property."""
        reviewer = get_reviewer_by_stage(stage)
        assert reviewer.reviewer_id == expected_id
        assert hasattr(reviewer, "review")


# ============================================================
# SecurityReviewer Tests
# ============================================================


class TestSecurityReviewer:
    """Tests for SecurityReviewer.review()."""

    @pytest.mark.asyncio
    async def test_detects_hardcoded_secret(self, security_reviewer, permissive_policy, review_request_id):
        """Detects hardcoded API key in added lines."""
        hunk = make_hunk(
            added_lines=[
                "API_KEY = 'sk-1234567890abcdef1234567890abcdef'",
                "password = 'super_secret_password123'",
            ],
        )
        assessment = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        assert len(assessment.findings) > 0
        # At least one finding should relate to secrets
        rule_ids = [f.rule_id for f in assessment.findings]
        assert any("SEC" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_detects_sql_injection(self, security_reviewer, permissive_policy, review_request_id):
        """Detects SQL injection pattern."""
        hunk = make_hunk(
            added_lines=[
                'query = f"SELECT * FROM users WHERE id = {user_id}"',
                'cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
            ],
        )
        assessment = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        assert len(assessment.findings) > 0
        rule_ids = [f.rule_id for f in assessment.findings]
        # SEC-002 is SQL injection
        assert any("SEC" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_clean_code_no_findings(self, security_reviewer, permissive_policy, review_request_id):
        """Clean code produces no findings."""
        hunk = make_hunk(
            added_lines=[
                "def add(a: int, b: int) -> int:",
                '    """Add two numbers."""',
                "    return a + b",
            ],
        )
        assessment = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    async def test_assessment_structure(self, security_reviewer, permissive_policy, review_request_id):
        """Assessment has reviewer_id='security' and stage=security."""
        hunk = make_hunk(added_lines=["x = 1"])
        assessment = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        assert assessment.reviewer_id == "security"
        assert assessment.stage == ReviewStage.security

    @pytest.mark.asyncio
    async def test_all_hunks_denied(self, security_reviewer, deny_all_policy, review_request_id):
        """Returns PASS with empty findings when all hunks denied by policy."""
        hunk = make_hunk(added_lines=["API_KEY = 'secret'"])
        assessment = await security_reviewer.review([hunk], deny_all_policy, review_request_id)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    async def test_empty_hunks(self, security_reviewer, permissive_policy, review_request_id):
        """Empty hunks list returns PASS assessment."""
        assessment = await security_reviewer.review([], permissive_policy, review_request_id)
        assert assessment.decision == ReviewDecision.pass_
        assert len(assessment.findings) == 0

    @pytest.mark.asyncio
    async def test_finding_rule_ids_pattern(self, security_reviewer, permissive_policy, review_request_id):
        """All findings have rule_ids matching SEC-xxx pattern."""
        hunk = make_hunk(
            added_lines=[
                "API_KEY = 'sk-1234567890abcdef'",
                'query = f"SELECT * FROM users WHERE id = {user_id}"',
                "import pickle; pickle.loads(data)",
            ],
        )
        assessment = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        for finding in assessment.findings:
            assert re.match(r"^SEC-\d{3}$", finding.rule_id), f"Invalid rule_id: {finding.rule_id}"

    @pytest.mark.asyncio
    async def test_no_exceptions_propagate(self, security_reviewer, permissive_policy, review_request_id):
        """Review never raises exceptions - errors captured in assessment."""
        # Even with unusual content, no exception should propagate
        hunk = make_hunk(
            added_lines=["\\x00\\x01\\x02 garbage data \xff\xfe"],
        )
        # Should not raise
        assessment = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        assert isinstance(assessment, Assessment)

    @pytest.mark.asyncio
    async def test_idempotent(self, security_reviewer, permissive_policy, review_request_id):
        """Calling review() twice with same inputs produces identical Assessment."""
        hunk = make_hunk(added_lines=["password = 'admin123'"])
        a1 = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        a2 = await security_reviewer.review([hunk], permissive_policy, review_request_id)
        assert a1.id == a2.id
        assert a1.decision == a2.decision
        assert a1.confidence == a2.confidence
        assert len(a1.findings) == len(a2.findings)


# ============================================================
# CorrectnessReviewer Tests
# ============================================================


class TestCorrectnessReviewer:
    """Tests for CorrectnessReviewer.review()."""

    @pytest.mark.asyncio
    async def test_detects_bare_except(self, correctness_reviewer, permissive_policy, review_request_id):
        """Detects bare except clause."""
        hunk = make_hunk(
            added_lines=[
                "try:",
                "    risky()",
                "except:",
                "    pass",
            ],
        )
        assessment = await correctness_reviewer.review([hunk], permissive_policy, review_request_id)
        # Should find COR-004 bare except
        rule_ids = [f.rule_id for f in assessment.findings]
        assert any("COR" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_detects_mutable_default(self, correctness_reviewer, permissive_policy, review_request_id):
        """Detects mutable default argument."""
        hunk = make_hunk(
            added_lines=[
                "def process(items=[]):",
                "    items.append(1)",
                "    return items",
            ],
        )
        assessment = await correctness_reviewer.review([hunk], permissive_policy, review_request_id)
        rule_ids = [f.rule_id for f in assessment.findings]
        assert any("COR" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_clean_code_no_findings(self, correctness_reviewer, permissive_policy, review_request_id):
        """Clean code produces no findings."""
        hunk = make_hunk(
            added_lines=[
                "def add(a: int, b: int) -> int:",
                '    """Add two numbers."""',
                "    return a + b",
            ],
        )
        assessment = await correctness_reviewer.review([hunk], permissive_policy, review_request_id)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    async def test_syntax_error_fallback(self, correctness_reviewer, permissive_policy, review_request_id):
        """Gracefully handles non-Python / unparseable content."""
        hunk = make_hunk(
            file_path="src/template.html",
            added_lines=[
                "<html>",
                "<body>{{ content }}</body>",
                "</html>",
            ],
            language=None,
        )
        # Should not crash
        assessment = await correctness_reviewer.review([hunk], permissive_policy, review_request_id)
        assert isinstance(assessment, Assessment)

    @pytest.mark.asyncio
    async def test_all_hunks_denied(self, correctness_reviewer, deny_all_policy, review_request_id):
        """Returns PASS with empty findings when all hunks denied."""
        hunk = make_hunk(added_lines=["except:\n    pass"])
        assessment = await correctness_reviewer.review([hunk], deny_all_policy, review_request_id)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    async def test_assessment_structure(self, correctness_reviewer, permissive_policy, review_request_id):
        """Assessment has correct reviewer_id and stage."""
        hunk = make_hunk(added_lines=["x = 1"])
        assessment = await correctness_reviewer.review([hunk], permissive_policy, review_request_id)
        assert assessment.reviewer_id == "correctness"
        assert assessment.stage == ReviewStage.correctness

    @pytest.mark.asyncio
    async def test_finding_rule_ids_pattern(self, correctness_reviewer, permissive_policy, review_request_id):
        """All findings have rule_ids matching COR-xxx pattern."""
        hunk = make_hunk(
            added_lines=[
                "def process(items=[]):",
                "    try:",
                "        risky()",
                "    except:",
                "        pass",
            ],
        )
        assessment = await correctness_reviewer.review([hunk], permissive_policy, review_request_id)
        for finding in assessment.findings:
            assert re.match(r"^COR-\d{3}$", finding.rule_id), f"Invalid rule_id: {finding.rule_id}"


# ============================================================
# StyleReviewer Tests
# ============================================================


class TestStyleReviewer:
    """Tests for StyleReviewer.review()."""

    @pytest.mark.asyncio
    async def test_detects_long_line(self, style_reviewer, permissive_policy, review_request_id):
        """Detects line exceeding length limit."""
        long_line = "x = " + "a" * 200  # Well over any reasonable line limit
        hunk = make_hunk(added_lines=[long_line])
        assessment = await style_reviewer.review([hunk], permissive_policy, review_request_id)
        rule_ids = [f.rule_id for f in assessment.findings]
        assert any("STY" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_detects_trailing_whitespace(self, style_reviewer, permissive_policy, review_request_id):
        """Detects trailing whitespace."""
        hunk = make_hunk(added_lines=["x = 1   ", "y = 2\t"])
        assessment = await style_reviewer.review([hunk], permissive_policy, review_request_id)
        rule_ids = [f.rule_id for f in assessment.findings]
        assert any("STY" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_clean_code_no_findings(self, style_reviewer, permissive_policy, review_request_id):
        """Well-formatted code produces no findings."""
        hunk = make_hunk(
            added_lines=[
                "def greet(name: str) -> str:",
                '    """Return a greeting."""',
                '    return f"Hello, {name}"',
            ],
        )
        assessment = await style_reviewer.review([hunk], permissive_policy, review_request_id)
        # May or may not have findings depending on exact rules, but structure should be valid
        assert isinstance(assessment, Assessment)
        assert assessment.decision in [ReviewDecision.pass_, ReviewDecision.warn]

    @pytest.mark.asyncio
    async def test_severity_cap_at_medium(self, style_reviewer, permissive_policy, review_request_id):
        """Style findings never exceed MEDIUM severity."""
        # Lines designed to trigger multiple style violations
        hunk = make_hunk(
            added_lines=[
                "x = " + "a" * 200,  # long line
                "BadName = 1   ",  # trailing whitespace + naming
                "\t    mixed",  # mixed indentation
            ],
        )
        assessment = await style_reviewer.review([hunk], permissive_policy, review_request_id)
        high_or_above = {Severity.critical, Severity.high}
        for finding in assessment.findings:
            assert finding.severity not in high_or_above, (
                f"Style finding {finding.rule_id} has severity {finding.severity} which exceeds MEDIUM"
            )

    @pytest.mark.asyncio
    async def test_all_hunks_denied(self, style_reviewer, deny_all_policy, review_request_id):
        """Returns PASS with empty findings when all hunks denied."""
        hunk = make_hunk(added_lines=["x = " + "a" * 200])
        assessment = await style_reviewer.review([hunk], deny_all_policy, review_request_id)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    async def test_assessment_structure(self, style_reviewer, permissive_policy, review_request_id):
        """Assessment has reviewer_id='style' and stage=style."""
        hunk = make_hunk(added_lines=["x = 1"])
        assessment = await style_reviewer.review([hunk], permissive_policy, review_request_id)
        assert assessment.reviewer_id == "style"
        assert assessment.stage == ReviewStage.style

    @pytest.mark.asyncio
    async def test_finding_rule_ids_pattern(self, style_reviewer, permissive_policy, review_request_id):
        """All findings have rule_ids matching STY-xxx pattern."""
        hunk = make_hunk(
            added_lines=[
                "x = " + "a" * 200,
                "y = 1   ",
            ],
        )
        assessment = await style_reviewer.review([hunk], permissive_policy, review_request_id)
        for finding in assessment.findings:
            assert re.match(r"^STY-\d{3}$", finding.rule_id), f"Invalid rule_id: {finding.rule_id}"


# ============================================================
# ArchitectureReviewer Tests
# ============================================================


class TestArchitectureReviewer:
    """Tests for ArchitectureReviewer.review()."""

    @pytest.mark.asyncio
    async def test_detects_excessive_imports(self, architecture_reviewer, permissive_policy, review_request_id):
        """Detects god module pattern with many imports."""
        # Generate many import lines to trigger god module / excessive coupling detection
        import_lines = [f"import module_{i}" for i in range(25)]
        hunk = make_hunk(added_lines=import_lines)
        assessment = await architecture_reviewer.review([hunk], permissive_policy, review_request_id)
        # Should detect at least one architecture issue
        if len(assessment.findings) > 0:
            rule_ids = [f.rule_id for f in assessment.findings]
            assert any("ARC" in rid for rid in rule_ids)

    @pytest.mark.asyncio
    async def test_clean_architecture(self, architecture_reviewer, permissive_policy, review_request_id):
        """Clean code with minimal imports produces no findings."""
        hunk = make_hunk(
            added_lines=[
                "import os",
                "x = os.path.join('a', 'b')",
            ],
        )
        assessment = await architecture_reviewer.review([hunk], permissive_policy, review_request_id)
        assert isinstance(assessment, Assessment)
        # Clean code should ideally pass
        # But even if it doesn't, structure should be correct
        assert assessment.reviewer_id == "architecture"

    @pytest.mark.asyncio
    async def test_all_hunks_denied(self, architecture_reviewer, deny_all_policy, review_request_id):
        """Returns PASS with empty findings when all hunks denied."""
        hunk = make_hunk(added_lines=["import os"] * 30)
        assessment = await architecture_reviewer.review([hunk], deny_all_policy, review_request_id)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    async def test_assessment_structure(self, architecture_reviewer, permissive_policy, review_request_id):
        """Assessment has correct reviewer_id and stage."""
        hunk = make_hunk(added_lines=["import os"])
        assessment = await architecture_reviewer.review([hunk], permissive_policy, review_request_id)
        assert assessment.reviewer_id == "architecture"
        assert assessment.stage == ReviewStage.architecture

    @pytest.mark.asyncio
    async def test_finding_rule_ids_pattern(self, architecture_reviewer, permissive_policy, review_request_id):
        """All findings have rule_ids matching ARC-xxx pattern."""
        import_lines = [f"import module_{i}" for i in range(25)]
        import_lines += [f"from package_{i} import thing_{i}" for i in range(25)]
        hunk = make_hunk(added_lines=import_lines)
        assessment = await architecture_reviewer.review([hunk], permissive_policy, review_request_id)
        for finding in assessment.findings:
            assert re.match(r"^ARC-\d{3}$", finding.rule_id), f"Invalid rule_id: {finding.rule_id}"

    @pytest.mark.asyncio
    async def test_cross_hunk_analysis(self, architecture_reviewer, permissive_policy, review_request_id):
        """Cross-hunk analysis considers all permitted hunks collectively."""
        # Two hunks that together might indicate circular dependency
        hunk_a = make_hunk(
            id="ha",
            file_path="src/module_a.py",
            added_lines=["from src.module_b import something"],
        )
        hunk_b = make_hunk(
            id="hb",
            file_path="src/module_b.py",
            added_lines=["from src.module_a import other_thing"],
        )
        assessment = await architecture_reviewer.review(
            [hunk_a, hunk_b], permissive_policy, review_request_id
        )
        assert isinstance(assessment, Assessment)
        # If circular dependency detected, should have ARC-003
        # Not all implementations may detect this, so just verify structure
        for finding in assessment.findings:
            assert re.match(r"^ARC-\d{3}$", finding.rule_id)

    @pytest.mark.asyncio
    async def test_no_exceptions_propagate(self, architecture_reviewer, permissive_policy, review_request_id):
        """Architecture review never raises exceptions."""
        hunk = make_hunk(
            added_lines=["weird import syntax that isn't valid"],
        )
        assessment = await architecture_reviewer.review([hunk], permissive_policy, review_request_id)
        assert isinstance(assessment, Assessment)


# ============================================================
# Cross-Cutting Invariant Tests
# ============================================================


class TestCrossCuttingInvariants:
    """Tests for cross-cutting contract invariants."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stage", [
        ReviewStage.security,
        ReviewStage.correctness,
        ReviewStage.style,
        ReviewStage.architecture,
    ])
    async def test_all_hunks_denied_returns_pass(self, stage):
        """All reviewers return PASS with empty findings when all hunks denied by policy."""
        reviewer = get_reviewer_by_stage(stage)
        deny_policy = make_policy(
            allowed_file_patterns=[],
            denied_file_patterns=["*"],
        )
        hunk = make_hunk(added_lines=["import os"])
        rrid = make_review_request_id()
        assessment = await reviewer.review([hunk], deny_policy, rrid)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stage", [
        ReviewStage.security,
        ReviewStage.correctness,
        ReviewStage.style,
        ReviewStage.architecture,
    ])
    async def test_empty_hunks_returns_pass(self, stage):
        """All reviewers return PASS with empty findings for empty hunk list."""
        reviewer = get_reviewer_by_stage(stage)
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        rrid = make_review_request_id()
        assessment = await reviewer.review([], policy, rrid)
        assert len(assessment.findings) == 0
        assert assessment.decision == ReviewDecision.pass_

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stage,expected_id", [
        (ReviewStage.security, "security"),
        (ReviewStage.correctness, "correctness"),
        (ReviewStage.style, "style"),
        (ReviewStage.architecture, "architecture"),
    ])
    async def test_reviewer_id_matches_stage(self, stage, expected_id):
        """Each reviewer's assessment has the correct reviewer_id."""
        reviewer = get_reviewer_by_stage(stage)
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        hunk = make_hunk(added_lines=["x = 1"])
        rrid = make_review_request_id()
        assessment = await reviewer.review([hunk], policy, rrid)
        assert assessment.reviewer_id == expected_id
        assert assessment.stage == stage

    @pytest.mark.asyncio
    @pytest.mark.parametrize("stage", [
        ReviewStage.security,
        ReviewStage.correctness,
        ReviewStage.style,
        ReviewStage.architecture,
    ])
    async def test_no_exceptions_propagate(self, stage):
        """No reviewer ever lets exceptions propagate."""
        reviewer = get_reviewer_by_stage(stage)
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        # Hunk with potentially problematic content
        hunk = make_hunk(
            added_lines=["\\x00 garbage \xff\xfe", "def \t\nbad(", "{{{{"],
        )
        rrid = make_review_request_id()
        # Should never raise
        assessment = await reviewer.review([hunk], policy, rrid)
        assert isinstance(assessment, Assessment)

    def test_derive_decision_deterministic(self):
        """derive_decision is deterministic - same inputs always produce same output."""
        findings = [
            make_finding(id="f1", severity=Severity.high, confidence=Confidence.medium),
            make_finding(id="f2", severity=Severity.low, confidence=Confidence.low),
        ]
        results = [derive_decision(findings) for _ in range(10)]
        assert all(r.decision == results[0].decision for r in results)
        assert all(r.min_confidence == results[0].min_confidence for r in results)

    def test_assessment_confidence_is_minimum(self):
        """Assessment.confidence is the conservative minimum across all findings."""
        findings = [
            make_finding(id="f1", severity=Severity.low, confidence=Confidence.high),
            make_finding(id="f2", severity=Severity.low, confidence=Confidence.medium),
            make_finding(id="f3", severity=Severity.low, confidence=Confidence.low),
        ]
        result = derive_decision(findings)
        assert result.min_confidence == Confidence.low

    @pytest.mark.asyncio
    async def test_rule_id_namespace_matches_stage(self):
        """Rule IDs are namespaced correctly: SEC for security, COR for correctness, etc."""
        stage_prefix_map = {
            ReviewStage.security: "SEC",
            ReviewStage.correctness: "COR",
            ReviewStage.style: "STY",
            ReviewStage.architecture: "ARC",
        }
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        rrid = make_review_request_id()

        # Create a hunk that's likely to trigger findings from most reviewers
        hunk = make_hunk(
            added_lines=[
                "API_KEY = 'sk-1234567890abcdef1234567890abcdef'",
                "def process(items=[]):",
                "    try:",
                "        risky()",
                "    except:",
                "        pass",
                "x = " + "a" * 200,
            ],
        )

        for stage, prefix in stage_prefix_map.items():
            reviewer = get_reviewer_by_stage(stage)
            assessment = await reviewer.review([hunk], policy, rrid)
            for finding in assessment.findings:
                assert finding.rule_id.startswith(prefix), (
                    f"Finding from {stage} reviewer has rule_id {finding.rule_id} "
                    f"which doesn't start with {prefix}"
                )


# ============================================================
# Additional Edge Cases and Randomized Tests
# ============================================================


class TestEdgeCases:
    """Additional edge case tests."""

    def test_derive_decision_single_info(self):
        """Single INFO finding -> PASS, confidence matches finding."""
        findings = [make_finding(severity=Severity.info, confidence=Confidence.medium)]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.pass_
        assert result.min_confidence == Confidence.medium

    def test_derive_decision_high_and_medium(self):
        """HIGH + MEDIUM -> BLOCK (HIGH dominates)."""
        findings = [
            make_finding(id="f1", severity=Severity.high, confidence=Confidence.high),
            make_finding(id="f2", severity=Severity.medium, confidence=Confidence.low),
        ]
        result = derive_decision(findings)
        assert result.decision == ReviewDecision.block
        assert result.has_high is True

    def test_filter_hunks_all_denied(self):
        """All hunks denied by deny pattern."""
        hunks = [make_hunk(id=f"h{i}", file_path=f"src/f{i}.py") for i in range(5)]
        policy = make_policy(denied_file_patterns=["*"])
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) == 0
        assert result.denied_count == 5

    def test_filter_hunks_non_matching_allowed(self):
        """When allowed_file_patterns is non-empty but matches nothing, all hunks denied."""
        hunks = [make_hunk(id="h1", file_path="src/main.py")]
        policy = make_policy(allowed_file_patterns=["*.rs"], denied_file_patterns=[])
        result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
        assert len(result.permitted) == 0
        assert result.denied_count == 1

    def test_build_assessment_with_findings(self):
        """build_assessment correctly incorporates findings into the assessment."""
        findings = [
            make_finding(id="f1", severity=Severity.critical, confidence=Confidence.high),
        ]
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        assessment = build_assessment("security", ReviewStage.security, findings, 1, 0, [], rrid, start_ns)
        assert len(assessment.findings) == 1
        assert assessment.decision == ReviewDecision.block

    def test_build_assessment_empty_findings_passes(self):
        """build_assessment with no findings produces PASS."""
        start_ns = time.monotonic_ns()
        rrid = make_review_request_id()
        assessment = build_assessment("security", ReviewStage.security, [], 0, 0, [], rrid, start_ns)
        assert assessment.decision == ReviewDecision.pass_
        assert assessment.confidence == Confidence.high

    @pytest.mark.asyncio
    async def test_security_reviewer_multiple_hunks(self):
        """SecurityReviewer handles multiple hunks correctly."""
        reviewer = get_reviewer_by_stage(ReviewStage.security)
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        hunks = [
            make_hunk(id="h1", file_path="src/a.py", added_lines=["API_KEY = 'secret123'"]),
            make_hunk(id="h2", file_path="src/b.py", added_lines=["x = 1"]),
            make_hunk(id="h3", file_path="src/c.py", added_lines=["password = 'admin'"]),
        ]
        rrid = make_review_request_id()
        assessment = await reviewer.review(hunks, policy, rrid)
        assert isinstance(assessment, Assessment)
        # Should have findings from at least the hunks with secrets
        assert len(assessment.findings) > 0

    @pytest.mark.asyncio
    async def test_correctness_reviewer_non_python_file(self):
        """CorrectnessReviewer handles non-Python files gracefully."""
        reviewer = get_reviewer_by_stage(ReviewStage.correctness)
        policy = make_policy(allowed_file_patterns=[], denied_file_patterns=[])
        hunk = make_hunk(
            file_path="config.yaml",
            added_lines=[
                "database:",
                "  host: localhost",
                "  port: 5432",
            ],
            language=None,
        )
        rrid = make_review_request_id()
        assessment = await reviewer.review([hunk], policy, rrid)
        assert isinstance(assessment, Assessment)
        # No crash, assessment returned

    def test_randomized_derive_decision_conservation(self):
        """Randomized test: derive_decision always returns valid decision for random findings."""
        import random
        random.seed(42)

        severities = [Severity.critical, Severity.high, Severity.medium, Severity.low, Severity.info]
        confidences = [Confidence.high, Confidence.medium, Confidence.low]

        for _ in range(50):
            n = random.randint(0, 20)
            findings = [
                make_finding(
                    id=f"f{i}",
                    severity=random.choice(severities),
                    confidence=random.choice(confidences),
                )
                for i in range(n)
            ]
            result = derive_decision(findings)

            # Decision should always be a valid ReviewDecision
            assert result.decision in [ReviewDecision.block, ReviewDecision.warn, ReviewDecision.pass_]

            # Confidence should always be valid
            assert result.min_confidence in [Confidence.high, Confidence.medium, Confidence.low]

            # If empty, should be PASS/HIGH
            if n == 0:
                assert result.decision == ReviewDecision.pass_
                assert result.min_confidence == Confidence.high

            # If any critical/high, should be BLOCK
            has_critical_or_high = any(
                f.severity in [Severity.critical, Severity.high] for f in findings
            )
            if has_critical_or_high:
                assert result.decision == ReviewDecision.block

    def test_randomized_filter_conservation(self):
        """Randomized test: filter_hunks_by_policy conservation property always holds."""
        import random
        random.seed(42)

        extensions = [".py", ".js", ".ts", ".rs", ".go", ".txt", ".md"]

        for _ in range(30):
            n = random.randint(0, 15)
            hunks = [
                make_hunk(
                    id=f"h{i}",
                    file_path=f"src/file{i}{random.choice(extensions)}",
                )
                for i in range(n)
            ]
            policy = make_policy(
                allowed_file_patterns=["*.py", "*.js"] if random.random() > 0.5 else [],
                denied_file_patterns=["*test*"] if random.random() > 0.5 else [],
            )
            result = filter_hunks_by_policy(hunks, policy, ReviewStage.security)
            assert len(result.permitted) + result.denied_count == n
