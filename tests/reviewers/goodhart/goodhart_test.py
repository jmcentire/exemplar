"""
Adversarial hidden acceptance tests for Reviewer Implementations.
These tests are designed to catch implementations that pass visible tests
through shortcuts (hardcoded returns, incomplete logic) rather than truly
satisfying the contract.
"""
import asyncio
import re
import time
import uuid
from unittest.mock import MagicMock, patch

import pytest

from exemplar.reviewers import (
    filter_hunks_by_policy,
    derive_decision,
    build_assessment,
    get_all_reviewers,
    get_reviewer_by_stage,
)

# Try importing types from schemas
try:
    from exemplar.schemas import (
        ReviewStage,
        Severity,
        Confidence,
        ReviewDecision,
        DiffHunk,
        PolicyToken,
        Finding,
        Assessment,
        FilteredHunksResult,
        DecisionDerivation,
        ClassificationLabel,
    )
except ImportError:
    # Fallback: try importing from reviewers module itself
    from exemplar.reviewers import (
        ReviewStage,
        Severity,
        Confidence,
        ReviewDecision,
        DiffHunk,
        PolicyToken,
        Finding,
        Assessment,
        FilteredHunksResult,
        DecisionDerivation,
        ClassificationLabel,
    )


# ============================================================
# Helper factories
# ============================================================

def make_hunk(
    hunk_id="hunk-1",
    file_path="src/main.py",
    added_lines=None,
    removed_lines=None,
    context_before=None,
    context_after=None,
    start_line_new=1,
    count_new=1,
    start_line_old=1,
    count_old=0,
    classifications=None,
    language="python",
    raw_header="@@ -1,0 +1,1 @@",
):
    """Create a minimal DiffHunk for testing."""
    kwargs = dict(
        id=hunk_id,
        file_path=file_path,
        start_line_old=start_line_old,
        count_old=count_old,
        start_line_new=start_line_new,
        count_new=count_new,
        context_before=context_before or [],
        added_lines=added_lines or [],
        removed_lines=removed_lines or [],
        context_after=context_after or [],
        raw_header=raw_header,
        classifications=classifications or [ClassificationLabel.public] if hasattr(ClassificationLabel, 'public') else classifications or ["public"],
        language=language,
    )
    try:
        return DiffHunk(**kwargs)
    except Exception:
        # If DiffHunk is a dataclass or namedtuple
        return type("DiffHunk", (), kwargs)()


def make_policy(
    allowed_file_patterns=None,
    denied_file_patterns=None,
    allowed_classifications=None,
    reviewer_id="security",
    max_severity=None,
):
    """Create a minimal PolicyToken for testing."""
    sev = max_severity or (Severity.critical if hasattr(Severity, 'critical') else "critical")
    kwargs = dict(
        token_id="tok-001",
        reviewer_id=reviewer_id,
        allowed_file_patterns=allowed_file_patterns or [],
        denied_file_patterns=denied_file_patterns or [],
        allowed_classifications=allowed_classifications or [],
        max_severity=sev,
        issued_at="2024-01-01T00:00:00Z",
        expires_at=None,
    )
    try:
        return PolicyToken(**kwargs)
    except Exception:
        return type("PolicyToken", (), kwargs)()


def make_finding(
    severity="medium",
    confidence="high",
    rule_id="SEC-001",
    stage="security",
    hunk_id="hunk-1",
    file_path="src/main.py",
    finding_id=None,
):
    """Create a minimal Finding for testing."""
    sev = getattr(Severity, severity, severity)
    conf = getattr(Confidence, confidence, confidence)
    stg = getattr(ReviewStage, stage, stage)
    kwargs = dict(
        id=finding_id or f"finding-{uuid.uuid4().hex[:8]}",
        hunk_id=hunk_id,
        file_path=file_path,
        line_number=1,
        severity=sev,
        confidence=conf,
        title="Test finding",
        description="Test description",
        suggestion=None,
        rule_id=rule_id,
        stage=stg,
    )
    try:
        return Finding(**kwargs)
    except Exception:
        return type("Finding", (), kwargs)()


REVIEW_REQUEST_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
REVIEW_REQUEST_ID_2 = "11111111-2222-3333-4444-555555555555"


# ============================================================
# derive_decision tests
# ============================================================

class TestGoodhartDeriveDecision:

    def test_goodhart_derive_decision_mixed_critical_and_low_confidence(self):
        """derive_decision with mixed severities including CRITICAL should BLOCK,
        and min_confidence should reflect the lowest confidence finding."""
        findings = [
            make_finding(severity="critical", confidence="high"),
            make_finding(severity="low", confidence="low"),
            make_finding(severity="medium", confidence="medium"),
        ]
        result = derive_decision(findings)
        block = getattr(ReviewDecision, "block", None) or getattr(ReviewDecision, "BLOCK", "block")
        assert result.decision == block
        assert result.has_critical is True
        low_conf = getattr(Confidence, "low", None) or getattr(Confidence, "LOW", "low")
        assert result.min_confidence == low_conf

    def test_goodhart_derive_decision_single_medium_confidence_low(self):
        """derive_decision with a single MEDIUM-severity LOW-confidence finding
        should produce WARN decision with LOW confidence."""
        findings = [make_finding(severity="medium", confidence="low")]
        result = derive_decision(findings)
        # Decision should be WARN/ADVISORY, not PASS
        pass_dec = getattr(ReviewDecision, "pass_", None) or getattr(ReviewDecision, "PASS", None) or getattr(ReviewDecision, "pass", "pass")
        block_dec = getattr(ReviewDecision, "block", None) or getattr(ReviewDecision, "BLOCK", "block")
        assert result.decision != pass_dec, "MEDIUM severity must not produce PASS"
        assert result.decision != block_dec, "MEDIUM severity alone must not produce BLOCK"
        low_conf = getattr(Confidence, "low", None) or getattr(Confidence, "LOW", "low")
        assert result.min_confidence == low_conf

    def test_goodhart_derive_decision_multiple_low_and_info(self):
        """derive_decision with a mix of LOW and INFO findings should PASS."""
        findings = [
            make_finding(severity="low", confidence="high"),
            make_finding(severity="info", confidence="medium"),
            make_finding(severity="low", confidence="medium"),
            make_finding(severity="info", confidence="high"),
        ]
        result = derive_decision(findings)
        assert result.has_critical is False
        assert result.has_high is False
        # Should be PASS
        pass_dec = getattr(ReviewDecision, "pass_", None) or getattr(ReviewDecision, "PASS", None) or getattr(ReviewDecision, "pass", "pass")
        # Accept various enum representations
        assert str(result.decision).lower().replace("reviewdecision.", "") in ("pass", "pass_"), \
            f"Expected PASS for LOW+INFO findings, got {result.decision}"
        med_conf = getattr(Confidence, "medium", None) or getattr(Confidence, "MEDIUM", "medium")
        assert result.min_confidence == med_conf

    def test_goodhart_derive_decision_has_critical_flag(self):
        """DecisionDerivation must accurately report has_critical and has_high flags."""
        # Only HIGH, no CRITICAL
        findings_high = [make_finding(severity="high", confidence="high")]
        result_high = derive_decision(findings_high)
        assert result_high.has_high is True
        assert result_high.has_critical is False

        # Only CRITICAL, no HIGH
        findings_crit = [make_finding(severity="critical", confidence="high")]
        result_crit = derive_decision(findings_crit)
        assert result_crit.has_critical is True
        # has_high could be False since there's no HIGH finding specifically
        # (the contract says "has_high" tracks HIGH, not CRITICAL)

    def test_goodhart_derive_decision_high_and_medium_blocks(self):
        """HIGH + MEDIUM findings should BLOCK, not WARN."""
        findings = [
            make_finding(severity="high", confidence="high"),
            make_finding(severity="medium", confidence="medium"),
        ]
        result = derive_decision(findings)
        block_dec = getattr(ReviewDecision, "block", None) or getattr(ReviewDecision, "BLOCK", "block")
        assert result.decision == block_dec


# ============================================================
# build_assessment tests
# ============================================================

class TestGoodhartBuildAssessment:

    def test_goodhart_build_assessment_deterministic_different_reviewers(self):
        """Different reviewer_ids with same review_request_id must produce different assessment IDs."""
        start_ns = time.monotonic_ns()
        a1 = build_assessment("security", ReviewStage.security if hasattr(ReviewStage, 'security') else "security",
                              [], 0, 0, [], REVIEW_REQUEST_ID, start_ns)
        a2 = build_assessment("correctness", ReviewStage.correctness if hasattr(ReviewStage, 'correctness') else "correctness",
                              [], 0, 0, [], REVIEW_REQUEST_ID, start_ns)
        assert a1.id != a2.id, "Different reviewer_ids must produce different assessment IDs"

    def test_goodhart_build_assessment_all_four_reviewer_ids(self):
        """build_assessment must accept all four canonical reviewer names."""
        start_ns = time.monotonic_ns()
        for rid, stage_name in [("security", "security"), ("correctness", "correctness"),
                                ("style", "style"), ("architecture", "architecture")]:
            stage = getattr(ReviewStage, stage_name, stage_name)
            a = build_assessment(rid, stage, [], 0, 0, [], REVIEW_REQUEST_ID, start_ns)
            assert a is not None

    def test_goodhart_build_assessment_decision_matches_derive(self):
        """build_assessment must derive decision from findings, not hardcode PASS."""
        start_ns = time.monotonic_ns()
        critical_finding = make_finding(severity="critical", confidence="high", rule_id="SEC-001", stage="security")
        a_with = build_assessment("security", ReviewStage.security if hasattr(ReviewStage, 'security') else "security",
                                  [critical_finding], 1, 0, [], REVIEW_REQUEST_ID, start_ns)
        block_dec = getattr(ReviewDecision, "block", None) or getattr(ReviewDecision, "BLOCK", "block")
        assert a_with.decision == block_dec, "Assessment with CRITICAL finding must have BLOCK decision"

        a_empty = build_assessment("security", ReviewStage.security if hasattr(ReviewStage, 'security') else "security",
                                   [], 0, 0, [], REVIEW_REQUEST_ID, start_ns)
        pass_dec = getattr(ReviewDecision, "pass_", None) or getattr(ReviewDecision, "PASS", None) or getattr(ReviewDecision, "pass", "pass")
        assert str(a_empty.decision).lower().replace("reviewdecision.", "") in ("pass", "pass_")

    def test_goodhart_build_assessment_uuid5_namespace_dns(self):
        """Assessment ID must match uuid5(NAMESPACE_DNS, '{review_request_id}:{reviewer_id}')."""
        start_ns = time.monotonic_ns()
        rid = "security"
        a = build_assessment(rid, ReviewStage.security if hasattr(ReviewStage, 'security') else "security",
                             [], 0, 0, [], REVIEW_REQUEST_ID, start_ns)
        expected_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{REVIEW_REQUEST_ID}:{rid}"))
        assert a.id == expected_id, f"Expected {expected_id}, got {a.id}"

    def test_goodhart_build_assessment_review_request_id_stored(self):
        """Assessment must store the review_request_id."""
        start_ns = time.monotonic_ns()
        a = build_assessment("security", ReviewStage.security if hasattr(ReviewStage, 'security') else "security",
                             [], 0, 0, [], REVIEW_REQUEST_ID_2, start_ns)
        assert a.review_request_id == REVIEW_REQUEST_ID_2


# ============================================================
# filter_hunks_by_policy tests
# ============================================================

class TestGoodhartFilterHunks:

    def test_goodhart_filter_hunks_deny_pattern_glob_star(self):
        """Deny patterns with globs must actually use fnmatch, not string equality."""
        h1 = make_hunk(hunk_id="h1", file_path="config/secrets.yaml")
        h2 = make_hunk(hunk_id="h2", file_path="src/main.py")
        policy = make_policy(denied_file_patterns=["config/*.yaml"])
        stage = getattr(ReviewStage, "security", "security")
        result = filter_hunks_by_policy([h1, h2], policy, stage)
        permitted_paths = [h.file_path for h in result.permitted]
        assert "config/secrets.yaml" not in permitted_paths
        assert "src/main.py" in permitted_paths
        assert result.denied_count == 1

    def test_goodhart_filter_hunks_allowed_pattern_no_match(self):
        """Hunks not matching allowed patterns should be denied."""
        h1 = make_hunk(hunk_id="h1", file_path="src/main.py")
        h2 = make_hunk(hunk_id="h2", file_path="tests/test_main.py")
        policy = make_policy(allowed_file_patterns=["tests/*.py"])
        stage = getattr(ReviewStage, "security", "security")
        result = filter_hunks_by_policy([h1, h2], policy, stage)
        permitted_paths = [h.file_path for h in result.permitted]
        assert "src/main.py" not in permitted_paths
        assert "tests/test_main.py" in permitted_paths
        assert result.denied_count == 1

    def test_goodhart_filter_hunks_multiple_deny_patterns(self):
        """Multiple deny patterns should each independently exclude matching hunks."""
        h1 = make_hunk(hunk_id="h1", file_path="vendor/lib.py")
        h2 = make_hunk(hunk_id="h2", file_path="generated/output.py")
        h3 = make_hunk(hunk_id="h3", file_path="src/app.py")
        policy = make_policy(denied_file_patterns=["vendor/*", "generated/*"])
        stage = getattr(ReviewStage, "security", "security")
        result = filter_hunks_by_policy([h1, h2, h3], policy, stage)
        permitted_paths = [h.file_path for h in result.permitted]
        assert "vendor/lib.py" not in permitted_paths
        assert "generated/output.py" not in permitted_paths
        assert "src/app.py" in permitted_paths
        assert result.denied_count == 2

    def test_goodhart_filter_hunks_deny_overrides_allow_glob(self):
        """Deny-wins: a file matching both allowed and denied should be excluded."""
        h1 = make_hunk(hunk_id="h1", file_path="src/secrets.py")
        policy = make_policy(
            allowed_file_patterns=["src/*.py"],
            denied_file_patterns=["*secrets*"],
        )
        stage = getattr(ReviewStage, "security", "security")
        result = filter_hunks_by_policy([h1], policy, stage)
        assert len(result.permitted) == 0
        assert result.denied_count == 1

    def test_goodhart_filter_hunks_single_hunk_denied(self):
        """Single hunk matching deny pattern gives empty permitted and denied_count=1."""
        h1 = make_hunk(hunk_id="h1", file_path="secret.key")
        policy = make_policy(denied_file_patterns=["secret.*"])
        stage = getattr(ReviewStage, "security", "security")
        result = filter_hunks_by_policy([h1], policy, stage)
        assert result.permitted == [] or len(result.permitted) == 0
        assert result.denied_count == 1

    def test_goodhart_filter_hunks_all_denied_by_pattern(self):
        """Deny pattern matching all hunks returns empty permitted."""
        hunks = [
            make_hunk(hunk_id=f"h{i}", file_path=f"src/file{i}.py")
            for i in range(5)
        ]
        policy = make_policy(denied_file_patterns=["src/*"])
        stage = getattr(ReviewStage, "security", "security")
        result = filter_hunks_by_policy(hunks, policy, stage)
        assert len(result.permitted) == 0
        assert result.denied_count == 5


# ============================================================
# SecurityReviewer tests
# ============================================================

class TestGoodhartSecurityReviewer:

    @pytest.fixture
    def reviewer(self):
        stage = getattr(ReviewStage, "security", "security")
        return get_reviewer_by_stage(stage)

    def test_goodhart_security_detects_path_traversal(self, reviewer):
        """SecurityReviewer must detect path traversal patterns."""
        hunk = make_hunk(
            added_lines=["open('../../../etc/passwd')", "path = user_input + '/../secret'"],
            file_path="src/handler.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [f.rule_id for f in assessment.findings]
        assert any("SEC-003" in str(rid) for rid in rule_ids), \
            f"Expected SEC-003 path traversal finding, got rule_ids: {rule_ids}"

    def test_goodhart_security_detects_command_injection(self, reviewer):
        """SecurityReviewer must detect command injection patterns."""
        hunk = make_hunk(
            added_lines=[
                "import os",
                "os.system(user_input)",
                "subprocess.call(cmd, shell=True)",
            ],
            file_path="src/executor.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [str(f.rule_id) for f in assessment.findings]
        assert any("SEC-004" in rid for rid in rule_ids), \
            f"Expected SEC-004 command injection finding, got rule_ids: {rule_ids}"

    def test_goodhart_security_detects_insecure_deserialization(self, reviewer):
        """SecurityReviewer must detect insecure deserialization patterns."""
        hunk = make_hunk(
            added_lines=[
                "import pickle",
                "data = pickle.loads(user_data)",
            ],
            file_path="src/loader.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [str(f.rule_id) for f in assessment.findings]
        assert any("SEC-005" in rid for rid in rule_ids), \
            f"Expected SEC-005 insecure deserialization finding, got rule_ids: {rule_ids}"

    def test_goodhart_security_multiple_findings_in_one_hunk(self, reviewer):
        """A hunk with multiple distinct security issues should produce multiple findings."""
        hunk = make_hunk(
            added_lines=[
                "API_KEY = 'sk-1234567890abcdef'",
                "query = f'SELECT * FROM users WHERE id = {user_id}'",
                "os.system(user_input)",
            ],
            file_path="src/bad.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        assert len(assessment.findings) > 1, \
            f"Expected multiple findings, got {len(assessment.findings)}"
        rule_ids = set(str(f.rule_id) for f in assessment.findings)
        assert len(rule_ids) > 1, \
            f"Expected distinct rule_ids, got {rule_ids}"

    def test_goodhart_security_only_scans_added_lines(self, reviewer):
        """SecurityReviewer should not flag vulnerabilities that only appear in removed_lines."""
        # Hunk with vulnerability only in removed lines
        hunk_removed = make_hunk(
            hunk_id="h-removed",
            added_lines=["x = 1"],
            removed_lines=["API_KEY = 'sk-1234567890abcdef'"],
            file_path="src/cleaned.py",
        )
        policy = make_policy()
        assessment_removed = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk_removed], policy, REVIEW_REQUEST_ID)
        )

        # Hunk with vulnerability in added lines
        hunk_added = make_hunk(
            hunk_id="h-added",
            added_lines=["API_KEY = 'sk-1234567890abcdef'"],
            removed_lines=[],
            file_path="src/bad.py",
        )
        assessment_added = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk_added], policy, REVIEW_REQUEST_ID_2)
        )

        assert len(assessment_added.findings) > 0, "Should detect vulnerability in added_lines"
        # Removed-only should have no findings (or fewer)
        assert len(assessment_removed.findings) == 0, \
            "Should not flag vulnerabilities only in removed_lines"

    def test_goodhart_security_per_hunk_isolation(self, reviewer):
        """Error in one hunk must not prevent analysis of other hunks."""
        good_hunk = make_hunk(
            hunk_id="good",
            added_lines=["API_KEY = 'sk-1234567890abcdef'"],
            file_path="src/good.py",
        )
        # Create a hunk that might cause issues but shouldn't crash
        weird_hunk = make_hunk(
            hunk_id="weird",
            added_lines=["normal_code = True"],
            file_path="src/weird.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([weird_hunk, good_hunk], policy, REVIEW_REQUEST_ID)
        )
        # Should still have findings from the good hunk
        assert len(assessment.findings) > 0, "Findings from valid hunk should be present"

    def test_goodhart_security_review_request_id_in_assessment(self, reviewer):
        """Assessment must contain the correct review_request_id."""
        hunk = make_hunk(added_lines=["x = 1"], file_path="src/clean.py")
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID_2)
        )
        assert assessment.review_request_id == REVIEW_REQUEST_ID_2

    def test_goodhart_security_finding_hunk_id_reference(self, reviewer):
        """Findings must reference the correct hunk_id and file_path."""
        hunk = make_hunk(
            hunk_id="specific-hunk-42",
            added_lines=["API_KEY = 'sk-1234567890abcdef'"],
            file_path="src/specific.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        assert len(assessment.findings) > 0
        for f in assessment.findings:
            assert f.hunk_id == "specific-hunk-42", f"Finding hunk_id should be 'specific-hunk-42', got '{f.hunk_id}'"
            assert f.file_path == "src/specific.py", f"Finding file_path should be 'src/specific.py', got '{f.file_path}'"

    def test_goodhart_security_weak_crypto(self, reviewer):
        """SecurityReviewer must detect weak cryptography usage."""
        hunk = make_hunk(
            added_lines=[
                "import hashlib",
                "h = hashlib.md5(password.encode())",
                "digest = hashlib.sha1(data)",
            ],
            file_path="src/crypto.py",
        )
        policy = make_policy()
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [str(f.rule_id) for f in assessment.findings]
        assert any("SEC-006" in rid for rid in rule_ids), \
            f"Expected SEC-006 weak crypto finding, got rule_ids: {rule_ids}"


# ============================================================
# CorrectnessReviewer tests
# ============================================================

class TestGoodhartCorrectnessReviewer:

    @pytest.fixture
    def reviewer(self):
        stage = getattr(ReviewStage, "correctness", "correctness")
        return get_reviewer_by_stage(stage)

    def test_goodhart_correctness_non_python_file_graceful(self, reviewer):
        """Non-Python files should be handled gracefully without errors."""
        hunk = make_hunk(
            hunk_id="js-hunk",
            added_lines=["const x = null;", "x.toString();"],
            file_path="src/app.js",
            language="javascript",
        )
        policy = make_policy(reviewer_id="correctness")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        assert assessment is not None
        # Should not have COR findings for non-Python files (or handle gracefully)
        # Most importantly: no exception

    def test_goodhart_correctness_idempotent(self, reviewer):
        """Two calls with same inputs must produce identical assessments."""
        hunk = make_hunk(
            added_lines=["try:", "    x = 1", "except:", "    pass"],
            file_path="src/test.py",
        )
        policy = make_policy(reviewer_id="correctness")
        a1 = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        a2 = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        assert a1.id == a2.id
        assert a1.decision == a2.decision
        assert len(a1.findings) == len(a2.findings)
        for f1, f2 in zip(a1.findings, a2.findings):
            assert f1.rule_id == f2.rule_id

    def test_goodhart_correctness_review_request_id_in_assessment(self, reviewer):
        """Assessment must contain the correct review_request_id."""
        hunk = make_hunk(added_lines=["x = 1"], file_path="src/clean.py")
        policy = make_policy(reviewer_id="correctness")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID_2)
        )
        assert assessment.review_request_id == REVIEW_REQUEST_ID_2

    def test_goodhart_correctness_detects_unreachable_code(self, reviewer):
        """CorrectnessReviewer must detect unreachable code after return."""
        hunk = make_hunk(
            added_lines=[
                "def foo():",
                "    return 42",
                "    x = 1",
                "    print(x)",
            ],
            file_path="src/unreachable.py",
        )
        policy = make_policy(reviewer_id="correctness")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [str(f.rule_id) for f in assessment.findings]
        assert any("COR-006" in rid for rid in rule_ids), \
            f"Expected COR-006 unreachable code finding, got: {rule_ids}"


# ============================================================
# StyleReviewer tests
# ============================================================

class TestGoodhartStyleReviewer:

    @pytest.fixture
    def reviewer(self):
        stage = getattr(ReviewStage, "style", "style")
        return get_reviewer_by_stage(stage)

    def test_goodhart_style_naming_convention_violation(self, reviewer):
        """StyleReviewer must detect camelCase function names."""
        hunk = make_hunk(
            added_lines=[
                "def myBadFunction():",
                "    pass",
                "def anotherCamelCase():",
                "    return True",
            ],
            file_path="src/naming.py",
        )
        policy = make_policy(reviewer_id="style")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [str(f.rule_id) for f in assessment.findings]
        assert any("STY-002" in rid for rid in rule_ids), \
            f"Expected STY-002 naming convention finding, got: {rule_ids}"

    def test_goodhart_style_severity_never_critical_or_high(self, reviewer):
        """Style findings must never exceed MEDIUM severity for any input."""
        hunk = make_hunk(
            added_lines=[
                "x" * 200,  # Very long line
                "def badName():  ",  # trailing whitespace + bad name
                "\t    mixed = True",  # mixed indentation
                "def anotherBadName():",
            ],
            file_path="src/ugly.py",
        )
        policy = make_policy(reviewer_id="style")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        critical_sev = getattr(Severity, "critical", "critical")
        high_sev = getattr(Severity, "high", "high")
        for f in assessment.findings:
            assert f.severity != critical_sev, f"Style finding should never be CRITICAL: {f}"
            assert f.severity != high_sev, f"Style finding should never be HIGH: {f}"

    def test_goodhart_style_mixed_indentation(self, reviewer):
        """StyleReviewer must detect mixed indentation."""
        hunk = make_hunk(
            added_lines=[
                "def foo():",
                "    x = 1",       # spaces
                "\ty = 2",         # tab
                "    z = x + y",   # back to spaces
            ],
            file_path="src/indent.py",
        )
        policy = make_policy(reviewer_id="style")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        # Should detect at least some style issue
        assert len(assessment.findings) > 0, \
            "Expected style findings for mixed indentation"

    def test_goodhart_style_decision_derived_from_findings(self, reviewer):
        """StyleReviewer decision must be derived from findings severity."""
        # Use code with many style issues to hopefully get MEDIUM findings
        hunk = make_hunk(
            added_lines=[
                "x" * 200,  # long line → likely MEDIUM or LOW
                "def badName():  ",
            ],
            file_path="src/style_issues.py",
        )
        policy = make_policy(reviewer_id="style")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        if len(assessment.findings) > 0:
            # If there are findings, decision should be consistent with derive_decision
            derived = derive_decision(assessment.findings)
            assert assessment.decision == derived.decision, \
                f"Assessment decision {assessment.decision} doesn't match derived {derived.decision}"


# ============================================================
# ArchitectureReviewer tests
# ============================================================

class TestGoodhartArchitectureReviewer:

    @pytest.fixture
    def reviewer(self):
        stage = getattr(ReviewStage, "architecture", "architecture")
        return get_reviewer_by_stage(stage)

    def test_goodhart_architecture_circular_dependency(self, reviewer):
        """ArchitectureReviewer must detect circular imports across hunks."""
        hunk_a = make_hunk(
            hunk_id="hunk-a",
            file_path="src/module_a.py",
            added_lines=[
                "from src.module_b import something",
                "x = something()",
            ],
        )
        hunk_b = make_hunk(
            hunk_id="hunk-b",
            file_path="src/module_b.py",
            added_lines=[
                "from src.module_a import other_thing",
                "y = other_thing()",
            ],
        )
        policy = make_policy(reviewer_id="architecture")
        assessment = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk_a, hunk_b], policy, REVIEW_REQUEST_ID)
        )
        rule_ids = [str(f.rule_id) for f in assessment.findings]
        assert any("ARC-003" in rid for rid in rule_ids), \
            f"Expected ARC-003 circular dependency finding, got: {rule_ids}"

    def test_goodhart_architecture_cross_hunk_analysis(self, reviewer):
        """ArchitectureReviewer must consider all hunks collectively for import analysis."""
        # Same as circular dependency but verifying cross-hunk behavior
        hunk_a = make_hunk(
            hunk_id="cross-a",
            file_path="src/alpha.py",
            added_lines=["from src.beta import helper"],
        )
        hunk_b = make_hunk(
            hunk_id="cross-b",
            file_path="src/beta.py",
            added_lines=["from src.alpha import util"],
        )
        policy = make_policy(reviewer_id="architecture")

        # Review with both hunks
        assessment_both = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk_a, hunk_b], policy, REVIEW_REQUEST_ID)
        )

        # Review with only one hunk - should NOT detect circular dependency
        assessment_one = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk_a], policy, REVIEW_REQUEST_ID_2)
        )

        # With both hunks, we should see the circular dependency
        both_rule_ids = [str(f.rule_id) for f in assessment_both.findings]
        one_rule_ids = [str(f.rule_id) for f in assessment_one.findings]

        circular_in_both = any("ARC-003" in rid for rid in both_rule_ids)
        circular_in_one = any("ARC-003" in rid for rid in one_rule_ids)

        assert circular_in_both, "Circular dependency should be detected with both hunks"
        assert not circular_in_one, "Circular dependency should NOT be detected with single hunk"

    def test_goodhart_architecture_idempotent(self, reviewer):
        """ArchitectureReviewer.review must be idempotent."""
        hunk = make_hunk(
            added_lines=[
                "import os",
                "import sys",
                "from pathlib import Path",
            ],
            file_path="src/imports.py",
        )
        policy = make_policy(reviewer_id="architecture")
        a1 = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        a2 = asyncio.get_event_loop().run_until_complete(
            reviewer.review([hunk], policy, REVIEW_REQUEST_ID)
        )
        assert a1.id == a2.id
        assert a1.decision == a2.decision
        assert len(a1.findings) == len(a2.findings)


# ============================================================
# get_all_reviewers / get_reviewer_by_stage tests
# ============================================================

class TestGoodhartReviewerFactory:

    def test_goodhart_get_all_reviewers_protocol_conformance(self):
        """Each reviewer must have review method, reviewer_id, and stage attributes."""
        reviewers = get_all_reviewers()
        for r in reviewers:
            assert hasattr(r, 'review'), f"Reviewer {r} missing 'review' method"
            assert callable(r.review), f"Reviewer {r}.review is not callable"
            assert hasattr(r, 'reviewer_id'), f"Reviewer {r} missing 'reviewer_id'"
            assert hasattr(r, 'stage'), f"Reviewer {r} missing 'stage'"

    def test_goodhart_get_reviewer_by_stage_all_stages(self):
        """get_reviewer_by_stage must return correct reviewer for every stage."""
        stage_to_id = {
            "security": "security",
            "correctness": "correctness",
            "style": "style",
            "architecture": "architecture",
        }
        for stage_name, expected_id in stage_to_id.items():
            stage = getattr(ReviewStage, stage_name, stage_name)
            reviewer = get_reviewer_by_stage(stage)
            assert reviewer.reviewer_id == expected_id, \
                f"Stage {stage_name} should give reviewer_id '{expected_id}', got '{reviewer.reviewer_id}'"

    def test_goodhart_reviewer_stage_property_matches(self):
        """Each reviewer's stage property must match its expected ReviewStage."""
        reviewers = get_all_reviewers()
        expected_stages = ["security", "correctness", "style", "architecture"]
        for r, expected_name in zip(reviewers, expected_stages):
            expected_stage = getattr(ReviewStage, expected_name, expected_name)
            assert r.stage == expected_stage, \
                f"Reviewer '{r.reviewer_id}' has stage {r.stage}, expected {expected_stage}"

    def test_goodhart_all_reviewers_no_exception_on_varied_hunks(self):
        """All four reviewers must handle mixed Python and non-Python hunks without exceptions."""
        hunks = [
            make_hunk(hunk_id="py", file_path="src/main.py", added_lines=["x = 1"], language="python"),
            make_hunk(hunk_id="js", file_path="src/app.js", added_lines=["const x = 1;"], language="javascript"),
            make_hunk(hunk_id="md", file_path="README.md", added_lines=["# Hello"], language=None),
        ]
        policy = make_policy()
        reviewers = get_all_reviewers()
        for r in reviewers:
            try:
                assessment = asyncio.get_event_loop().run_until_complete(
                    r.review(hunks, policy, REVIEW_REQUEST_ID)
                )
                assert assessment is not None, f"Reviewer {r.reviewer_id} returned None"
            except Exception as e:
                pytest.fail(f"Reviewer {r.reviewer_id} raised exception: {e}")
