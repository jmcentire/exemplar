"""Tests for PreflightManager — red-line enforcement before tool execution.

Covers: plan creation/persistence, expiry, red-line matching via fnmatch,
contingency lookup, violation recording, MCP fire-and-forget fallback.
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from exemplar.governance import (
    GovernanceError,
    PreflightManager,
    PreflightPlan,
    PreflightViolation,
)


@pytest.fixture
def preflight_dir(tmp_path):
    """Provide a temporary directory for preflight storage."""
    d = tmp_path / "preflight"
    d.mkdir()
    return d


@pytest.fixture
def mgr(preflight_dir):
    """PreflightManager wired to tmp storage."""
    return PreflightManager(base_dir=preflight_dir)


# ---------------------------------------------------------------------------
# submit_preflight
# ---------------------------------------------------------------------------
class TestSubmitPreflight:
    def test_basic_submit(self, mgr, preflight_dir):
        plan = mgr.submit_preflight(
            component_id="intake",
            red_lines=["rm_rf_*", "drop_table_*"],
            contingencies={"rm_rf_*": "use safe_delete instead"},
            lockout_minutes=15,
        )
        assert isinstance(plan, PreflightPlan)
        assert plan.component_id == "intake"
        assert plan.red_lines == ["rm_rf_*", "drop_table_*"]
        assert plan.contingencies == {"rm_rf_*": "use safe_delete instead"}
        assert plan.lockout_minutes == 15
        assert plan.plan_id  # non-empty hex
        assert plan.created_at
        assert plan.expires_at

        # File should exist on disk
        path = preflight_dir / "intake.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["plan_id"] == plan.plan_id

    def test_submit_default_lockout(self, mgr):
        plan = mgr.submit_preflight("comp", red_lines=["*dangerous*"])
        assert plan.lockout_minutes == 30

    def test_submit_replaces_previous(self, mgr, preflight_dir):
        plan1 = mgr.submit_preflight("comp", red_lines=["a"])
        plan2 = mgr.submit_preflight("comp", red_lines=["b"])
        assert plan1.plan_id != plan2.plan_id
        # Only one file
        data = json.loads((preflight_dir / "comp.json").read_text())
        assert data["plan_id"] == plan2.plan_id

    def test_submit_empty_component_raises(self, mgr):
        with pytest.raises(GovernanceError, match="component_id"):
            mgr.submit_preflight("", red_lines=["x"])

    def test_submit_whitespace_component_raises(self, mgr):
        with pytest.raises(GovernanceError, match="component_id"):
            mgr.submit_preflight("   ", red_lines=["x"])

    def test_submit_empty_red_lines_raises(self, mgr):
        with pytest.raises(GovernanceError, match="red_lines"):
            mgr.submit_preflight("comp", red_lines=[])

    def test_expiry_is_correct(self, mgr):
        before = datetime.now(timezone.utc)
        plan = mgr.submit_preflight("comp", red_lines=["x"], lockout_minutes=60)
        after = datetime.now(timezone.utc)
        expires = datetime.fromisoformat(plan.expires_at)
        assert expires >= before + timedelta(minutes=60)
        assert expires <= after + timedelta(minutes=60)

    def test_mcp_fallback_does_not_raise(self, mgr):
        """MCP submit failure is swallowed — local storage still works."""
        with patch.object(
            PreflightManager,
            "_try_mcp_submit",
            side_effect=RuntimeError("boom"),
        ):
            plan = mgr.submit_preflight("comp", red_lines=["x"])
            assert plan.plan_id  # still created


# ---------------------------------------------------------------------------
# get_active_preflight
# ---------------------------------------------------------------------------
class TestGetActivePreflight:
    def test_get_existing(self, mgr):
        submitted = mgr.submit_preflight("comp", red_lines=["x"])
        fetched = mgr.get_active_preflight("comp")
        assert fetched is not None
        assert fetched.plan_id == submitted.plan_id

    def test_get_missing_returns_none(self, mgr):
        assert mgr.get_active_preflight("nonexistent") is None

    def test_expired_plan_returns_none(self, mgr, preflight_dir):
        """A plan whose expires_at is in the past should return None."""
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        plan_data = {
            "plan_id": "deadbeef",
            "component_id": "comp",
            "red_lines": ["x"],
            "contingencies": {},
            "lockout_minutes": 1,
            "created_at": (past - timedelta(minutes=2)).isoformat(),
            "expires_at": past.isoformat(),
        }
        path = preflight_dir / "comp.json"
        path.write_text(json.dumps(plan_data))
        assert mgr.get_active_preflight("comp") is None

    def test_corrupt_file_returns_none(self, mgr, preflight_dir):
        path = preflight_dir / "comp.json"
        path.write_text("NOT VALID JSON {{{")
        assert mgr.get_active_preflight("comp") is None


# ---------------------------------------------------------------------------
# check_violation
# ---------------------------------------------------------------------------
class TestCheckViolation:
    def test_allowed_when_no_plan(self, mgr):
        allowed, alt = mgr.check_violation("comp", "any_tool", {})
        assert allowed is True
        assert alt is None

    def test_allowed_when_no_match(self, mgr):
        mgr.submit_preflight("comp", red_lines=["rm_rf_*"])
        allowed, alt = mgr.check_violation("comp", "safe_delete", {})
        assert allowed is True
        assert alt is None

    def test_blocked_on_match(self, mgr):
        mgr.submit_preflight(
            "comp",
            red_lines=["rm_rf_*"],
            contingencies={"rm_rf_*": "use safe_delete"},
        )
        allowed, alt = mgr.check_violation("comp", "rm_rf_everything", {})
        assert allowed is False
        assert alt == "use safe_delete"

    def test_blocked_no_contingency(self, mgr):
        mgr.submit_preflight("comp", red_lines=["danger*"])
        allowed, alt = mgr.check_violation("comp", "danger_zone", {})
        assert allowed is False
        assert alt is None

    def test_glob_star_matches(self, mgr):
        mgr.submit_preflight("comp", red_lines=["*delete*"])
        allowed, _ = mgr.check_violation("comp", "bulk_delete_rows", {})
        assert allowed is False

    def test_exact_match(self, mgr):
        mgr.submit_preflight("comp", red_lines=["specific_tool"])
        allowed, _ = mgr.check_violation("comp", "specific_tool", {})
        assert allowed is False

    def test_records_violation_on_block(self, mgr):
        mgr.submit_preflight("comp", red_lines=["bad_*"])
        mgr.check_violation("comp", "bad_tool", {"key": "val"})
        violations = mgr.get_violations("comp")
        assert len(violations) == 1
        v = violations[0]
        assert v.tool_name == "bad_tool"
        assert v.matched_red_line == "bad_*"
        assert v.tool_input == {"key": "val"}

    def test_multiple_violations_accumulate(self, mgr):
        mgr.submit_preflight("comp", red_lines=["bad_*"])
        mgr.check_violation("comp", "bad_one", {})
        mgr.check_violation("comp", "bad_two", {})
        assert len(mgr.get_violations("comp")) == 2

    def test_no_violation_on_allow(self, mgr):
        mgr.submit_preflight("comp", red_lines=["bad_*"])
        mgr.check_violation("comp", "good_tool", {})
        assert len(mgr.get_violations("comp")) == 0

    def test_tool_input_defaults_to_empty_dict(self, mgr):
        mgr.submit_preflight("comp", red_lines=["bad"])
        mgr.check_violation("comp", "bad")  # no tool_input arg
        violations = mgr.get_violations("comp")
        assert violations[0].tool_input == {}

    def test_first_matching_red_line_wins(self, mgr):
        mgr.submit_preflight(
            "comp",
            red_lines=["a*", "ab*"],
            contingencies={"a*": "first", "ab*": "second"},
        )
        allowed, alt = mgr.check_violation("comp", "abc", {})
        assert allowed is False
        assert alt == "first"


# ---------------------------------------------------------------------------
# get_violations
# ---------------------------------------------------------------------------
class TestGetViolations:
    def test_empty_when_no_violations(self, mgr):
        assert mgr.get_violations("comp") == []

    def test_persisted_across_instances(self, preflight_dir):
        """Violations written by one manager are readable by another."""
        mgr1 = PreflightManager(base_dir=preflight_dir)
        mgr1.submit_preflight("comp", red_lines=["bad"])
        mgr1.check_violation("comp", "bad", {})

        mgr2 = PreflightManager(base_dir=preflight_dir)
        violations = mgr2.get_violations("comp")
        assert len(violations) == 1
        assert violations[0].tool_name == "bad"

    def test_violations_isolated_by_component(self, mgr):
        mgr.submit_preflight("a", red_lines=["x"])
        mgr.submit_preflight("b", red_lines=["y"])
        mgr.check_violation("a", "x", {})
        mgr.check_violation("b", "y", {})
        assert len(mgr.get_violations("a")) == 1
        assert len(mgr.get_violations("b")) == 1
        assert mgr.get_violations("a")[0].component_id == "a"


# ---------------------------------------------------------------------------
# PreflightPlan / PreflightViolation model properties
# ---------------------------------------------------------------------------
class TestModels:
    def test_plan_is_frozen(self):
        plan = PreflightPlan(
            plan_id="abc",
            component_id="comp",
            red_lines=["x"],
        )
        with pytest.raises(Exception):
            plan.plan_id = "changed"

    def test_violation_is_frozen(self):
        v = PreflightViolation(
            violation_id="abc",
            plan_id="p1",
            component_id="comp",
            tool_name="t",
            matched_red_line="x",
        )
        with pytest.raises(Exception):
            v.violation_id = "changed"

    def test_plan_roundtrip(self):
        plan = PreflightPlan(
            plan_id="abc",
            component_id="comp",
            red_lines=["x", "y"],
            contingencies={"x": "use z"},
            lockout_minutes=10,
            created_at="2025-01-01T00:00:00+00:00",
            expires_at="2025-01-01T00:10:00+00:00",
        )
        data = plan.model_dump()
        restored = PreflightPlan(**data)
        assert restored == plan
