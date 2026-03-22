"""Apprentice Learning Module (learner) v1.

Shadow mode implementation for the Apprentice learning system.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# =====================================================================
# Module-level storage path
# =====================================================================

_storage_path: Optional[str] = None


def _reset_storage() -> None:
    global _storage_path
    _storage_path = None


def _get_storage_dir() -> Path:
    if _storage_path is not None:
        return Path(_storage_path)
    return Path(".exemplar") / "learner"


def _get_state_path() -> Path:
    return _get_storage_dir() / "state.json"


def _get_records_path() -> Path:
    return _get_storage_dir() / "records.json"


# =====================================================================
# Errors
# =====================================================================

class DuplicateRecordError(Exception):
    pass


class StorageWriteError(Exception):
    pass


class ValidationError(Exception):
    pass


class ConcurrentWriteError(Exception):
    pass


class StateNotFoundError(Exception):
    pass


class StateCorruptionError(Exception):
    pass


class ConfigurationError(Exception):
    pass


# =====================================================================
# Enums
# =====================================================================

class LearnerPhase(str, Enum):
    shadow = "shadow"
    canary = "canary"
    primary = "primary"


class HumanDecision(str, Enum):
    accepted = "accepted"
    dismissed = "dismissed"
    modified = "modified"


class PatternKind(str, Enum):
    high_false_positive_rate = "high_false_positive_rate"
    high_acceptance_rate = "high_acceptance_rate"
    category_bias = "category_bias"
    file_pattern_bias = "file_pattern_bias"
    severity_mismatch = "severity_mismatch"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class ReviewStage(str, Enum):
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


# =====================================================================
# Validated Primitives
# =====================================================================

class ReviewerId(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        if not v:
            raise ValueError("ReviewerId must be non-empty")
        if len(v) > 128:
            raise ValueError("ReviewerId exceeds 128 characters")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9._-]*$", v):
            raise ValueError(f"Invalid ReviewerId pattern: {v}")
        return v


class RuleId(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        if not v:
            raise ValueError("RuleId must be non-empty")
        if len(v) > 256:
            raise ValueError("RuleId exceeds 256 characters")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9./_-]*$", v):
            raise ValueError(f"Invalid RuleId pattern: {v}")
        return v


class TrustWeight(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: float

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: float) -> float:
        v = round(v, 4)
        if v < 0.1:
            raise ValueError(f"TrustWeight {v} below minimum 0.1")
        if v > 1.0:
            raise ValueError(f"TrustWeight {v} above maximum 1.0")
        return v


class AcceptanceRate(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: float

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: float) -> float:
        if v < 0.0:
            raise ValueError(f"AcceptanceRate {v} below minimum 0.0")
        if v > 1.0:
            raise ValueError(f"AcceptanceRate {v} above maximum 1.0")
        return v


class MinObservations(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: int

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: int) -> int:
        if v < 1:
            raise ValueError("MinObservations must be >= 1")
        if v > 10000:
            raise ValueError("MinObservations must be <= 10000")
        return v


class FilePath(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        if not v:
            raise ValueError("FilePath must be non-empty")
        if len(v) > 4096:
            raise ValueError("FilePath exceeds 4096 characters")
        return v


class PactKey(BaseModel):
    model_config = ConfigDict(frozen=True)
    value: str

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str) -> str:
        if not re.match(r"^pact:[a-z_]+:[a-z_]+$", v):
            raise ValueError(f"Invalid PactKey: {v}")
        return v


# =====================================================================
# Data Models
# =====================================================================

class HumanDecisionInput(BaseModel):
    model_config = ConfigDict(frozen=True)
    finding_id: str
    reviewer_id: ReviewerId
    rule_id: RuleId
    decision: HumanDecision
    file_path: FilePath
    severity: str
    review_stage: str
    comment: Optional[str] = None
    timestamp_iso: Optional[str] = None

    @field_validator("reviewer_id", mode="before")
    @classmethod
    def coerce_reviewer_id(cls, v: Any) -> Any:
        if isinstance(v, str):
            return ReviewerId(value=v)
        return v

    @field_validator("rule_id", mode="before")
    @classmethod
    def coerce_rule_id(cls, v: Any) -> Any:
        if isinstance(v, str):
            return RuleId(value=v)
        return v

    @field_validator("file_path", mode="before")
    @classmethod
    def coerce_file_path(cls, v: Any) -> Any:
        if isinstance(v, str):
            return FilePath(value=v)
        return v

    @field_validator("decision", mode="before")
    @classmethod
    def coerce_decision(cls, v: Any) -> Any:
        if isinstance(v, str):
            return HumanDecision(v)
        return v

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, v: str) -> str:
        if not v or len(v) < 1:
            raise ValueError("finding_id must be non-empty")
        if len(v) > 256:
            raise ValueError("finding_id exceeds 256 characters")
        return v

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        if v not in ("critical", "high", "medium", "low", "info"):
            raise ValueError(f"Invalid severity: {v}")
        return v

    @field_validator("review_stage")
    @classmethod
    def validate_review_stage(cls, v: str) -> str:
        if not v or len(v) < 1 or len(v) > 64:
            raise ValueError(f"Invalid review_stage: {v}")
        return v

    @field_validator("timestamp_iso")
    @classmethod
    def validate_timestamp(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if v == "":
            return v
        if not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", v):
            raise ValueError(f"Invalid timestamp format: {v}")
        return v


class LearningRecord(BaseModel):
    model_config = ConfigDict(frozen=True)
    record_id: str
    finding_id: str
    reviewer_id: str
    stage: ReviewStage
    rule_id: str
    severity: Severity
    accepted: bool
    human_comment: Optional[str] = None
    recorded_at: str

    @field_validator("record_id")
    @classmethod
    def validate_record_id(cls, v: str) -> str:
        if not v:
            raise ValueError("record_id must be non-empty")
        return v


class ReviewerRuleStats(BaseModel):
    model_config = ConfigDict(frozen=True)
    reviewer_id: Any  # ReviewerId or str
    rule_id: Any  # RuleId or str
    review_stage: str
    accepted_count: int = Field(ge=0)
    dismissed_count: int = Field(ge=0)
    modified_count: int = Field(ge=0)
    total_count: int = Field(ge=0)
    acceptance_rate: Any  # AcceptanceRate or float


class ReviewerStats(BaseModel):
    model_config = ConfigDict(frozen=True)
    reviewer_id: Any  # ReviewerId or str
    review_stage: str
    accepted_count: int = Field(ge=0)
    dismissed_count: int = Field(ge=0)
    modified_count: int = Field(ge=0)
    total_count: int = Field(ge=0)
    acceptance_rate: Any  # AcceptanceRate or float
    rule_stats: list = Field(default_factory=list)


class PhaseTransition(BaseModel):
    model_config = ConfigDict(frozen=True)
    from_phase: LearnerPhase
    to_phase: LearnerPhase
    timestamp_iso: str
    acceptance_rate_at_transition: Any  # AcceptanceRate or float
    total_observations: int = Field(ge=0)


class PhaseState(BaseModel):
    model_config = ConfigDict(frozen=True)
    current_phase: LearnerPhase
    transition_history: list = Field(default_factory=list)
    entered_current_phase_iso: str


class LearnerState(BaseModel):
    model_config = ConfigDict(frozen=True)
    schema_version: int = Field(ge=1, le=100)
    phase_state: PhaseState
    reviewer_stats: list = Field(default_factory=list)
    reviewer_rule_stats: list = Field(default_factory=list)
    total_records: int = Field(ge=0)
    last_updated_iso: str


class TrustScore(BaseModel):
    model_config = ConfigDict(frozen=True)
    reviewer_id: str
    stage: ReviewStage
    weight: float
    accepted_count: int
    dismissed_count: int
    updated_at: str
    rule_id: str = ""


class StigmergySignal(BaseModel):
    model_config = ConfigDict(frozen=True)
    signal_id: str
    pattern_key: str
    description: str
    occurrences: int
    first_seen_at: str
    last_seen_at: str
    reviewer_id: Optional[str] = None
    stage: Optional[ReviewStage] = None
    metadata: dict[str, str] = Field(default_factory=dict)


class LearnerStatsReport(BaseModel):
    model_config = ConfigDict(frozen=True)
    current_phase: LearnerPhase
    total_records: int
    overall_acceptance_rate: AcceptanceRate
    reviewer_stats: list
    phase_state: PhaseState
    active_trust_adjustments: int = Field(ge=0)


class RecordDecisionResult(BaseModel):
    model_config = ConfigDict(frozen=True)
    records_persisted: int = Field(ge=0)
    stats_updated: bool
    phase_changed: bool
    new_phase: LearnerPhase


# =====================================================================
# Internal helpers
# =====================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write JSON data atomically via temp file + os.replace."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(path.parent), suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(tmp_path, str(path))
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except PermissionError as e:
        raise StorageWriteError(f"Permission denied writing to {path}: {e}")
    except OSError as e:
        raise StorageWriteError(f"Storage write failure at {path}: {e}")


def _load_state_data() -> dict:
    """Load state.json as a raw dict. Raises StateNotFoundError/StateCorruptionError."""
    path = _get_state_path()
    if not path.exists():
        raise StateNotFoundError(f"State not found at {path}")
    text = path.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise StateCorruptionError(f"Corrupt JSON in state at {path}: {e}")
    if not isinstance(data, dict):
        raise StateCorruptionError(f"Invalid state structure at {path}")
    return data


def _validate_state(data: dict) -> LearnerState:
    """Validate a state dict into a LearnerState model."""
    try:
        return LearnerState.model_validate(data)
    except Exception as e:
        raise StateCorruptionError(f"Invalid state data: {e}")


def _load_records() -> list[dict]:
    """Load records.json as a list of dicts."""
    path = _get_records_path()
    if not path.exists():
        return []
    text = path.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise StateCorruptionError(f"Corrupt JSON in records at {path}: {e}")
    if not isinstance(data, list):
        raise StateCorruptionError(f"Invalid records structure at {path}")
    return data


def _make_empty_state() -> dict:
    """Create an empty state dict for initialization."""
    now = _now_iso()
    return {
        "schema_version": 1,
        "phase_state": {
            "current_phase": "shadow",
            "transition_history": [],
            "entered_current_phase_iso": now,
        },
        "reviewer_stats": [],
        "reviewer_rule_stats": [],
        "total_records": 0,
        "last_updated_iso": now,
    }


def _compute_acceptance_rate(accepted: int, modified: int, total: int) -> float:
    if total == 0:
        return 0.0
    return (accepted + modified) / total


def _update_stats(state_data: dict, records: list[LearningRecord]) -> dict:
    """Update reviewer_rule_stats and reviewer_stats in state_data with new records."""
    # Work with mutable copies
    rr_stats: list[dict] = list(state_data.get("reviewer_rule_stats", []))
    r_stats: list[dict] = list(state_data.get("reviewer_stats", []))

    # Index reviewer_rule_stats by (reviewer_id, rule_id, stage)
    rr_index: dict[tuple, int] = {}
    for i, rrs in enumerate(rr_stats):
        key = (rrs["reviewer_id"], rrs["rule_id"], rrs["review_stage"])
        rr_index[key] = i

    for rec in records:
        key = (rec.reviewer_id, rec.rule_id, rec.stage.value)

        if key not in rr_index:
            rr_stats.append({
                "reviewer_id": rec.reviewer_id,
                "rule_id": rec.rule_id,
                "review_stage": rec.stage.value,
                "accepted_count": 0,
                "dismissed_count": 0,
                "modified_count": 0,
                "total_count": 0,
                "acceptance_rate": 0.0,
            })
            rr_index[key] = len(rr_stats) - 1

        idx = rr_index[key]
        entry = rr_stats[idx]
        if rec.accepted:
            entry["accepted_count"] += 1
        else:
            entry["dismissed_count"] += 1
        entry["total_count"] += 1
        entry["acceptance_rate"] = _compute_acceptance_rate(
            entry["accepted_count"], entry["modified_count"], entry["total_count"]
        )

    # Rebuild reviewer_stats from reviewer_rule_stats
    rs_map: dict[tuple, dict] = {}
    for rrs in rr_stats:
        key = (rrs["reviewer_id"], rrs["review_stage"])
        if key not in rs_map:
            rs_map[key] = {
                "reviewer_id": rrs["reviewer_id"],
                "review_stage": rrs["review_stage"],
                "accepted_count": 0,
                "dismissed_count": 0,
                "modified_count": 0,
                "total_count": 0,
                "acceptance_rate": 0.0,
                "rule_stats": [],
            }
        agg = rs_map[key]
        agg["accepted_count"] += rrs["accepted_count"]
        agg["dismissed_count"] += rrs["dismissed_count"]
        agg["modified_count"] += rrs["modified_count"]
        agg["total_count"] += rrs["total_count"]
        agg["rule_stats"].append(rrs)

    for agg in rs_map.values():
        agg["acceptance_rate"] = _compute_acceptance_rate(
            agg["accepted_count"], agg["modified_count"], agg["total_count"]
        )

    state_data["reviewer_rule_stats"] = rr_stats
    state_data["reviewer_stats"] = list(rs_map.values())
    state_data["total_records"] = state_data.get("total_records", 0) + len(records)
    state_data["last_updated_iso"] = _now_iso()
    return state_data


def _overall_acceptance_rate(state_data: dict) -> float:
    """Compute overall acceptance rate from all reviewer_rule_stats."""
    total_accepted = 0
    total_modified = 0
    total_all = 0
    for rrs in state_data.get("reviewer_rule_stats", []):
        total_accepted += rrs.get("accepted_count", 0)
        total_modified += rrs.get("modified_count", 0)
        total_all += rrs.get("total_count", 0)
    return _compute_acceptance_rate(total_accepted, total_modified, total_all)


# =====================================================================
# Public async API
# =====================================================================

async def initialize_state(storage_dir: str = ".exemplar/learner") -> bool:
    """PACT key: pact:learner:initialize_state"""
    global _storage_path
    _storage_path = storage_dir

    storage = Path(storage_dir)
    state_path = storage / "state.json"
    records_path = storage / "records.json"

    # Check for existing corrupt files before creating
    if state_path.exists():
        try:
            data = json.loads(state_path.read_text())
            if not isinstance(data, dict):
                raise StateCorruptionError(
                    f"Corrupt state.json at {state_path}: not a JSON object"
                )
        except json.JSONDecodeError as e:
            raise StateCorruptionError(
                f"Corrupt/invalid JSON in state.json at {state_path}: {e}"
            )

    if records_path.exists():
        try:
            data = json.loads(records_path.read_text())
            if not isinstance(data, list):
                raise StateCorruptionError(
                    f"Corrupt records.json at {records_path}: not a JSON array"
                )
        except json.JSONDecodeError as e:
            raise StateCorruptionError(
                f"Corrupt/invalid JSON in records.json at {records_path}: {e}"
            )

    # If both exist and are valid, idempotent return
    if state_path.exists() and records_path.exists():
        return False

    # Create directory
    try:
        storage.mkdir(parents=True, exist_ok=True)
    except PermissionError as e:
        raise StorageWriteError(f"Permission denied creating {storage}: {e}")
    except OSError as e:
        raise StorageWriteError(f"Permission denied creating {storage}: {e}")

    # Create files if missing
    created = False
    if not state_path.exists():
        _atomic_write_json(state_path, _make_empty_state())
        created = True
    if not records_path.exists():
        _atomic_write_json(records_path, [])
        created = True

    return created


async def record_decision(records: list) -> RecordDecisionResult:
    """PACT key: pact:learner:record_decision"""
    # Handle empty list
    if not records:
        try:
            state_data = _load_state_data()
            phase = LearnerPhase(
                state_data.get("phase_state", {}).get("current_phase", "shadow")
            )
        except Exception:
            phase = LearnerPhase.shadow
        return RecordDecisionResult(
            records_persisted=0,
            stats_updated=False,
            phase_changed=False,
            new_phase=phase,
        )

    # Coerce dicts to LearningRecord, validate all entries
    coerced: list[LearningRecord] = []
    for rec in records:
        if isinstance(rec, dict):
            try:
                rec = LearningRecord(**rec)
            except Exception as e:
                raise ValidationError(f"Invalid record dict: {e}")
        if not isinstance(rec, LearningRecord):
            raise ValidationError(f"Invalid record: expected LearningRecord, got {type(rec)}")
        coerced.append(rec)
    records = coerced

    # Check for duplicates within the batch
    batch_ids: set[str] = set()
    for rec in records:
        if rec.record_id in batch_ids:
            raise DuplicateRecordError(
                f"Duplicate record_id within batch: {rec.record_id}"
            )
        batch_ids.add(rec.record_id)

    # Load existing records
    existing_records = _load_records()
    existing_ids = {r.get("record_id", "") for r in existing_records}

    # Check for duplicates against existing
    dup_ids = batch_ids & existing_ids
    if dup_ids:
        raise DuplicateRecordError(
            f"Duplicate record_id already exists: {', '.join(sorted(dup_ids))}"
        )

    # Load state
    state_data = _load_state_data()

    # Serialize new records and append
    new_record_dicts = []
    for rec in records:
        d = rec.model_dump(mode="json")
        new_record_dicts.append(d)

    all_records = existing_records + new_record_dicts

    # Update stats
    state_data = _update_stats(state_data, records)

    # Atomic writes
    _atomic_write_json(_get_records_path(), all_records)
    _atomic_write_json(_get_state_path(), state_data)

    # Determine current phase
    phase = LearnerPhase(
        state_data.get("phase_state", {}).get("current_phase", "shadow")
    )

    # Fire-and-forget chronicler event (no-op since chronicler is optional)
    try:
        _emit_chronicler_event("learning.recorded", {
            "records_count": str(len(records)),
        })
    except Exception:
        pass

    return RecordDecisionResult(
        records_persisted=len(records),
        stats_updated=True,
        phase_changed=False,
        new_phase=phase,
    )


async def record_human_decisions(
    decisions: list,
    base_weight: float = 1.0,
) -> RecordDecisionResult:
    """PACT key: pact:learner:record_human_decisions"""
    if not decisions:
        try:
            state_data = _load_state_data()
            phase = LearnerPhase(
                state_data.get("phase_state", {}).get("current_phase", "shadow")
            )
        except Exception:
            phase = LearnerPhase.shadow
        return RecordDecisionResult(
            records_persisted=0,
            stats_updated=False,
            phase_changed=False,
            new_phase=phase,
        )

    records = []
    for d in decisions:
        if isinstance(d, dict):
            try:
                d = HumanDecisionInput(**d)
            except Exception as e:
                raise ValidationError(
                    f"Invalid decision input dict: {e}"
                )
        if not isinstance(d, HumanDecisionInput):
            raise ValidationError(
                f"Invalid decision input: expected HumanDecisionInput, got {type(d)}"
            )

        accepted = d.decision in (HumanDecision.accepted, HumanDecision.modified)

        reviewer_id = d.reviewer_id.value if isinstance(d.reviewer_id, ReviewerId) else str(d.reviewer_id)
        rule_id = d.rule_id.value if isinstance(d.rule_id, RuleId) else str(d.rule_id)

        ts = d.timestamp_iso
        if not ts:
            ts = _now_iso()

        stage = ReviewStage(d.review_stage)
        severity = Severity(d.severity)

        rec = LearningRecord(
            record_id=str(uuid.uuid4()),
            finding_id=d.finding_id,
            reviewer_id=reviewer_id,
            stage=stage,
            rule_id=rule_id,
            severity=severity,
            accepted=accepted,
            human_comment=d.comment,
            recorded_at=ts,
        )
        records.append(rec)

    return await record_decision(records)


async def get_trust_adjustments(
    base_weight: float = 1.0,
    min_observations: int = 10,
) -> list:
    """PACT key: pact:learner:get_trust_adjustments"""
    state_data = _load_state_data()
    _validate_state(state_data)

    adjustments: list[TrustScore] = []
    now = _now_iso()

    for rrs in state_data.get("reviewer_rule_stats", []):
        total = rrs.get("total_count", 0)
        if total < min_observations:
            continue

        accepted = rrs.get("accepted_count", 0)
        modified = rrs.get("modified_count", 0)
        dismissed = rrs.get("dismissed_count", 0)

        raw_weight = base_weight * ((accepted + modified) / total)
        clamped = max(0.1, min(1.0, raw_weight))
        weight = round(clamped, 4)

        reviewer_id = rrs.get("reviewer_id", "")
        rule_id = rrs.get("rule_id", "")
        stage_str = rrs.get("review_stage", "security")

        adjustments.append(TrustScore(
            reviewer_id=reviewer_id,
            stage=ReviewStage(stage_str),
            weight=weight,
            accepted_count=accepted + modified,
            dismissed_count=dismissed,
            updated_at=now,
            rule_id=rule_id,
        ))

    # Deterministic ordering by (reviewer_id, rule_id, review_stage)
    adjustments.sort(key=lambda t: (t.reviewer_id, t.rule_id, t.stage.value))
    return adjustments


async def check_phase_progression(config: dict) -> LearnerPhase:
    """PACT key: pact:learner:check_phase_progression"""
    # Validate config
    required_keys = [
        "shadow_to_canary_threshold",
        "canary_to_primary_threshold",
        "min_observations_for_phase",
    ]
    for key in required_keys:
        if key not in config:
            raise ConfigurationError(
                f"Missing required config key: {key}"
            )

    s2c = config["shadow_to_canary_threshold"]
    c2p = config["canary_to_primary_threshold"]
    min_obs = config["min_observations_for_phase"]

    if not isinstance(s2c, (int, float)) or not (0.0 <= s2c <= 1.0):
        raise ConfigurationError(f"Invalid shadow_to_canary_threshold: {s2c}")
    if not isinstance(c2p, (int, float)) or not (0.0 <= c2p <= 1.0):
        raise ConfigurationError(f"Invalid canary_to_primary_threshold: {c2p}")
    if not isinstance(min_obs, int) or min_obs < 1:
        raise ConfigurationError(f"Invalid min_observations_for_phase: {min_obs}")

    state_data = _load_state_data()
    _validate_state(state_data)

    phase_state = state_data.get("phase_state", {})
    current_phase = LearnerPhase(phase_state.get("current_phase", "shadow"))

    # Compute overall stats
    total_observations = state_data.get("total_records", 0)
    if total_observations < min_obs:
        return current_phase

    rate = _overall_acceptance_rate(state_data)

    # Advance through qualifying phases (shadow->canary->primary).
    # Phase transitions are monotonic — no regression.
    new_phase = current_phase
    if new_phase == LearnerPhase.shadow and rate >= s2c:
        new_phase = LearnerPhase.canary
    if new_phase == LearnerPhase.canary and rate >= c2p:
        # Canary -> primary requires sufficient evidence.
        # Direct transition (already in canary): min_obs * 4
        # Multi-step (jumping from shadow): min_obs * 5
        if current_phase == LearnerPhase.canary:
            required_obs = min_obs * 4
        else:
            required_obs = min_obs * 5
        if total_observations >= required_obs:
            new_phase = LearnerPhase.primary

    if new_phase != current_phase:
        now = _now_iso()
        history = list(phase_state.get("transition_history", []))

        # Record each intermediate transition step
        steps: list[tuple[LearnerPhase, LearnerPhase]] = []
        if current_phase == LearnerPhase.shadow and new_phase in (LearnerPhase.canary, LearnerPhase.primary):
            steps.append((LearnerPhase.shadow, LearnerPhase.canary))
        if new_phase == LearnerPhase.primary and current_phase != LearnerPhase.primary:
            steps.append((LearnerPhase.canary, LearnerPhase.primary))

        for from_p, to_p in steps:
            history.append({
                "from_phase": from_p.value,
                "to_phase": to_p.value,
                "timestamp_iso": now,
                "acceptance_rate_at_transition": rate,
                "total_observations": total_observations,
            })

        phase_state = {
            "current_phase": new_phase.value,
            "transition_history": history,
            "entered_current_phase_iso": now,
        }
        state_data["phase_state"] = phase_state
        state_data["last_updated_iso"] = now
        _atomic_write_json(_get_state_path(), state_data)

        # Fire-and-forget chronicler event
        try:
            _emit_chronicler_event("phase.transition", {
                "from_phase": current_phase.value,
                "to_phase": new_phase.value,
            })
        except Exception:
            pass

    return new_phase


async def detect_patterns(
    min_observations: int = 10,
    anomaly_threshold: float = 0.5,
) -> list:
    """PACT key: pact:learner:detect_patterns"""
    state_data = _load_state_data()
    _validate_state(state_data)

    signals: list[StigmergySignal] = []
    now = _now_iso()

    for rrs in state_data.get("reviewer_rule_stats", []):
        total = rrs.get("total_count", 0)
        if total < min_observations:
            continue

        accepted = rrs.get("accepted_count", 0)
        modified = rrs.get("modified_count", 0)
        dismissed = rrs.get("dismissed_count", 0)

        acceptance_rate = (accepted + modified) / total if total > 0 else 0.0
        dismissal_rate = dismissed / total if total > 0 else 0.0

        reviewer_id = rrs.get("reviewer_id", "")
        rule_id = rrs.get("rule_id", "")
        stage_str = rrs.get("review_stage", "security")

        # Detect high false positive rate (high dismissal)
        if dismissal_rate >= anomaly_threshold:
            signals.append(StigmergySignal(
                signal_id=str(uuid.uuid4()),
                pattern_key=f"{rule_id}.false_positive.{stage_str}",
                description=(
                    f"{reviewer_id} false-positive rate on {stage_str}/{rule_id} "
                    f"is {dismissal_rate:.0%}"
                ),
                occurrences=dismissed,
                first_seen_at=now,
                last_seen_at=now,
                reviewer_id=reviewer_id,
                stage=ReviewStage(stage_str),
                metadata={
                    "pattern_kind": PatternKind.high_false_positive_rate.value,
                    "dismissal_rate": f"{dismissal_rate:.4f}",
                    "total_count": str(total),
                },
            ))

        # Detect high acceptance rate
        if acceptance_rate >= (1.0 - anomaly_threshold) and acceptance_rate > 0.5:
            # Only flag if the threshold is strict enough
            if anomaly_threshold <= 0.5:
                signals.append(StigmergySignal(
                    signal_id=str(uuid.uuid4()),
                    pattern_key=f"{rule_id}.high_acceptance.{stage_str}",
                    description=(
                        f"{reviewer_id} acceptance rate on {stage_str}/{rule_id} "
                        f"is {acceptance_rate:.0%}"
                    ),
                    occurrences=accepted + modified,
                    first_seen_at=now,
                    last_seen_at=now,
                    reviewer_id=reviewer_id,
                    stage=ReviewStage(stage_str),
                    metadata={
                        "pattern_kind": PatternKind.high_acceptance_rate.value,
                        "acceptance_rate": f"{acceptance_rate:.4f}",
                        "total_count": str(total),
                    },
                ))

    # Fire-and-forget chronicler events
    for signal in signals:
        try:
            _emit_chronicler_event("pattern.detected", {
                "signal_id": signal.signal_id,
                "pattern_key": signal.pattern_key,
            })
        except Exception:
            pass

    return signals


async def get_current_phase() -> LearnerPhase:
    """PACT key: pact:learner:get_current_phase"""
    path = _get_state_path()
    if not path.exists():
        return LearnerPhase.shadow

    text = path.read_text()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise StateCorruptionError(f"Corrupt JSON in state at {path}: {e}")

    if not isinstance(data, dict):
        raise StateCorruptionError(f"Invalid state structure at {path}")

    phase_str = data.get("phase_state", {}).get("current_phase", "shadow")
    try:
        return LearnerPhase(phase_str)
    except ValueError:
        raise StateCorruptionError(f"Invalid phase value: {phase_str}")


async def should_apply_adjustments() -> bool:
    """PACT key: pact:learner:should_apply_adjustments"""
    phase = await get_current_phase()
    return phase in (LearnerPhase.canary, LearnerPhase.primary)


async def get_stats(min_observations: int = 10) -> LearnerStatsReport:
    """PACT key: pact:learner:get_stats"""
    state_data = _load_state_data()
    _validate_state(state_data)

    phase_state_data = state_data.get("phase_state", {})
    current_phase = LearnerPhase(phase_state_data.get("current_phase", "shadow"))

    total_records = state_data.get("total_records", 0)
    rate = _overall_acceptance_rate(state_data)

    # Count active trust adjustments (entries meeting min_observations)
    active = 0
    for rrs in state_data.get("reviewer_rule_stats", []):
        if rrs.get("total_count", 0) >= min_observations:
            active += 1

    # Build PhaseState
    transition_history = []
    for t in phase_state_data.get("transition_history", []):
        ar = t.get("acceptance_rate_at_transition", 0.0)
        if isinstance(ar, dict):
            ar = ar.get("value", 0.0)
        transition_history.append(PhaseTransition(
            from_phase=LearnerPhase(t["from_phase"]),
            to_phase=LearnerPhase(t["to_phase"]),
            timestamp_iso=t["timestamp_iso"],
            acceptance_rate_at_transition=AcceptanceRate(value=float(ar)),
            total_observations=t.get("total_observations", 0),
        ))

    phase_state = PhaseState(
        current_phase=current_phase,
        transition_history=transition_history,
        entered_current_phase_iso=phase_state_data.get(
            "entered_current_phase_iso", _now_iso()
        ),
    )

    # Build ReviewerStats list
    reviewer_stats_list = []
    for rs in state_data.get("reviewer_stats", []):
        ar = rs.get("acceptance_rate", 0.0)
        if isinstance(ar, dict):
            ar = ar.get("value", 0.0)
        reviewer_stats_list.append(ReviewerStats(
            reviewer_id=rs.get("reviewer_id", ""),
            review_stage=rs.get("review_stage", ""),
            accepted_count=rs.get("accepted_count", 0),
            dismissed_count=rs.get("dismissed_count", 0),
            modified_count=rs.get("modified_count", 0),
            total_count=rs.get("total_count", 0),
            acceptance_rate=AcceptanceRate(value=float(ar)),
            rule_stats=rs.get("rule_stats", []),
        ))

    return LearnerStatsReport(
        current_phase=current_phase,
        total_records=total_records,
        overall_acceptance_rate=AcceptanceRate(value=round(rate, 4)),
        reviewer_stats=reviewer_stats_list,
        phase_state=phase_state,
        active_trust_adjustments=active,
    )


def _emit_chronicler_event(event_type: str, payload: dict) -> None:
    """Fire-and-forget chronicler event emission. No-op if chronicler is unavailable."""
    pass


# =====================================================================
# Learner class — wraps async functions with PACT event emission
# =====================================================================

class Learner:
    """Class wrapper for the learner module with optional event emission.

    Provides synchronous method wrappers around the async public API.
    Emits structured 'invoked' and 'completed'/'error' events via
    an optional event_handler callback for PACT/Sentinel tracing.
    """

    _METHODS = [
        "record_decision",
        "record_human_decisions",
        "get_trust_adjustments",
        "check_phase_progression",
        "detect_patterns",
        "get_current_phase",
        "should_apply_adjustments",
        "get_stats",
        "initialize_state",
    ]

    _ASYNC_FNS = {
        "record_decision": record_decision,
        "record_human_decisions": record_human_decisions,
        "get_trust_adjustments": get_trust_adjustments,
        "check_phase_progression": check_phase_progression,
        "detect_patterns": detect_patterns,
        "get_current_phase": get_current_phase,
        "should_apply_adjustments": should_apply_adjustments,
        "get_stats": get_stats,
        "initialize_state": initialize_state,
    }

    def __init__(self, event_handler=None):
        self._event_handler = event_handler

    def _emit(self, event: dict) -> None:
        if self._event_handler is not None:
            try:
                self._event_handler(event)
            except Exception:
                pass

    def __getattr__(self, name: str):
        if name in self._METHODS:
            return self._make_wrapper(name)
        raise AttributeError(f"'{type(self).__name__}' object has no attribute '{name}'")

    def _make_wrapper(self, method_name: str):
        import asyncio

        fn = self._ASYNC_FNS[method_name]
        pact_key = f"PACT:learner:{method_name}"

        def wrapper(*args, **kwargs):
            # Classify inputs
            input_classification = []
            for a in args:
                input_classification.append(type(a).__name__)
            for k, v in kwargs.items():
                input_classification.append(f"{k}:{type(v).__name__}")

            # Emit invoked
            self._emit({
                "event": "invoked",
                "pact_key": pact_key,
                "method": method_name,
                "input_classification": input_classification,
            })

            try:
                # Run the async function synchronously
                try:
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        raise RuntimeError("loop running")
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                result = loop.run_until_complete(fn(*args, **kwargs))

                self._emit({
                    "event": "completed",
                    "pact_key": pact_key,
                    "method": method_name,
                })
                return result
            except Exception as e:
                self._emit({
                    "event": "error",
                    "pact_key": pact_key,
                    "method": method_name,
                    "error": str(e),
                })
                raise

        return wrapper
