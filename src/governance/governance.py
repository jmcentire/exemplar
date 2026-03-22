"""Governance Primitives — inline implementations of governance stack patterns.

Includes: TesseraSealer, ChronicleEmitter, AgentSafeEnforcer, SignetManager,
ArbiterScorer, LedgerClassifier, StigmergyTracker, KindexStore.

Each is a focused class with a clean Protocol-based interface.
Sync methods for pure computation, async for file I/O.
Canonical JSON via json.dumps(data, sort_keys=True, separators=(',',':'))
for deterministic hashing. Atomic file writes (write-to-temp + os.replace)
for JSON stores. PACT keys as class-level constants included in
ChroniclerEvent payloads.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from fnmatch import fnmatch
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Canonical JSON helper
# ---------------------------------------------------------------------------
def _canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid4_hex() -> str:
    return uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class CredentialErrorReason(Enum):
    EXPIRED = "EXPIRED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    UNKNOWN_REVIEWER = "UNKNOWN_REVIEWER"
    STAGE_MISMATCH = "STAGE_MISMATCH"
    MALFORMED = "MALFORMED"


class ReviewStage(Enum):
    security = "security"
    correctness = "correctness"
    style = "style"
    architecture = "architecture"


# ChroniclerEventType with dotted names -- use functional Enum to support
# non-identifier member names. Then wrap in a proxy for underscore access.
_CET_BASE = Enum(
    "ChroniclerEventType",
    {
        "review.started": "review.started",
        "stage.started": "stage.started",
        "stage.complete": "stage.complete",
        "assessment.merged": "assessment.merged",
        "report.sealed": "report.sealed",
        "review.complete": "review.complete",
        "policy.violation": "policy.violation",
        "pattern.detected": "pattern.detected",
        "learning.recorded": "learning.recorded",
    },
)

_CET_ALIASES = {
    "review_started": "review.started",
    "stage_started": "stage.started",
    "stage_complete": "stage.complete",
    "assessment_merged": "assessment.merged",
    "report_sealed": "report.sealed",
    "review_complete": "review.complete",
    "policy_violation": "policy.violation",
    "pattern_detected": "pattern.detected",
    "learning_recorded": "learning.recorded",
}


class _ChroniclerEventTypeProxy:
    """Proxy supporting both ["review.started"] and .review_started access."""

    def __init__(self, enum_cls, aliases):
        object.__setattr__(self, "_enum_cls", enum_cls)
        object.__setattr__(self, "_aliases", aliases)

    def __getattr__(self, name):
        aliases = object.__getattribute__(self, "_aliases")
        enum_cls = object.__getattribute__(self, "_enum_cls")
        if name in aliases:
            return enum_cls[aliases[name]]
        return getattr(enum_cls, name)

    def __getitem__(self, key):
        return object.__getattribute__(self, "_enum_cls")[key]

    def __iter__(self):
        return iter(object.__getattribute__(self, "_enum_cls"))

    def __call__(self, value):
        return object.__getattribute__(self, "_enum_cls")(value)

    def __repr__(self):
        return repr(object.__getattribute__(self, "_enum_cls"))


ChroniclerEventType = _ChroniclerEventTypeProxy(_CET_BASE, _CET_ALIASES)


class ReviewDecision(Enum):
    block = "block"
    warn = "warn"
    pass_ = "pass"  # 'pass' is a keyword; use pass_ as attr name, "pass" as value

    # Allow accessing by value "pass"
    @classmethod
    def _missing_(cls, value: object):
        for member in cls:
            if member.value == value:
                return member
        return None


class ClassificationLabel(Enum):
    secret = "secret"
    pii = "pii"
    internal_api = "internal_api"
    public = "public"


class Confidence(Enum):
    high = "high"
    medium = "medium"
    low = "low"


class Severity(Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class LearningOutcome(Enum):
    CORRECT_ACCEPT = "CORRECT_ACCEPT"
    CORRECT_REJECT = "CORRECT_REJECT"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    PARTIAL_MATCH = "PARTIAL_MATCH"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class GovernanceError(Exception):
    """Base exception for all governance primitive errors."""

    def __init__(self, message: str = "", context: Optional[Dict] = None):
        self.message = message
        self.context = context or {}
        super().__init__(message)


class SealVerificationError(GovernanceError):
    """Raised when a TesseraSeal fails verification."""

    def __init__(
        self,
        message: str = "",
        seal_id: str = "",
        expected_hash: str = "",
        actual_hash: str = "",
        **kwargs: Any,
    ):
        self.seal_id = seal_id
        self.expected_hash = expected_hash
        self.actual_hash = actual_hash
        super().__init__(message=message, context=kwargs.get("context"))


class PolicyViolationError(GovernanceError):
    """Raised when a PolicyToken scope check fails."""

    def __init__(
        self,
        message: str = "",
        token_id: str = "",
        violated_scopes: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        self.token_id = token_id
        self.violated_scopes = violated_scopes or []
        super().__init__(message=message, context=kwargs.get("context"))


class CredentialError(GovernanceError):
    """Raised when a ReviewerCredential fails verification."""

    def __init__(
        self,
        message: str = "",
        credential_id: str = "",
        reason: Optional[CredentialErrorReason] = None,
        **kwargs: Any,
    ):
        self.credential_id = credential_id
        self.reason = reason
        super().__init__(message=message, context=kwargs.get("context"))


# ---------------------------------------------------------------------------
# Pydantic frozen models
# ---------------------------------------------------------------------------
class TesseraSeal(BaseModel):
    model_config = {"frozen": True}

    content_hash: str
    previous_hash: Optional[str] = None
    chain_hash: str
    sealed_at: str
    sealer_id: str
    sequence_number: int = 0


class ChroniclerEvent(BaseModel):
    model_config = {"frozen": True}

    event_id: str
    event_type: Any  # ChroniclerEventType (functional Enum)
    review_request_id: str
    timestamp: str
    stage: Optional[Any] = None  # ReviewStage
    reviewer_id: Optional[str] = None
    payload: Dict[str, Any] = {}
    message: str = ""


class DiffHunk(BaseModel):
    model_config = {"frozen": True}

    id: str
    file_path: str
    start_line_old: int
    count_old: int
    start_line_new: int
    count_new: int
    context_before: List[str] = []
    added_lines: List[str] = []
    removed_lines: List[str] = []
    context_after: List[str] = []
    raw_header: str = ""
    classifications: List[ClassificationLabel] = []
    language: Optional[str] = None


class PolicyToken(BaseModel):
    model_config = {"frozen": True}

    token_id: str
    reviewer_id: str
    allowed_file_patterns: List[str] = ["**/*"]
    denied_file_patterns: List[str] = []
    allowed_classifications: List[ClassificationLabel] = [ClassificationLabel.public]
    max_severity: Severity = Severity.critical
    issued_at: str = ""
    expires_at: Optional[str] = None


class ReviewerCredential(BaseModel):
    model_config = {"frozen": True}

    reviewer_id: str
    display_name: str
    stage: Any  # ReviewStage
    public_key_hex: str = ""
    created_at: str = ""
    is_active: bool = True
    # Fields for class-based API
    credential_id: str = ""
    signature_hash: str = ""
    expires_iso: Optional[str] = None


class Assessment(BaseModel):
    model_config = {"frozen": True}

    id: str
    review_request_id: str
    stage: Any  # ReviewStage
    reviewer_id: str
    decision: Any  # ReviewDecision
    findings: List[Any] = []  # List[Finding]
    confidence: Any  # Confidence
    is_partial: bool = False
    error_message: Optional[str] = None
    duration_ms: int = 0
    created_at: str = ""


class Finding(BaseModel):
    model_config = {"frozen": True}

    id: str
    hunk_id: str
    file_path: str
    line_number: Optional[int] = None
    severity: Any  # Severity
    confidence: Any  # Confidence
    title: str
    description: str
    suggestion: Optional[str] = None
    rule_id: str
    stage: Any  # ReviewStage


class TrustScore(BaseModel):
    model_config = {"frozen": True}

    reviewer_id: str
    stage: Any  # ReviewStage
    weight: float
    accepted_count: int = 0
    dismissed_count: int = 0
    updated_at: str = ""

    @field_validator("weight")
    @classmethod
    def _validate_weight(cls, v: float) -> float:
        if v < 0.0 or v > 1.0:
            raise ValueError("Trust weight must be between 0.0 and 1.0")
        return v


class LearningRecord(BaseModel):
    model_config = {"frozen": True}

    record_id: str
    finding_id: str
    reviewer_id: str
    stage: Any  # ReviewStage
    rule_id: str
    severity: Any  # Severity
    accepted: bool
    human_comment: Optional[str] = None
    recorded_at: str = ""


class LedgerFieldRule(BaseModel):
    model_config = {"frozen": True}

    pattern: str
    label: ClassificationLabel
    description: str = ""


class LedgerConfig(BaseModel):
    model_config = {"frozen": True}

    rules: List[LedgerFieldRule]
    default_label: ClassificationLabel = ClassificationLabel.public


class StigmergySignal(BaseModel):
    model_config = {"frozen": True}

    signal_id: str
    pattern_key: str
    description: str
    occurrences: int = 1
    first_seen_at: str = ""
    last_seen_at: str = ""
    reviewer_id: Optional[str] = None
    stage: Optional[Any] = None  # ReviewStage
    metadata: Dict[str, Any] = {}


class KindexEntry(BaseModel):
    model_config = {"frozen": True}

    key: str
    kind: str
    summary: str
    data: Dict[str, Any] = {}
    tags: List[str] = []
    created_at: str = ""
    updated_at: str = ""


class CircuitConfig(BaseModel):
    model_config = {"frozen": True}

    stages: List[Any] = []  # List[ReviewStage]
    parallel_stages: List[List[Any]] = []  # List[List[ReviewStage]]
    stage_timeout_ms: int = 30000
    block_threshold: int = 1
    warn_threshold: int = 3

    @field_validator("stage_timeout_ms")
    @classmethod
    def _validate_timeout(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("Stage timeout must be positive.")
        return v


class FilterResult(BaseModel):
    model_config = {"frozen": True}

    allowed_hunks: List[DiffHunk] = []
    denied_hunk_ids: List[str] = []
    violations: List[str] = []


class PreflightPlan(BaseModel):
    """A preflight plan declaring red lines and contingencies for a component."""

    model_config = {"frozen": True}

    plan_id: str
    component_id: str
    red_lines: List[str]
    contingencies: Dict[str, str] = {}
    lockout_minutes: int = 30
    created_at: str = ""
    expires_at: str = ""


class PreflightViolation(BaseModel):
    """A recorded violation against an active preflight plan."""

    model_config = {"frozen": True}

    violation_id: str
    plan_id: str
    component_id: str
    tool_name: str
    tool_input: Dict[str, Any] = {}
    matched_red_line: str
    alternative: Optional[str] = None
    recorded_at: str = ""


# ---------------------------------------------------------------------------
# PACT keys (class-level constants)
# ---------------------------------------------------------------------------
PACT_KEY_TESSERA = "governance.tessera"
PACT_KEY_CHRONICLE = "governance.chronicle"
PACT_KEY_AGENTSAFE = "governance.agentsafe"
PACT_KEY_SIGNET = "governance.signet"
PACT_KEY_ARBITER = "governance.arbiter"
PACT_KEY_LEDGER = "governance.ledger"
PACT_KEY_STIGMERGY = "governance.stigmergy"
PACT_KEY_KINDEX = "governance.kindex"
PACT_KEY_PREFLIGHT = "governance.preflight"


# ---------------------------------------------------------------------------
# TesseraSealer — class-based and function-based API
# ---------------------------------------------------------------------------
_sealer_chains: Dict[str, str] = {}  # sealer_id -> last chain_hash
_sealer_seq: Dict[str, int] = {}  # sealer_id -> last sequence_number


class TesseraSealer:
    """Hash-chain sealer with per-instance chain state."""

    def __init__(self):
        self._chains: Dict[str, str] = {}  # sealer_id -> last chain_hash
        self._seqs: Dict[str, int] = {}  # sealer_id -> last sequence_number

    def seal(self, content: str, sealer_id: str) -> TesseraSeal:
        """Create a SHA-256 hash-chain seal over canonical JSON content."""
        if not sealer_id or not sealer_id.strip():
            raise GovernanceError("sealer_id must not be empty.")

        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            raise GovernanceError(
                "Content must be valid JSON for canonical serialization."
            ) from exc

        canonical = _canonical_json(data)
        content_hash = _sha256(canonical)

        previous_hash = self._chains.get(sealer_id, "0" * 64)
        seq = self._seqs.get(sealer_id, -1) + 1
        sealed_at = _now_iso()
        chain_hash = _sha256(content_hash + previous_hash + sealer_id + sealed_at)

        self._chains[sealer_id] = chain_hash
        self._seqs[sealer_id] = seq

        return TesseraSeal(
            content_hash=content_hash,
            previous_hash=previous_hash,
            chain_hash=chain_hash,
            sealed_at=sealed_at,
            sealer_id=sealer_id,
            sequence_number=seq,
        )

    def verify_seal(self, seal_obj: TesseraSeal, content: str) -> bool:
        """Verify that a TesseraSeal is valid for the given content."""
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, TypeError) as exc:
            raise GovernanceError(
                "Content must be valid JSON for canonical verification."
            ) from exc

        canonical = _canonical_json(data)
        computed_content_hash = _sha256(canonical)

        if computed_content_hash != seal_obj.content_hash:
            raise SealVerificationError(
                message="Content hash does not match seal.",
                seal_id=getattr(seal_obj, "seal_id", seal_obj.sealer_id),
                expected_hash=seal_obj.content_hash,
                actual_hash=computed_content_hash,
            )

        expected_chain = _sha256(
            seal_obj.content_hash
            + (seal_obj.previous_hash or ("0" * 64))
            + seal_obj.sealer_id
            + seal_obj.sealed_at
        )
        if expected_chain != seal_obj.chain_hash:
            raise SealVerificationError(
                message="Chain hash does not match seal.",
                seal_id=getattr(seal_obj, "seal_id", seal_obj.sealer_id),
                expected_hash=expected_chain,
                actual_hash=seal_obj.chain_hash,
            )

        return True


# Module-level singleton sealer for function-based API
_default_sealer = TesseraSealer()


def seal(content: str, sealer_id: str) -> TesseraSeal:
    """Create a SHA-256 hash-chain seal over canonical JSON content."""
    if not sealer_id or not sealer_id.strip():
        raise GovernanceError("sealer_id must not be empty.")

    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError) as exc:
        raise GovernanceError(
            "Content must be valid JSON for canonical serialization."
        ) from exc

    canonical = _canonical_json(data)
    content_hash = _sha256(canonical)

    previous_hash = _sealer_chains.get(sealer_id, "0" * 64)
    seq = _sealer_seq.get(sealer_id, -1) + 1
    sealed_at = _now_iso()
    chain_hash = _sha256(content_hash + previous_hash + sealer_id + sealed_at)

    _sealer_chains[sealer_id] = chain_hash
    _sealer_seq[sealer_id] = seq

    return TesseraSeal(
        content_hash=content_hash,
        previous_hash=previous_hash,
        chain_hash=chain_hash,
        sealed_at=sealed_at,
        sealer_id=sealer_id,
        sequence_number=seq,
    )


def verify_seal(seal_obj: TesseraSeal, content: str) -> bool:
    """Verify that a TesseraSeal is valid for the given content."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, TypeError) as exc:
        raise GovernanceError(
            "Content must be valid JSON for canonical verification."
        ) from exc

    canonical = _canonical_json(data)
    computed_content_hash = _sha256(canonical)

    if computed_content_hash != seal_obj.content_hash:
        raise SealVerificationError(
            message="Content hash does not match seal.",
            seal_id=getattr(seal_obj, "seal_id", seal_obj.sealer_id),
            expected_hash=seal_obj.content_hash,
            actual_hash=computed_content_hash,
        )

    expected_chain = _sha256(
        seal_obj.content_hash
        + (seal_obj.previous_hash or ("0" * 64))
        + seal_obj.sealer_id
        + seal_obj.sealed_at
    )
    if expected_chain != seal_obj.chain_hash:
        raise SealVerificationError(
            message="Chain hash does not match seal.",
            seal_id=getattr(seal_obj, "seal_id", seal_obj.sealer_id),
            expected_hash=expected_chain,
            actual_hash=seal_obj.chain_hash,
        )

    return True


# ---------------------------------------------------------------------------
# ChronicleEmitter — JSON-lines log file
# ---------------------------------------------------------------------------
_CHRONICLE_LOG = Path(tempfile.gettempdir()) / "exemplar_chronicle.jsonl"


def _event_to_dict(event: ChroniclerEvent) -> Dict[str, Any]:
    d: Dict[str, Any] = {}
    d["event_id"] = event.event_id
    d["event_type"] = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
    d["review_request_id"] = event.review_request_id
    d["timestamp"] = event.timestamp
    d["stage"] = event.stage.value if event.stage and hasattr(event.stage, "value") else event.stage
    d["reviewer_id"] = event.reviewer_id
    d["payload"] = event.payload
    d["message"] = event.message
    d["pact_key"] = PACT_KEY_CHRONICLE
    return d


def _dict_to_event(d: Dict[str, Any]) -> ChroniclerEvent:
    et_raw = d.get("event_type", "")
    try:
        event_type = ChroniclerEventType[et_raw]
    except (KeyError, ValueError):
        event_type = ChroniclerEventType(et_raw)

    stage_raw = d.get("stage")
    stage = None
    if stage_raw:
        try:
            stage = ReviewStage(stage_raw)
        except (KeyError, ValueError):
            stage = stage_raw

    return ChroniclerEvent(
        event_id=d["event_id"],
        event_type=event_type,
        review_request_id=d["review_request_id"],
        timestamp=d["timestamp"],
        stage=stage,
        reviewer_id=d.get("reviewer_id"),
        payload=d.get("payload", {}),
        message=d.get("message", ""),
    )


class Chronicler:
    """JSON-lines chronicle log with configurable path."""

    def __init__(self, chronicle_log_path: Optional[str] = None):
        if chronicle_log_path:
            self._log_path = Path(chronicle_log_path)
        else:
            self._log_path = _CHRONICLE_LOG

    async def emit(self, event: ChroniclerEvent) -> bool:
        """Emit a structured ChroniclerEvent. Fire-and-forget: never raises."""
        try:
            line = json.dumps(_event_to_dict(event), sort_keys=True)
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            return True
        except Exception:
            logger.exception("Failed to emit chronicle event")
            return False

    async def query_events(
        self,
        review_request_id: str,
        event_type: Optional[Any] = None,
    ) -> List[ChroniclerEvent]:
        """Query chronicle events by review_request_id and optional event_type."""
        results: List[ChroniclerEvent] = []
        if not self._log_path.exists():
            return results
        try:
            with open(self._log_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        d = json.loads(raw_line)
                    except json.JSONDecodeError:
                        logger.warning("Corrupt line in chronicle log: %s", raw_line[:80])
                        continue
                    if d.get("review_request_id") != review_request_id:
                        continue
                    evt = _dict_to_event(d)
                    if event_type is not None:
                        evt_val = evt.event_type.value if hasattr(evt.event_type, "value") else str(evt.event_type)
                        cmp_val = event_type.value if hasattr(event_type, "value") else str(event_type)
                        if evt_val != cmp_val:
                            continue
                    results.append(evt)
        except Exception:
            logger.exception("Failed to read chronicle log")
        return results


async def emit(event: ChroniclerEvent) -> bool:
    """Emit a structured ChroniclerEvent. Fire-and-forget: never raises."""
    try:
        line = json.dumps(_event_to_dict(event), sort_keys=True)
        with open(_CHRONICLE_LOG, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        return True
    except Exception:
        logger.exception("Failed to emit chronicle event")
        return False


async def query_events(
    review_request_id: str,
    event_type: Optional[Any] = None,
) -> List[ChroniclerEvent]:
    """Query chronicle events by review_request_id and optional event_type."""
    results: List[ChroniclerEvent] = []
    if not _CHRONICLE_LOG.exists():
        return results
    try:
        with open(_CHRONICLE_LOG, "r", encoding="utf-8") as f:
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    d = json.loads(raw_line)
                except json.JSONDecodeError:
                    logger.warning("Corrupt line in chronicle log: %s", raw_line[:80])
                    continue
                if d.get("review_request_id") != review_request_id:
                    continue
                evt = _dict_to_event(d)
                if event_type is not None:
                    evt_val = evt.event_type.value if hasattr(evt.event_type, "value") else str(evt.event_type)
                    cmp_val = event_type.value if hasattr(event_type, "value") else str(event_type)
                    if evt_val != cmp_val:
                        continue
                results.append(evt)
    except Exception:
        logger.exception("Failed to read chronicle log")
    return results


# ---------------------------------------------------------------------------
# AgentSafeEnforcer — filter hunks by PolicyToken scope
# ---------------------------------------------------------------------------
def _token_expired(token: PolicyToken) -> bool:
    if token.expires_at is None:
        return False
    try:
        exp = datetime.fromisoformat(token.expires_at)
        now = datetime.now(timezone.utc)
        return exp < now
    except Exception:
        return False


def _do_filter_hunks(hunks: List[DiffHunk], token: PolicyToken) -> FilterResult:
    """Core filter logic shared by function and class API."""
    if _token_expired(token):
        raise PolicyViolationError(
            message="PolicyToken has expired.",
            token_id=token.token_id,
        )

    allowed: List[DiffHunk] = []
    denied_ids: List[str] = []
    violations: List[str] = []

    allowed_cls = set(token.allowed_classifications)

    for hunk in hunks:
        deny_reason: Optional[str] = None

        # Check file pattern match (empty patterns = allow all)
        if token.allowed_file_patterns:
            file_matches = False
            for pat in token.allowed_file_patterns:
                if fnmatch(hunk.file_path, pat):
                    file_matches = True
                    break
            if not file_matches:
                deny_reason = (
                    f"Hunk {hunk.id}: file '{hunk.file_path}' does not match "
                    f"allowed patterns {token.allowed_file_patterns}"
                )

        # Check denied patterns
        if deny_reason is None:
            for pat in token.denied_file_patterns:
                if fnmatch(hunk.file_path, pat):
                    deny_reason = (
                        f"Hunk {hunk.id}: file '{hunk.file_path}' matches "
                        f"denied pattern '{pat}'"
                    )
                    break

        # Check classification
        if deny_reason is None:
            for cls_label in hunk.classifications:
                if cls_label not in allowed_cls:
                    deny_reason = (
                        f"Hunk {hunk.id}: classification '{cls_label.value}' "
                        f"exceeds allowed classifications"
                    )
                    break

        if deny_reason:
            denied_ids.append(hunk.id)
            violations.append(deny_reason)
        else:
            allowed.append(hunk)

    return FilterResult(
        allowed_hunks=allowed,
        denied_hunk_ids=denied_ids,
        violations=violations,
    )


def _do_check_token(token: PolicyToken) -> bool:
    """Core check_token logic shared by function and class API."""
    if _token_expired(token):
        raise PolicyViolationError(
            message="PolicyToken has expired.",
            token_id=token.token_id,
        )
    # Contract says: returns True only if reviewer_id is non-empty
    if not token.reviewer_id or not token.reviewer_id.strip():
        return False
    return True


class AgentSafeEnforcer:
    """Filter hunks by PolicyToken scope."""

    def filter_hunks(self, hunks: List[DiffHunk], token: PolicyToken) -> FilterResult:
        return _do_filter_hunks(hunks, token)

    def check_token(self, token: PolicyToken) -> bool:
        return _do_check_token(token)


def filter_hunks(hunks: List[DiffHunk], token: PolicyToken) -> FilterResult:
    """Filter DiffHunks by PolicyToken scope."""
    return _do_filter_hunks(hunks, token)


def check_token(token: PolicyToken) -> bool:
    """Check whether a PolicyToken is valid (not expired)."""
    return _do_check_token(token)


# ---------------------------------------------------------------------------
# SignetManager — create/verify reviewer credentials
# ---------------------------------------------------------------------------
_SIGNET_SECRET = os.environ.get("EXEMPLAR_SIGNET_SECRET", "exemplar-default-secret-key")


def _hmac_signature(secret: str, credential_id: str, reviewer_id: str, stage_value: str) -> str:
    msg = (credential_id + reviewer_id + stage_value).encode("utf-8")
    return hmac.new(
        secret.encode("utf-8"), msg, hashlib.sha256
    ).hexdigest()


class SignetManager:
    """Create and verify reviewer credentials with HMAC-SHA256 signatures."""

    def __init__(self, secret_key: Optional[str] = None):
        self._secret = secret_key or _SIGNET_SECRET

    def create_credential(
        self,
        reviewer_id: str,
        display_name: str,
        stage: Any,  # ReviewStage
    ) -> ReviewerCredential:
        """Create a ReviewerCredential with HMAC-SHA256 signature."""
        if not reviewer_id or not reviewer_id.strip():
            raise GovernanceError("reviewer_id must not be empty.")
        if not display_name or not display_name.strip():
            raise GovernanceError("display_name must not be empty.")

        credential_id = _uuid4_hex()
        stage_val = stage.value if hasattr(stage, "value") else str(stage)
        sig = _hmac_signature(self._secret, credential_id, reviewer_id, stage_val)

        # Encode credential_id + signature into public_key_hex for backward compat
        public_key_hex = credential_id + sig

        now = _now_iso()
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()

        return ReviewerCredential(
            reviewer_id=reviewer_id,
            display_name=display_name,
            stage=stage,
            public_key_hex=public_key_hex,
            created_at=now,
            is_active=True,
            credential_id=credential_id,
            signature_hash=sig,
            expires_iso=expires,
        )

    def verify_credential(self, credential: ReviewerCredential) -> bool:
        """Verify a ReviewerCredential's HMAC signature."""
        # If the credential has credential_id and signature_hash directly, use those
        cred_id = credential.credential_id
        sig_hash = credential.signature_hash

        # If credential_id is empty, fall back to parsing public_key_hex
        if not cred_id:
            pk = credential.public_key_hex
            if len(pk) < 32:
                raise CredentialError(
                    message="Credential is malformed.",
                    credential_id=pk,
                    reason=CredentialErrorReason.MALFORMED,
                )
            cred_id = pk[:32]
            sig_hash = pk[32:]

        # Validate credential_id is valid hex (UUID4 hex)
        try:
            int(cred_id, 16)
        except ValueError:
            raise CredentialError(
                message="Credential is malformed.",
                credential_id=cred_id,
                reason=CredentialErrorReason.MALFORMED,
            )

        if len(cred_id) != 32:
            raise CredentialError(
                message="Credential is malformed.",
                credential_id=cred_id,
                reason=CredentialErrorReason.MALFORMED,
            )

        stage_val = credential.stage.value if hasattr(credential.stage, "value") else str(credential.stage)
        expected_sig = _hmac_signature(self._secret, cred_id, credential.reviewer_id, stage_val)

        if not hmac.compare_digest(sig_hash, expected_sig):
            raise CredentialError(
                message="Credential signature is invalid.",
                credential_id=cred_id,
                reason=CredentialErrorReason.INVALID_SIGNATURE,
            )

        return True


# Module-level singleton for function-based API
_default_signet = SignetManager()


def create_credential(
    reviewer_id: str,
    display_name: str,
    stage: Any,  # ReviewStage
) -> ReviewerCredential:
    """Create a ReviewerCredential with HMAC-SHA256 signature."""
    return _default_signet.create_credential(reviewer_id, display_name, stage)


def verify_credential(credential: ReviewerCredential) -> bool:
    """Verify a ReviewerCredential's HMAC signature."""
    return _default_signet.verify_credential(credential)


# ---------------------------------------------------------------------------
# ArbiterScorer — weighted trust score calculation
# ---------------------------------------------------------------------------
_CONFIDENCE_WEIGHTS = {
    "high": 1.0,
    "medium": 0.6,
    "low": 0.3,
}

_TRUST_DELTA = 0.05  # How much to adjust trust per learning record


def _do_score(
    assessments: List[Assessment],
    trust_scores: List[TrustScore],
    circuit_config: CircuitConfig,
) -> list:
    """Core scoring logic shared by function and class API."""
    if not assessments:
        raise GovernanceError("Cannot score an empty assessments list.")

    # Build trust score lookup: (reviewer_id, stage_value) -> TrustScore
    ts_map: Dict[tuple, TrustScore] = {}
    for ts in trust_scores:
        stage_val = ts.stage.value if hasattr(ts.stage, "value") else str(ts.stage)
        ts_map[(ts.reviewer_id, stage_val)] = ts

    # Validate all assessments have trust scores
    for a in assessments:
        stage_val = a.stage.value if hasattr(a.stage, "value") else str(a.stage)
        key = (a.reviewer_id, stage_val)
        if key not in ts_map:
            raise GovernanceError(
                f"Missing trust score for reviewer+stage pair: {key}"
            )

    reasoning: List[str] = []
    weighted_decisions: Dict[str, float] = {"block": 0.0, "warn": 0.0, "pass": 0.0}
    total_weight = 0.0

    for a in assessments:
        stage_val = a.stage.value if hasattr(a.stage, "value") else str(a.stage)
        ts = ts_map[(a.reviewer_id, stage_val)]
        conf_val = a.confidence.value if hasattr(a.confidence, "value") else str(a.confidence)
        conf_w = _CONFIDENCE_WEIGHTS.get(conf_val, 0.5)
        w = ts.weight * conf_w

        dec_val = a.decision.value if hasattr(a.decision, "value") else str(a.decision)
        weighted_decisions[dec_val] = weighted_decisions.get(dec_val, 0.0) + w
        total_weight += w

        reasoning.append(
            f"Assessment {a.id} (reviewer={a.reviewer_id}, stage={stage_val}): "
            f"decision={dec_val}, trust_weight={ts.weight:.2f}, "
            f"confidence={conf_val}, effective_weight={w:.3f}"
        )

    # Determine final decision
    if total_weight == 0:
        final_decision = ReviewDecision.pass_
    else:
        # Highest weighted decision wins
        best_dec = max(weighted_decisions, key=lambda k: weighted_decisions[k])
        if best_dec == "block":
            final_decision = ReviewDecision.block
        elif best_dec == "warn":
            final_decision = ReviewDecision.warn
        else:
            final_decision = ReviewDecision.pass_

    # Determine aggregate confidence
    if total_weight > 0.7:
        agg_confidence = Confidence.high
    elif total_weight > 0.3:
        agg_confidence = Confidence.medium
    else:
        agg_confidence = Confidence.low

    return [final_decision, agg_confidence, reasoning]


def _do_update_trust(trust_score: TrustScore, record: LearningRecord) -> TrustScore:
    """Core update_trust logic shared by function and class API."""
    if trust_score.reviewer_id != record.reviewer_id:
        raise GovernanceError(
            "LearningRecord reviewer_id does not match TrustScore reviewer_id."
        )

    if record.accepted:
        new_weight = min(1.0, trust_score.weight + _TRUST_DELTA)
        new_accepted = trust_score.accepted_count + 1
        new_dismissed = trust_score.dismissed_count
    else:
        new_weight = max(0.0, trust_score.weight - _TRUST_DELTA)
        new_accepted = trust_score.accepted_count
        new_dismissed = trust_score.dismissed_count + 1

    return TrustScore(
        reviewer_id=trust_score.reviewer_id,
        stage=trust_score.stage,
        weight=new_weight,
        accepted_count=new_accepted,
        dismissed_count=new_dismissed,
        updated_at=_now_iso(),
    )


class ArbiterScorer:
    """Weighted trust score calculation and conflict resolution."""

    def score(
        self,
        assessments: List[Assessment],
        trust_scores: List[TrustScore],
        circuit_config: CircuitConfig,
    ) -> list:
        return _do_score(assessments, trust_scores, circuit_config)

    def update_trust(self, trust_score: TrustScore, record: LearningRecord) -> TrustScore:
        return _do_update_trust(trust_score, record)


def score(
    assessments: List[Assessment],
    trust_scores: List[TrustScore],
    circuit_config: CircuitConfig,
) -> list:
    """Compute weighted trust score and final ReviewDecision."""
    return _do_score(assessments, trust_scores, circuit_config)


def update_trust(trust_score: TrustScore, record: LearningRecord) -> TrustScore:
    """Update a TrustScore based on a LearningRecord. Returns new instance."""
    return _do_update_trust(trust_score, record)


# ---------------------------------------------------------------------------
# LedgerClassifier — classify diff hunks against field rules
# ---------------------------------------------------------------------------
def _do_classify(hunk: DiffHunk, rules: List[LedgerFieldRule]) -> List[ClassificationLabel]:
    """Core classify logic shared by function and class API."""
    if not rules:
        raise GovernanceError("Cannot classify with empty rules list.")

    # Pre-compile patterns
    compiled: List[tuple] = []
    for rule in rules:
        try:
            compiled.append((re.compile(rule.pattern), rule.label))
        except re.error as exc:
            raise GovernanceError(
                f"Invalid regex pattern in LedgerFieldRule: {rule.pattern}"
            ) from exc

    labels: List[ClassificationLabel] = []
    all_lines = list(hunk.added_lines) + list(hunk.removed_lines)

    for line in all_lines:
        for regex, label in compiled:
            if regex.search(line):
                if label not in labels:
                    labels.append(label)

    if not labels:
        # Return default/public as fallback
        labels.append(ClassificationLabel.public)

    return labels


def _do_classify_all(
    hunks: List[DiffHunk], config: LedgerConfig
) -> List[DiffHunk]:
    """Core classify_all logic shared by function and class API."""
    if not config.rules:
        raise GovernanceError("Cannot classify with empty rules in LedgerConfig.")

    result: List[DiffHunk] = []
    for hunk in hunks:
        labels = _do_classify(hunk, config.rules)
        # Create new DiffHunk with updated classifications
        new_hunk = hunk.model_copy(update={"classifications": labels})
        result.append(new_hunk)

    return result


class LedgerClassifier:
    """Classify diff hunks against field rules for secrets/PII/internal APIs."""

    def __init__(self, rules: Optional[List[LedgerFieldRule]] = None):
        self._rules = rules or []

    def classify(self, hunk: DiffHunk, rules: Optional[List[LedgerFieldRule]] = None) -> List[ClassificationLabel]:
        use_rules = rules if rules is not None else self._rules
        return _do_classify(hunk, use_rules)

    def classify_all(self, hunks: List[DiffHunk], config: LedgerConfig) -> List[DiffHunk]:
        return _do_classify_all(hunks, config)


def classify(hunk: DiffHunk, rules: List[LedgerFieldRule]) -> List[ClassificationLabel]:
    """Classify a single DiffHunk against rules. Returns deduplicated labels."""
    return _do_classify(hunk, rules)


def classify_all(
    hunks: List[DiffHunk], config: LedgerConfig
) -> List[DiffHunk]:
    """Classify all DiffHunks using a LedgerConfig. Returns new instances."""
    return _do_classify_all(hunks, config)


# ---------------------------------------------------------------------------
# StigmergyTracker — record and query recurring pattern signals
# ---------------------------------------------------------------------------
_STIGMERGY_STORE = Path(tempfile.gettempdir()) / "exemplar_stigmergy.jsonl"


def _signal_to_dict(signal: StigmergySignal) -> Dict[str, Any]:
    stage_val = None
    if signal.stage is not None:
        stage_val = signal.stage.value if hasattr(signal.stage, "value") else str(signal.stage)
    return {
        "signal_id": signal.signal_id,
        "pattern_key": signal.pattern_key,
        "description": signal.description,
        "occurrences": signal.occurrences,
        "first_seen_at": signal.first_seen_at,
        "last_seen_at": signal.last_seen_at,
        "reviewer_id": signal.reviewer_id,
        "stage": stage_val,
        "metadata": signal.metadata,
        "pact_key": PACT_KEY_STIGMERGY,
    }


def _dict_to_signal(d: Dict[str, Any]) -> StigmergySignal:
    stage_raw = d.get("stage")
    stage = None
    if stage_raw:
        try:
            stage = ReviewStage(stage_raw)
        except (KeyError, ValueError):
            stage = stage_raw
    return StigmergySignal(
        signal_id=d["signal_id"],
        pattern_key=d["pattern_key"],
        description=d.get("description", ""),
        occurrences=d.get("occurrences", 1),
        first_seen_at=d.get("first_seen_at", ""),
        last_seen_at=d.get("last_seen_at", ""),
        reviewer_id=d.get("reviewer_id"),
        stage=stage,
        metadata=d.get("metadata", {}),
    )


class StigmergyStore:
    """Record and query recurring pattern signals to JSON storage."""

    def __init__(self, stigmergy_store_path: Optional[str] = None):
        if stigmergy_store_path:
            self._store_path = Path(stigmergy_store_path)
        else:
            self._store_path = _STIGMERGY_STORE

    async def record_signal(self, signal: StigmergySignal) -> bool:
        """Record a StigmergySignal. Fire-and-forget: never raises."""
        try:
            line = json.dumps(_signal_to_dict(signal), sort_keys=True)
            with open(self._store_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            return True
        except Exception:
            logger.exception("Failed to record stigmergy signal")
            return False

    async def query_signals(self, pattern_key: str) -> List[StigmergySignal]:
        """Query StigmergySignals by pattern_key. Chronological order."""
        results: List[StigmergySignal] = []
        if not self._store_path.exists():
            return results
        try:
            with open(self._store_path, "r", encoding="utf-8") as f:
                for raw_line in f:
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        d = json.loads(raw_line)
                    except json.JSONDecodeError:
                        logger.warning("Corrupt line in stigmergy store")
                        continue
                    if d.get("pattern_key") != pattern_key:
                        continue
                    results.append(_dict_to_signal(d))
        except Exception:
            logger.exception("Failed to read stigmergy store")
        return results


async def record_signal(signal: StigmergySignal) -> bool:
    """Record a StigmergySignal. Fire-and-forget: never raises."""
    try:
        line = json.dumps(_signal_to_dict(signal), sort_keys=True)
        with open(_STIGMERGY_STORE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
        return True
    except Exception:
        logger.exception("Failed to record stigmergy signal")
        return False


async def query_signals(pattern_key: str) -> List[StigmergySignal]:
    """Query StigmergySignals by pattern_key. Chronological order."""
    results: List[StigmergySignal] = []
    if not _STIGMERGY_STORE.exists():
        return results
    try:
        with open(_STIGMERGY_STORE, "r", encoding="utf-8") as f:
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    d = json.loads(raw_line)
                except json.JSONDecodeError:
                    logger.warning("Corrupt line in stigmergy store")
                    continue
                if d.get("pattern_key") != pattern_key:
                    continue
                results.append(_dict_to_signal(d))
    except Exception:
        logger.exception("Failed to read stigmergy store")
    return results


# ---------------------------------------------------------------------------
# KindexStore — persistent JSON-file key-value store
# ---------------------------------------------------------------------------
_KINDEX_STORE = Path(tempfile.gettempdir()) / "exemplar_kindex.json"


def _entry_to_dict(entry: KindexEntry) -> Dict[str, Any]:
    return {
        "key": entry.key,
        "kind": entry.kind,
        "summary": entry.summary,
        "data": entry.data,
        "tags": entry.tags,
        "created_at": entry.created_at,
        "updated_at": entry.updated_at,
        "pact_key": PACT_KEY_KINDEX,
    }


def _dict_to_entry(d: Dict[str, Any]) -> KindexEntry:
    return KindexEntry(
        key=d["key"],
        kind=d.get("kind", ""),
        summary=d.get("summary", ""),
        data=d.get("data", {}),
        tags=d.get("tags", []),
        created_at=d.get("created_at", ""),
        updated_at=d.get("updated_at", ""),
    )


def _load_kindex(store_path: Path) -> Dict[str, Dict[str, Any]]:
    if not store_path.exists():
        return {}
    with open(store_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_kindex(store: Dict[str, Dict[str, Any]], store_path: Path) -> None:
    tmp = store_path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(store, f, sort_keys=True)
    os.replace(tmp, store_path)


class KindexStore:
    """Persistent JSON-file key-value store for review history and codebase context."""

    def __init__(self, kindex_store_path: Optional[str] = None):
        if kindex_store_path:
            self._store_path = Path(kindex_store_path)
        else:
            self._store_path = _KINDEX_STORE

    async def kindex_put(self, entry: KindexEntry) -> bool:
        """Store or update a KindexEntry. Fire-and-forget: never raises."""
        try:
            store = _load_kindex(self._store_path)
            store[entry.key] = _entry_to_dict(entry)
            _save_kindex(store, self._store_path)
            return True
        except Exception:
            logger.exception("Failed to write kindex entry")
            return False

    async def kindex_get(self, key: str) -> Optional[KindexEntry]:
        """Retrieve a KindexEntry by key. Returns None if missing."""
        try:
            store = _load_kindex(self._store_path)
            d = store.get(key)
            if d is None:
                return None
            return _dict_to_entry(d)
        except Exception:
            logger.exception("Failed to read kindex store")
            return None

    async def kindex_query_by_tags(self, tags: List[str]) -> List[KindexEntry]:
        """Query KindexEntries by tags (ANY match). Returns matching entries."""
        if not tags:
            raise GovernanceError("Cannot query with empty tags list.")

        tag_set = set(tags)
        results: List[KindexEntry] = []
        try:
            store = _load_kindex(self._store_path)
            for _key, d in store.items():
                entry_tags = set(d.get("tags", []))
                if entry_tags & tag_set:
                    results.append(_dict_to_entry(d))
        except GovernanceError:
            raise
        except Exception:
            logger.exception("Failed to read kindex store")
        return results


async def kindex_put(entry: KindexEntry) -> bool:
    """Store or update a KindexEntry. Fire-and-forget: never raises."""
    try:
        store = _load_kindex(_KINDEX_STORE)
        store[entry.key] = _entry_to_dict(entry)
        _save_kindex(store, _KINDEX_STORE)
        return True
    except Exception:
        logger.exception("Failed to write kindex entry")
        return False


async def kindex_get(key: str) -> Optional[KindexEntry]:
    """Retrieve a KindexEntry by key. Returns None if missing."""
    try:
        store = _load_kindex(_KINDEX_STORE)
        d = store.get(key)
        if d is None:
            return None
        return _dict_to_entry(d)
    except Exception:
        logger.exception("Failed to read kindex store")
        return None


async def kindex_query_by_tags(tags: List[str]) -> List[KindexEntry]:
    """Query KindexEntries by tags (ANY match). Returns matching entries."""
    if not tags:
        raise GovernanceError("Cannot query with empty tags list.")

    tag_set = set(tags)
    results: List[KindexEntry] = []
    try:
        store = _load_kindex(_KINDEX_STORE)
        for _key, d in store.items():
            entry_tags = set(d.get("tags", []))
            if entry_tags & tag_set:
                results.append(_dict_to_entry(d))
    except GovernanceError:
        raise
    except Exception:
        logger.exception("Failed to read kindex store")
    return results


# ---------------------------------------------------------------------------
# PreflightManager — red-line enforcement before tool execution
# ---------------------------------------------------------------------------
_PREFLIGHT_DIR = Path(".exemplar") / "preflight"


class PreflightManager:
    """Pre-flight red-line enforcement for component tool calls.

    Stores preflight plans locally in .exemplar/preflight/ and attempts
    fire-and-forget submission to a signet_preflight_submit MCP tool when
    available.  Plans define red lines (glob patterns matched against
    tool_name) and contingencies (alternative tool suggestions).

    Violations are recorded locally and can be queried per component.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self._base = Path(base_dir) if base_dir else _PREFLIGHT_DIR
        self._violations: Dict[str, List[PreflightViolation]] = {}

    # -- storage helpers ----------------------------------------------------

    def _plan_path(self, component_id: str) -> Path:
        return self._base / f"{component_id}.json"

    def _violations_path(self, component_id: str) -> Path:
        return self._base / f"{component_id}_violations.json"

    def _ensure_dir(self) -> None:
        self._base.mkdir(parents=True, exist_ok=True)

    def _atomic_write(self, path: Path, data: Any) -> None:
        """Write JSON atomically via temp file + os.replace."""
        self._ensure_dir()
        fd, tmp = tempfile.mkstemp(dir=str(self._base), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, sort_keys=True, indent=2)
            os.replace(tmp, str(path))
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    # -- public API ---------------------------------------------------------

    def submit_preflight(
        self,
        component_id: str,
        red_lines: List[str],
        contingencies: Optional[Dict[str, str]] = None,
        lockout_minutes: int = 30,
    ) -> PreflightPlan:
        """Create a PreflightPlan and persist it.

        Attempts fire-and-forget submission via signet_preflight_submit MCP
        tool, falls back to local JSON storage in .exemplar/preflight/.

        Args:
            component_id: Identifier for the governed component.
            red_lines: Glob patterns for tool names that are forbidden.
            contingencies: Mapping of red-line pattern -> suggested alternative.
            lockout_minutes: How long the plan stays active (default 30).

        Returns:
            The created PreflightPlan.

        Raises:
            GovernanceError: If component_id or red_lines are empty.
        """
        if not component_id or not component_id.strip():
            raise GovernanceError("component_id must not be empty.")
        if not red_lines:
            raise GovernanceError("red_lines must not be empty.")

        now = datetime.now(timezone.utc)
        plan = PreflightPlan(
            plan_id=_uuid4_hex(),
            component_id=component_id,
            red_lines=red_lines,
            contingencies=contingencies or {},
            lockout_minutes=lockout_minutes,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(minutes=lockout_minutes)).isoformat(),
        )

        # Persist locally
        self._atomic_write(self._plan_path(component_id), plan.model_dump())

        # Fire-and-forget MCP submission (best-effort, never raises)
        try:
            self._try_mcp_submit(plan)
        except Exception:
            logger.debug("MCP preflight submit unavailable; local-only.")

        return plan

    def get_active_preflight(self, component_id: str) -> Optional[PreflightPlan]:
        """Read the active preflight plan for *component_id*.

        Returns None if no plan exists or the plan has expired.
        """
        path = self._plan_path(component_id)
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            plan = PreflightPlan(**data)
            # Check expiry
            expires = datetime.fromisoformat(plan.expires_at)
            if datetime.now(timezone.utc) > expires:
                return None
            return plan
        except Exception:
            logger.exception("Failed to read preflight plan for %s", component_id)
            return None

    def check_violation(
        self,
        component_id: str,
        tool_name: str,
        tool_input: Optional[Dict[str, Any]] = None,
    ) -> tuple:
        """Test a proposed tool call against the active plan's red lines.

        Returns:
            (allowed, alternative) — allowed is True if no red line matches;
            if blocked, alternative is the contingency string (or None).
        """
        plan = self.get_active_preflight(component_id)
        if plan is None:
            # No active plan => everything allowed
            return (True, None)

        for pattern in plan.red_lines:
            if fnmatch(tool_name, pattern):
                alternative = plan.contingencies.get(pattern)
                # Record the violation
                violation = PreflightViolation(
                    violation_id=_uuid4_hex(),
                    plan_id=plan.plan_id,
                    component_id=component_id,
                    tool_name=tool_name,
                    tool_input=tool_input or {},
                    matched_red_line=pattern,
                    alternative=alternative,
                    recorded_at=_now_iso(),
                )
                self._violations.setdefault(component_id, []).append(violation)
                self._persist_violation(component_id, violation)
                return (False, alternative)

        return (True, None)

    def get_violations(self, component_id: str) -> List[PreflightViolation]:
        """Return all recorded violations for *component_id*."""
        # Merge in-memory and on-disk
        on_disk = self._load_violations(component_id)
        in_memory = self._violations.get(component_id, [])
        seen_ids = {v.violation_id for v in on_disk}
        merged = list(on_disk)
        for v in in_memory:
            if v.violation_id not in seen_ids:
                merged.append(v)
        return merged

    # -- internal -----------------------------------------------------------

    def _persist_violation(
        self, component_id: str, violation: PreflightViolation
    ) -> None:
        """Append a violation to the component's violations JSON."""
        path = self._violations_path(component_id)
        existing: List[Dict[str, Any]] = []
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                existing = []
        existing.append(violation.model_dump())
        self._atomic_write(path, existing)

    def _load_violations(self, component_id: str) -> List[PreflightViolation]:
        path = self._violations_path(component_id)
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return [PreflightViolation(**d) for d in data]
        except Exception:
            logger.exception("Failed to load violations for %s", component_id)
            return []

    @staticmethod
    def _try_mcp_submit(plan: PreflightPlan) -> None:
        """Attempt fire-and-forget submission via MCP tool.

        In a real deployment this would call the signet_preflight_submit MCP
        tool.  Here we attempt the import and call; if the tool isn't
        available (typical in tests / standalone), we silently skip.
        """
        try:
            # Attempt dynamic import of MCP client — not expected to exist in
            # test/demo environments, so failure is the normal path.
            import mcp_client  # type: ignore[import-not-found]

            mcp_client.call_tool(
                "signet_preflight_submit",
                {
                    "plan_id": plan.plan_id,
                    "component_id": plan.component_id,
                    "red_lines": plan.red_lines,
                    "contingencies": plan.contingencies,
                    "lockout_minutes": plan.lockout_minutes,
                },
            )
        except ImportError:
            pass  # MCP client not available — local-only mode
        except Exception:
            logger.debug("MCP preflight submit failed; local-only.", exc_info=True)


# ---------------------------------------------------------------------------
# Governance — unified class wrapping all functions with PACT event emission
# ---------------------------------------------------------------------------
def _classify_inputs(*args, **kwargs) -> list:
    """Classify input types for PACT event emission."""
    result = []
    for a in args:
        result.append(type(a).__name__)
    for k, v in kwargs.items():
        result.append(f"{k}:{type(v).__name__}")
    return result


class Governance:
    """Unified governance class with optional PACT event emission."""

    def __init__(self, event_handler: Optional[Callable] = None):
        self._handler = event_handler
        self._sealer = TesseraSealer()
        self._signet = SignetManager()
        self._enforcer = AgentSafeEnforcer()
        self._arbiter = ArbiterScorer()
        self._ledger = LedgerClassifier()
        self._chronicler = Chronicler()
        self._stigmergy = StigmergyStore()
        self._kindex = KindexStore()

    def _emit_event(self, pact_key: str, event: str, **extra):
        if self._handler:
            payload = {"pact_key": pact_key, "event": event}
            payload.update(extra)
            self._handler(payload)

    def _wrap_sync(self, method_name: str, pact_key: str, fn, *args, **kwargs):
        """Wrap a sync call with invoked/completed/error events."""
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

    async def _wrap_async(self, method_name: str, pact_key: str, fn, *args, **kwargs):
        """Wrap an async call with invoked/completed/error events."""
        self._emit_event(
            pact_key, "invoked",
            input_classification=_classify_inputs(*args, **kwargs),
        )
        try:
            result = await fn(*args, **kwargs)
            self._emit_event(pact_key, "completed")
            return result
        except Exception as e:
            self._emit_event(pact_key, "error", error=str(e))
            raise

    def seal(self, *args, **kwargs):
        return self._wrap_sync("seal", "PACT:governance:seal", self._sealer.seal, *args, **kwargs)

    def verify_seal(self, *args, **kwargs):
        return self._wrap_sync("verify_seal", "PACT:governance:verify_seal", self._sealer.verify_seal, *args, **kwargs)

    def emit(self, *args, **kwargs):
        return self._wrap_sync("emit", "PACT:governance:emit", lambda *a, **kw: asyncio.get_event_loop().run_until_complete(self._chronicler.emit(*a, **kw)) if asyncio.get_event_loop().is_running() else None, *args, **kwargs)

    def query_events(self, *args, **kwargs):
        return self._wrap_sync("query_events", "PACT:governance:query_events", lambda *a, **kw: None, *args, **kwargs)

    def filter_hunks(self, *args, **kwargs):
        return self._wrap_sync("filter_hunks", "PACT:governance:filter_hunks", self._enforcer.filter_hunks, *args, **kwargs)

    def check_token(self, *args, **kwargs):
        return self._wrap_sync("check_token", "PACT:governance:check_token", self._enforcer.check_token, *args, **kwargs)

    def create_credential(self, *args, **kwargs):
        return self._wrap_sync("create_credential", "PACT:governance:create_credential", self._signet.create_credential, *args, **kwargs)

    def verify_credential(self, *args, **kwargs):
        return self._wrap_sync("verify_credential", "PACT:governance:verify_credential", self._signet.verify_credential, *args, **kwargs)

    def score(self, *args, **kwargs):
        return self._wrap_sync("score", "PACT:governance:score", self._arbiter.score, *args, **kwargs)

    def update_trust(self, *args, **kwargs):
        return self._wrap_sync("update_trust", "PACT:governance:update_trust", self._arbiter.update_trust, *args, **kwargs)

    def classify(self, *args, **kwargs):
        return self._wrap_sync("classify", "PACT:governance:classify", self._ledger.classify, *args, **kwargs)

    def classify_all(self, *args, **kwargs):
        return self._wrap_sync("classify_all", "PACT:governance:classify_all", self._ledger.classify_all, *args, **kwargs)

    def record_signal(self, *args, **kwargs):
        return self._wrap_sync("record_signal", "PACT:governance:record_signal", lambda *a, **kw: None, *args, **kwargs)

    def query_signals(self, *args, **kwargs):
        return self._wrap_sync("query_signals", "PACT:governance:query_signals", lambda *a, **kw: None, *args, **kwargs)

    def kindex_get(self, *args, **kwargs):
        return self._wrap_sync("kindex_get", "PACT:governance:kindex_get", lambda *a, **kw: None, *args, **kwargs)

    def kindex_put(self, *args, **kwargs):
        return self._wrap_sync("kindex_put", "PACT:governance:kindex_put", lambda *a, **kw: None, *args, **kwargs)

    def kindex_query_by_tags(self, *args, **kwargs):
        return self._wrap_sync("kindex_query_by_tags", "PACT:governance:kindex_query_by_tags", lambda *a, **kw: None, *args, **kwargs)
