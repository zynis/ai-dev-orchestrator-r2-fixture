"""Immutable domain records and strict, versioned JSON-compatible state encoding."""
from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import re
from types import UnionType
from typing import get_args, get_origin, get_type_hints


class State(str, Enum):
    ROUND_READY = "ROUND_READY"
    IMPLEMENTING = "IMPLEMENTING"
    SIT_RUNNING = "SIT_RUNNING"
    REVIEW_RUNNING = "REVIEW_RUNNING"
    FIXING = "FIXING"
    BLOCKED = "BLOCKED"
    AUTO_FIX_LIMIT_REACHED = "AUTO_FIX_LIMIT_REACHED"
    HUMAN_DECISION_REQUIRED = "HUMAN_DECISION_REQUIRED"
    HUMAN_REVIEW_READY = "HUMAN_REVIEW_READY"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class Outcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    SKIPPED = "SKIPPED"


class Severity(str, Enum):
    P0 = "P0"
    P1 = "P1"
    P2 = "P2"


class Drift(str, Enum):
    MISSING = "Missing"
    PARTIAL = "Partial"
    CONTRADICTS = "Contradicts"
    UNREQUESTED = "Unrequested"


class EventKind(str, Enum):
    START = "START"
    DELIVERY = "DELIVERY"
    SIT = "SIT"
    ACCESS = "ACCESS"
    REVIEW = "REVIEW"
    LOW_RISK_ERROR = "LOW_RISK_ERROR"
    STOP = "STOP"
    BLOCK = "BLOCK"
    RESUME = "RESUME"
    HUMAN = "HUMAN"
    CANCEL = "CANCEL"


class EffectKind(str, Enum):
    START_EXECUTOR = "START_EXECUTOR"
    START_SIT = "START_SIT"
    START_REVIEW = "START_REVIEW"
    START_FIX = "START_FIX"
    REQUEST_HUMAN = "REQUEST_HUMAN"


class Decision(str, Enum):
    ACCEPT = "ACCEPT"
    REJECT = "REJECT"
    REQUEST_CHANGES = "REQUEST_CHANGES"
    CANCEL = "CANCEL"


class StopCategory(str, Enum):
    DATA = "DATA"
    GIT = "GIT"
    PRODUCTION = "PRODUCTION"
    PAYMENT = "PAYMENT"
    SECRET = "SECRET"
    BUSINESS = "BUSINESS"
    BUDGET = "BUDGET"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def text(value: str, name: str) -> None:
    require(type(value) is str and bool(value.strip()), f"{name} must be nonempty")


def sha(value: str) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None,
            "SHA must be a full lowercase Git SHA")


def digest(value: str) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None,
            "spec digest must be SHA-256 hex")


def _matches(value, annotation) -> bool:
    origin = get_origin(annotation)
    if origin is UnionType:
        return any(_matches(value, t) for t in get_args(annotation))
    if origin is tuple:
        item_type, _ = get_args(annotation)
        return type(value) is tuple and all(_matches(v, item_type) for v in value)
    return type(value) is annotation


class Record:
    def __post_init__(self):
        for name, annotation in get_type_hints(type(self)).items():
            require(_matches(getattr(self, name), annotation),
                    f"{type(self).__name__}.{name}: wrong type")


@dataclass(frozen=True)
class Finding(Record):
    id: str
    severity: Severity
    drift: Drift
    location: str
    spec_basis: str
    impact: str
    required_fix: str
    retest_requirement: str
    deferred: bool = False
    reason: str = ""

    def __post_init__(self):
        super().__post_init__()
        for name in ("id", "location", "spec_basis", "impact", "required_fix", "retest_requirement"):
            text(getattr(self, name), name)
        require(not self.deferred or self.severity is Severity.P2,
                "P0/P1 cannot be deferred")
        if self.deferred:
            text(self.reason, "deferred reason")


@dataclass(frozen=True)
class BoundResult(Record):
    current_sha: str
    spec_digest: str
    outcome: Outcome
    evidence: str

    def __post_init__(self):
        super().__post_init__()
        sha(self.current_sha)
        digest(self.spec_digest)
        text(self.evidence, "evidence")


@dataclass(frozen=True)
class ReviewAccess(BoundResult):
    reviewer_id: str

    def __post_init__(self):
        super().__post_init__()
        text(self.reviewer_id, "reviewer_id")


@dataclass(frozen=True)
class ReviewResult(BoundResult):
    reviewer_id: str
    independent: bool
    p0: int
    p1: int
    p2: int
    findings: tuple[Finding, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        text(self.reviewer_id, "reviewer_id")
        require(all(n >= 0 for n in (self.p0, self.p1, self.p2)), "negative count")
        require(len({f.id for f in self.findings}) == len(self.findings), "duplicate finding ID")
        # Semantic contradictions are kept representable so transition can reject
        # malformed reviewer messages without silently losing their known findings.

    @classmethod
    def from_dict(cls, value: dict) -> ReviewResult:
        return _decode(cls, value)


@dataclass(frozen=True)
class Delivery(Record):
    run_id: str
    round_id: str
    attempt: int
    base_sha: str
    input_sha: str
    candidate_sha: str
    spec_digest: str
    executor_id: str
    evidence: str

    def __post_init__(self):
        super().__post_init__()
        for name in ("run_id", "round_id", "executor_id", "evidence"):
            text(getattr(self, name), name)
        for value in (self.base_sha, self.input_sha, self.candidate_sha):
            sha(value)
        digest(self.spec_digest)
        require(0 <= self.attempt <= 3, "invalid delivery attempt")


@dataclass(frozen=True)
class StopCondition(Record):
    code: str
    category: StopCategory
    reason: str
    evidence: str
    resolution_requirement: str
    human_role: str = "Owner"

    def __post_init__(self):
        super().__post_init__()
        for name in ("code", "reason", "evidence", "resolution_requirement", "human_role"):
            text(getattr(self, name), name)


@dataclass(frozen=True)
class Block(Record):
    reason: str
    unblock_requirement: str

    def __post_init__(self):
        super().__post_init__()
        text(self.reason, "block reason")
        text(self.unblock_requirement, "unblock requirement")


@dataclass(frozen=True)
class Resume(Record):
    condition_resolved: bool
    binding_confirmed: bool


@dataclass(frozen=True)
class HumanDecision(Record):
    decision: Decision
    actor: str
    authorized: bool

    def __post_init__(self):
        super().__post_init__()
        text(self.actor, "human actor")


@dataclass(frozen=True)
class LowRiskError(Record):
    reason: str
    scope_clear: bool
    frozen_facts_consistent: bool

    def __post_init__(self):
        super().__post_init__()
        text(self.reason, "low risk error")


@dataclass(frozen=True)
class Event(Record):
    event_id: str
    run_id: str
    round_id: str
    kind: EventKind
    current_sha: str
    spec_digest: str
    attempt: int
    evidence: str
    payload: Delivery | BoundResult | ReviewAccess | ReviewResult | StopCondition | Block | Resume | HumanDecision | LowRiskError | None = None
    authorized: bool = False

    def __post_init__(self):
        super().__post_init__()
        for name in ("event_id", "run_id", "round_id", "evidence"):
            text(getattr(self, name), name)
        sha(self.current_sha)
        digest(self.spec_digest)
        require(0 <= self.attempt <= 3, "invalid event attempt")


@dataclass(frozen=True)
class TransitionRecord(Record):
    event_id: str
    from_state: State
    to_state: State
    current_sha: str
    spec_digest: str
    attempt: int
    reason: str
    evidence: str
    event_kind: EventKind
    event_attempt: int
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class Effect(Record):
    kind: EffectKind
    run_id: str
    round_id: str
    attempt: int
    current_sha: str
    spec_digest: str
    event_id: str


@dataclass(frozen=True)
class RunState(Record):
    run_id: str
    round_id: str
    spec_digest: str
    base_sha: str
    current_sha: str
    state: State = State.ROUND_READY
    previous_state: State | None = None
    interrupted_state: State | None = None
    unblock_requirement: str = ""
    auto_fix_count: int = 0
    max_auto_fix_rounds: int = 3
    sit_result: BoundResult | None = None
    review_access: ReviewAccess | None = None
    review_result: ReviewResult | None = None
    unresolved_findings: tuple[Finding, ...] = ()
    active_stop: StopCondition | None = None
    processed_event_ids: tuple[str, ...] = ()
    human_decision: HumanDecision | None = None
    history: tuple[TransitionRecord, ...] = ()
    executor_id: str = ""
    scope_clear: bool = True
    frozen_facts_consistent: bool = True

    def __post_init__(self):
        super().__post_init__()
        text(self.run_id, "run_id")
        text(self.round_id, "round_id")
        digest(self.spec_digest)
        sha(self.base_sha)
        sha(self.current_sha)
        require(0 <= self.auto_fix_count <= self.max_auto_fix_rounds <= 3, "invalid fix budget")
        require(len(set(self.processed_event_ids)) == len(self.processed_event_ids), "duplicate event IDs")
        require(all(x.strip() for x in self.processed_event_ids), "empty event ID")
        require(len({f.id for f in self.unresolved_findings}) == len(self.unresolved_findings),
                "duplicate unresolved finding ID")
        if self.state is State.BLOCKED:
            require(self.interrupted_state in (State.ROUND_READY, State.IMPLEMENTING,
                    State.FIXING, State.SIT_RUNNING, State.REVIEW_RUNNING,
                    State.HUMAN_REVIEW_READY), "invalid blocked checkpoint")
            text(self.unblock_requirement, "unblock requirement")

    def to_dict(self) -> dict:
        return {"schema_version": 1, "run": _encode(self)}

    @classmethod
    def from_dict(cls, value: dict) -> RunState:
        require(type(value) is dict and set(value) == {"schema_version", "run"}, "invalid state envelope")
        require(type(value["schema_version"]) is int and value["schema_version"] == 1,
                "unsupported state schema")
        return _decode(cls, value["run"])


@dataclass(frozen=True)
class TransitionResult(Record):
    new_state: RunState
    records: tuple[TransitionRecord, ...] = ()
    effects: tuple[Effect, ...] = ()
    errors: tuple[str, ...] = ()
    disposition: str = "APPLIED"


def _encode(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {f.name: _encode(getattr(value, f.name)) for f in fields(value)}
    if type(value) is tuple:
        return [_encode(v) for v in value]
    return value


def _decode(annotation, value):
    origin = get_origin(annotation)
    if origin is UnionType:
        for choice in get_args(annotation):
            try:
                return _decode(choice, value)
            except (ValueError, TypeError):
                pass
        raise ValueError("value does not match optional/union type")
    if origin is tuple:
        require(type(value) is list, "expected JSON array")
        return tuple(_decode(get_args(annotation)[0], x) for x in value)
    if isinstance(annotation, type) and issubclass(annotation, Enum):
        require(type(value) is str, "expected enum string")
        return annotation(value)
    if is_dataclass(annotation):
        require(type(value) is dict, "expected record object")
        names = {f.name for f in fields(annotation)}
        require(set(value) == names, "missing/unknown record field")
        hints = get_type_hints(annotation)
        return annotation(**{k: _decode(hints[k], v) for k, v in value.items()})
    require(type(value) is annotation, "incorrect primitive type")
    return value
