"""Business gates only: no I/O, provider decisions, clocks or random values."""
from dataclasses import replace

from .domain import Outcome, RunState, Severity, State, ReviewResult

MAX_AUTO_FIX_ROUNDS = 3
TERMINAL_STATES = frozenset((State.COMPLETED, State.CANCELLED))
BUILTIN_STOP_CODES = frozenset((
    "DESTRUCTIVE_MIGRATION", "SHARED_HISTORY_REWRITE", "FORCE_PUSH",
    "PRODUCTION_DEPLOYMENT", "REAL_PAYMENT", "SECRET_EXPOSURE",
    "BUSINESS_CONFLICT", "SCOPE_EXPANSION", "MERGE_MAIN", "REMOTE_DELETE",
    "BASELINE_MISMATCH", "FIX_LIMIT",
))


def bound_to_current(state: RunState, result) -> bool:
    return (result is not None and result.current_sha == state.current_sha
            and result.spec_digest == state.spec_digest)


def review_errors(result: ReviewResult) -> tuple[str, ...]:
    errors = []
    counts = tuple(sum(f.severity is s for f in result.findings) for s in Severity)
    if counts != (result.p0, result.p1, result.p2):
        errors.append("review counts do not match findings")
    if result.outcome is Outcome.PASS and (result.p0 or result.p1 or counts[0] or counts[1]):
        errors.append("PASS review contains blocking findings")
    if result.outcome is Outcome.FAIL and not any(counts[:2]):
        errors.append("FAIL review requires a blocking finding")
    if not result.independent:
        errors.append("review is not independent")
    return tuple(errors)


def defer_p2(findings):
    return tuple(replace(f, deferred=True,
                         reason=f.reason if f.reason.strip() else "Deferred by default P2 policy")
                 if f.severity is Severity.P2 else f for f in findings)


def is_human_review_ready(state: RunState) -> bool:
    if state.state not in (State.REVIEW_RUNNING, State.HUMAN_REVIEW_READY):
        return False
    if state.active_stop or not state.executor_id or not state.scope_clear or not state.frozen_facts_consistent:
        return False
    results = (state.sit_result, state.review_access, state.review_result)
    if not all(bound_to_current(state, r) and r.outcome is Outcome.PASS for r in results):
        return False
    review = state.review_result
    access = state.review_access
    if (review_errors(review) or review.reviewer_id != access.reviewer_id
            or review.reviewer_id == state.executor_id):
        return False
    findings = state.unresolved_findings + review.findings
    return all(f.severity is Severity.P2 and f.deferred and bool(f.reason.strip())
               for f in findings)


def may_fix(state: RunState) -> bool:
    return (state.active_stop is None and state.scope_clear and state.frozen_facts_consistent
            and not any(f.severity is Severity.P0 for f in state.unresolved_findings))
