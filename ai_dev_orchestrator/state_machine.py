"""Pure state + event -> state, audit records, symbolic intents, rejection."""
from dataclasses import replace

from .domain import (
    Block, BoundResult, Decision, Delivery, Effect, EffectKind, Event, EventKind,
    HumanDecision, LowRiskError, Outcome, Resume, ReviewAccess, ReviewResult,
    RunState, Severity, State, StopCategory, StopCondition, TransitionRecord,
    TransitionResult,
)
from .policy import (
    TERMINAL_STATES, bound_to_current, defer_p2, is_human_review_ready,
    may_fix, review_errors,
)


def _reject(state, reason):
    return TransitionResult(state, errors=(reason,), disposition="REJECTED")


def transition(state: RunState, event: Event) -> TransitionResult:
    if type(state) is not RunState or type(event) is not Event:
        raise TypeError("transition expects RunState and Event")
    if (event.run_id, event.round_id) != (state.run_id, state.round_id):
        return _reject(state, "wrong run/round")
    if event.event_id in state.processed_event_ids:
        return TransitionResult(state, disposition="ALREADY_PROCESSED")
    if state.state in TERMINAL_STATES:
        return TransitionResult(state, disposition="TERMINAL_NOOP")
    if (event.current_sha != state.current_sha or event.spec_digest != state.spec_digest
            or event.attempt != state.auto_fix_count):
        return _reject(state, "stale SHA/spec/attempt")

    records = []
    effects = []
    errors = []
    current = state

    def move(target, reason, **changes):
        nonlocal current
        before = current.state
        current = replace(current, state=target, previous_state=before, **changes)
        record = TransitionRecord(event.event_id, before, target, current.current_sha,
                                  current.spec_digest, current.auto_fix_count, reason, event.evidence,
                                  event.kind, event.attempt, current.unresolved_findings)
        records.append(record)
        current = replace(current, history=current.history + (record,))

    def emit(kind):
        effects.append(Effect(kind, current.run_id, current.round_id, current.auto_fix_count,
                              current.current_sha, current.spec_digest, event.event_id))

    def human(reason, stop=None):
        move(State.HUMAN_DECISION_REQUIRED, reason, active_stop=stop or current.active_stop,
             interrupted_state=None, unblock_requirement="")
        emit(EffectKind.REQUEST_HUMAN)

    def block(reason):
        checkpoint = current.interrupted_state if current.state is State.BLOCKED else current.state
        move(State.BLOCKED, reason, interrupted_state=checkpoint, unblock_requirement=reason)

    def fix(reason):
        if not may_fix(current):
            human("Fix requires human decision: " + reason)
        elif current.auto_fix_count >= current.max_auto_fix_rounds:
            stop = StopCondition("FIX_LIMIT", StopCategory.BUDGET, "Auto-fix budget exhausted",
                                 event.evidence, "Owner must decide next scope; no automatic retry")
            move(State.AUTO_FIX_LIMIT_REACHED, "Fix limit reached", active_stop=stop)
            human("No further automatic Fix", stop)
        else:
            move(State.FIXING, reason, auto_fix_count=current.auto_fix_count + 1,
                 sit_result=None, review_access=None, review_result=None,
                 interrupted_state=None, unblock_requirement="")
            emit(EffectKind.START_FIX)

    def merge_findings(incoming):
        by_id = {f.id: f for f in current.unresolved_findings}
        for finding in incoming:
            old = by_id.get(finding.id)
            # A failing/blocked report may not downgrade previously known risk.
            if old is None or list(Severity).index(finding.severity) <= list(Severity).index(old.severity):
                by_id[finding.id] = finding
        return tuple(by_id[k] for k in sorted(by_id))

    payload = event.payload
    kind = event.kind
    if kind is EventKind.CANCEL or (kind is EventKind.HUMAN and
                                   type(payload) is HumanDecision and payload.decision is Decision.CANCEL):
        if type(payload) is not HumanDecision or payload.decision is not Decision.CANCEL or not payload.authorized:
            return _reject(state, "Cancel requires authorized human")
        move(State.CANCELLED, "Human cancelled", human_decision=payload)
    elif kind is EventKind.STOP:
        if type(payload) is not StopCondition:
            return _reject(state, "Stop requires StopCondition")
        human(payload.reason, payload)
    elif kind is EventKind.HUMAN:
        if type(payload) is not HumanDecision or not payload.authorized:
            return _reject(state, "Human decision lacks authorization")
        if current.state is not State.HUMAN_REVIEW_READY:
            return _reject(state, "Human acceptance/rejection requires ready state")
        current = replace(current, human_decision=payload)
        if payload.decision is Decision.ACCEPT:
            if not is_human_review_ready(current):
                return _reject(state, "Ready evidence is no longer valid")
            move(State.COMPLETED, "Round accepted; no merge/release/deployment")
        else:
            human("Human " + payload.decision.value)
    elif kind is EventKind.BLOCK:
        if type(payload) is not Block or current.state in (
                State.HUMAN_DECISION_REQUIRED, State.AUTO_FIX_LIMIT_REACHED):
            return _reject(state, "Invalid block/checkpoint")
        checkpoint = current.interrupted_state if current.state is State.BLOCKED else current.state
        # Revalidate before resuming a formerly ready checkpoint.
        changes = {"sit_result": None, "review_access": None, "review_result": None} if checkpoint is State.HUMAN_REVIEW_READY else {}
        move(State.BLOCKED, payload.reason, interrupted_state=checkpoint,
             unblock_requirement=payload.unblock_requirement, **changes)
    elif kind is EventKind.RESUME:
        if type(payload) is not Resume or current.state is not State.BLOCKED:
            return _reject(state, "Resume requires blocked state")
        if not payload.condition_resolved or not payload.binding_confirmed or current.active_stop:
            return _reject(state, "Blocking condition/baseline not resolved")
        checkpoint = current.interrupted_state
        if checkpoint is State.HUMAN_REVIEW_READY:
            checkpoint = State.SIT_RUNNING
        move(checkpoint, "Explicitly resolved blocking condition",
             interrupted_state=None, unblock_requirement="")
        if checkpoint is State.SIT_RUNNING:
            current = replace(current, sit_result=None, review_access=None, review_result=None)
            emit(EffectKind.START_SIT)
        elif checkpoint is State.REVIEW_RUNNING:
            current = replace(current, review_access=None, review_result=None)
            if not bound_to_current(current, current.sit_result) or current.sit_result.outcome is not Outcome.PASS:
                block("SIT evidence must be recovered before review")
            else:
                emit(EffectKind.START_REVIEW)
        # IMPLEMENTING/FIXING resume waits for original attempt delivery.
        # Never re-emit an expensive START_EXECUTOR/START_FIX on resume.
    elif current.active_stop or current.state in (State.HUMAN_DECISION_REQUIRED, State.AUTO_FIX_LIMIT_REACHED):
        return _reject(state, "Active stop/human decision prevents automatic effects")
    elif kind is EventKind.START:
        if current.state is not State.ROUND_READY or payload is not None or not event.authorized:
            return _reject(state, "Start requires authorized ROUND_READY")
        if not current.scope_clear or not current.frozen_facts_consistent:
            human("Scope/frozen facts require a decision before implementation")
        else:
            move(State.IMPLEMENTING, "Initial implementation authorized")
            emit(EffectKind.START_EXECUTOR)
    elif kind is EventKind.DELIVERY:
        if type(payload) is not Delivery or current.state not in (State.IMPLEMENTING, State.FIXING):
            return _reject(state, "Delivery is not expected")
        if ((payload.run_id, payload.round_id, payload.attempt, payload.base_sha,
             payload.input_sha, payload.spec_digest) !=
            (current.run_id, current.round_id, current.auto_fix_count, current.base_sha,
             current.current_sha, current.spec_digest) or payload.candidate_sha == current.current_sha):
            return _reject(state, "Invalid delivery identity or unchanged candidate")
        move(State.SIT_RUNNING, "New candidate invalidates all old gates",
             current_sha=payload.candidate_sha, executor_id=payload.executor_id,
             sit_result=None, review_access=None, review_result=None)
        emit(EffectKind.START_SIT)
    elif kind is EventKind.SIT:
        if type(payload) is not BoundResult or current.state is not State.SIT_RUNNING:
            return _reject(state, "SIT result is not expected")
        if not bound_to_current(current, payload):
            return _reject(state, "SIT result SHA/spec mismatch")
        current = replace(current, sit_result=payload, review_access=None, review_result=None)
        if payload.outcome is Outcome.PASS:
            move(State.REVIEW_RUNNING, "Required SIT passed")
            emit(EffectKind.START_REVIEW)
        elif payload.outcome is Outcome.FAIL:
            fix("SIT failed")
        else:
            block("SIT unavailable or required SIT skipped")
    elif kind in (EventKind.ACCESS, EventKind.REVIEW):
        waiting = current.state is State.REVIEW_RUNNING
        blocked_review = current.state is State.BLOCKED and current.interrupted_state is State.REVIEW_RUNNING
        if not (waiting or blocked_review):
            return _reject(state, "Review is not expected")
        expected = ReviewAccess if kind is EventKind.ACCESS else ReviewResult
        if type(payload) is not expected or not bound_to_current(current, payload):
            return _reject(state, "Review payload type or SHA/spec mismatch")
        if kind is EventKind.ACCESS:
            if payload.reviewer_id == current.executor_id:
                block("Executor cannot confirm independent review access")
            else:
                current = replace(current, review_access=payload)
                if payload.outcome is not Outcome.PASS:
                    block("Exact review source unavailable")
                else:
                    move(current.state, "Review source access recorded")
        else:
            incoming = defer_p2(payload.findings)
            payload = replace(payload, findings=incoming)
            current = replace(current, review_result=payload,
                              unresolved_findings=merge_findings(incoming))
            if any(f.severity is Severity.P0 for f in current.unresolved_findings):
                human("Reviewer P0; no automatic Fix")
            else:
                errors.extend(review_errors(payload))
                if payload.reviewer_id == current.executor_id:
                    errors.append("Executor cannot be independent Reviewer")
                access_ok = (bound_to_current(current, current.review_access)
                             and current.review_access.outcome is Outcome.PASS
                             and current.review_access.reviewer_id == payload.reviewer_id)
                sit_ok = bound_to_current(current, current.sit_result) and current.sit_result.outcome is Outcome.PASS
                if errors or not access_ok or not sit_ok or blocked_review:
                    block("Review evidence/access/independence invalid; preserve known findings")
                elif payload.outcome in (Outcome.BLOCKED, Outcome.SKIPPED):
                    block("Review unavailable or skipped; preserve known findings")
                elif payload.outcome is Outcome.FAIL:
                    fix("Reviewer P1")
                else:
                    # A fresh, complete independent PASS resolves prior candidate findings.
                    # A fresh PASS resolves prior P0/P1 for the new candidate.
                    # Deferred P2 stay visible; absence in a later report is not
                    # an explicit resolution of a previously deferred item.
                    retained = {f.id: f for f in current.unresolved_findings if f.severity is Severity.P2}
                    retained.update({f.id: f for f in incoming})
                    current = replace(current, unresolved_findings=tuple(retained[k] for k in sorted(retained)))
                    if is_human_review_ready(current):
                        move(State.HUMAN_REVIEW_READY, "All exact-candidate gates passed; halt")
                    else:
                        block("Ready gate denied")
    elif kind is EventKind.LOW_RISK_ERROR:
        if type(payload) is not LowRiskError or current.state not in (
                State.IMPLEMENTING, State.SIT_RUNNING, State.REVIEW_RUNNING, State.FIXING):
            return _reject(state, "Low-risk error is not expected")
        if not payload.scope_clear or not payload.frozen_facts_consistent:
            human("Low-risk classification cannot override scope/spec conflict")
        else:
            fix(payload.reason)
    else:
        return _reject(state, "Unsupported event/state combination")

    current = replace(current, processed_event_ids=current.processed_event_ids + (event.event_id,))
    return TransitionResult(current, tuple(records), tuple(effects), tuple(errors))
