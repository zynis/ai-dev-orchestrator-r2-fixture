"""Local-tested controller application boundary; live job wiring is separately gated."""
import copy
import re

from .candidate_transport import canonical, hash_bytes
from .domain import Event, EventKind, RunState, StopCategory, StopCondition
from .github_state import StateBlocked, validate_document
from .state_machine import transition


def canonical_submission(submission, *, target_repository, base_sha, planner_identity, authorized):
    required = {"submission_id", "run_id", "round_id", "spec_revision", "target_repository",
                "base_sha", "goal", "background", "in_scope", "out_of_scope", "invariants",
                "acceptance_criteria", "validation", "git_requirements", "review_access",
                "stop_conditions", "planner_identity", "authorization_evidence", "control_plane_sha"}
    if type(submission) is not dict or set(submission) != required or authorized is not True:
        raise StateBlocked("untrusted/incomplete Planner submission")
    if (submission["target_repository"] != target_repository or submission["base_sha"] != base_sha
            or submission["planner_identity"] != planner_identity):
        raise StateBlocked("Planner authorization binding mismatch")
    for name in required - {"spec_revision", "in_scope", "out_of_scope", "invariants",
                            "acceptance_criteria", "validation", "stop_conditions"}:
        if type(submission[name]) is not str or not submission[name].strip():
            raise StateBlocked("invalid Planner field")
    for name in ("in_scope", "out_of_scope", "invariants", "acceptance_criteria", "validation", "stop_conditions"):
        if type(submission[name]) is not list or not submission[name] or any(type(v) is not str or not v.strip() for v in submission[name]):
            raise StateBlocked("invalid Planner list")
    if type(submission["spec_revision"]) is not int or submission["spec_revision"] != 1:
        raise StateBlocked("unsupported initial spec revision")
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", submission["target_repository"])
            or not all(re.fullmatch(r"[0-9a-f]{40}", submission[k]) for k in ("base_sha", "control_plane_sha"))):
        raise StateBlocked("invalid repository/SHA")
    result = copy.deepcopy(submission)
    def normalize(value):
        if isinstance(value, dict):
            return {k: normalize(v) for k, v in value.items()}
        if isinstance(value, list):
            return [normalize(v) for v in value]
        return value.replace("\r\n", "\n").replace("\r", "\n") if isinstance(value, str) else value
    return normalize(result)


class Controller:
    def __init__(self, store):
        self.store = store

    def plan(self, event, *, expected_revision, actual_control_plane_sha, issue_body):
        doc, _, _, repair = self.store.load()
        if repair:
            raise StateBlocked("snapshot recovery required")
        state = validate_document(doc)
        if doc["control_plane_sha"] != actual_control_plane_sha:
            raise StateBlocked("untrusted control-plane revision")
        if type(event) is not Event or (event.run_id, event.round_id) != (state.run_id, state.round_id):
            raise StateBlocked("event identity mismatch")
        # Detect edit even on replay, before any new effect can be started.
        if hash_bytes(issue_body.encode("utf-8")) != doc["submission_body_digest"]:
            stop = StopCondition("BUSINESS_CONFLICT", StopCategory.BUSINESS, "Active Issue body edited",
                                 event.evidence, "Explicit authorized spec revision required")
            conflict_id = "body-conflict-" + hash_bytes(issue_body.encode("utf-8"))
            event = Event(conflict_id, state.run_id, state.round_id, EventKind.STOP,
                          state.current_sha, state.spec_digest, state.auto_fix_count, event.evidence, stop)
        elif event.event_id in state.processed_event_ids:
            return doc, transition(state, event)
        elif doc["revision"] != expected_revision:
            raise StateBlocked("event revision conflict")
        result = transition(state, event)
        if result.errors and result.disposition == "REJECTED":
            raise StateBlocked("core rejected event")
        if result.new_state == state:
            return doc, result
        updated = copy.deepcopy(doc)
        updated["revision"] += 1
        updated["run"] = result.new_state.to_dict()
        for effect in result.effects:
            effect_id = hash_bytes(canonical({"run": effect.run_id, "round": effect.round_id,
                "phase": result.new_state.state.value, "attempt": effect.attempt,
                "sha": effect.current_sha, "kind": effect.kind.value}))
            if effect_id not in updated["completed"]:
                updated["pending"].setdefault(effect_id, {"kind": effect.kind.value,
                    "attempt": effect.attempt, "expected_sha": effect.current_sha,
                    "event_id": event.event_id})
        return updated, result

    def apply(self, event, *, expected_revision, actual_control_plane_sha, issue_body, dry_run=False):
        old, _, _, _ = self.store.load()
        updated, result = self.plan(event, expected_revision=expected_revision,
                                   actual_control_plane_sha=actual_control_plane_sha, issue_body=issue_body)
        if not dry_run and updated != old:
            self.store.save(updated, expected_revision=old["revision"], event_id=result.records[-1].event_id,
                            reason=result.records[-1].reason, evidence=event.evidence)
        return updated, result
