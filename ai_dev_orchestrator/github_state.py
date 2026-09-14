"""GitHub comments as a checked journal; caller supplies verified writer provenance.

GitHub has no multi-object CAS. A single logical writer is a precondition, not
an exactly-once claim. Lost/ambiguous mutation responses never trigger a retry.
"""
import copy
import json

from .candidate_transport import canonical, hash_bytes
from .domain import RunState

STATE_MARKER = "<!-- ai-orchestrator-state/v1 -->"
AUDIT_MARKER = "<!-- ai-orchestrator-audit/v1 -->"
ZERO = "0" * 64


class StateBlocked(ValueError):
    pass


def _check(value, message):
    if not value:
        raise StateBlocked(message)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _check(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def parse_comment(body, marker):
    _check(type(body) is str and body.startswith(marker + "\n"), "invalid comment marker")
    try:
        value = json.loads(body[len(marker) + 1:], object_pairs_hook=_unique)
    except (ValueError, TypeError):
        raise StateBlocked("invalid comment JSON") from None
    _check(type(value) is dict, "expected comment object")
    return value


def validate_document(doc):
    keys = {"schema_version", "revision", "control_plane_sha", "spec", "run",
            "submission_body_digest", "branch", "pr_number", "pending", "completed"}
    _check(type(doc) is dict and set(doc) == keys, "document schema mismatch")
    _check(type(doc["schema_version"]) is int and doc["schema_version"] == 1, "schema version")
    _check(type(doc["revision"]) is int and doc["revision"] >= 0, "invalid revision")
    _check(type(doc["control_plane_sha"]) is str and len(doc["control_plane_sha"]) == 40
           and all(c in "0123456789abcdef" for c in doc["control_plane_sha"]), "control plane SHA")
    _check(type(doc["spec"]) is dict and type(doc["pending"]) is dict and type(doc["completed"]) is dict,
           "invalid document records")
    _check(type(doc["submission_body_digest"]) is str and len(doc["submission_body_digest"]) == 64, "body digest")
    _check(type(doc["branch"]) is str and (doc["pr_number"] is None or
           type(doc["pr_number"]) is int and doc["pr_number"] > 0), "branch/PR identity")
    try:
        state = RunState.from_dict(doc["run"])
    except (ValueError, TypeError, KeyError):
        raise StateBlocked("invalid core state") from None
    _check(hash_bytes(canonical(doc["spec"])) == state.spec_digest, "spec binding mismatch")
    _check(not set(doc["pending"]) & set(doc["completed"]), "pending/completed overlap")
    return state


def new_document(state, spec, control_plane_sha, submission_body):
    doc = {"schema_version": 1, "revision": 0, "control_plane_sha": control_plane_sha,
           "spec": spec, "run": state.to_dict(),
           "submission_body_digest": hash_bytes(submission_body.encode("utf-8")),
           "branch": "", "pr_number": None, "pending": {}, "completed": {}}
    validate_document(doc)
    return doc


def audit_entry(document, previous_digest, *, event_id, effect_id, from_state, reason, evidence):
    state = validate_document(document)
    entry = {"revision": document["revision"], "previous_digest": previous_digest,
             "event_id": event_id, "effect_id": effect_id, "from_state": from_state,
             "to_state": state.state.value, "current_sha": state.current_sha,
             "spec_digest": state.spec_digest, "reason": reason, "evidence": evidence,
             "new_state_digest": hash_bytes(canonical(document)),
             "control_plane_sha": document["control_plane_sha"], "document": document}
    return {**entry, "digest": hash_bytes(canonical(entry))}


class GitHubStateStore:
    def __init__(self, api, issue_number, control_plane_sha, verify_writer):
        if type(issue_number) is not int or issue_number < 1:
            raise ValueError("invalid Issue")
        self.api, self.issue = api, issue_number
        self.control_plane_sha = control_plane_sha
        self.verify_writer = verify_writer

    @property
    def route(self):
        return f"issues/{self.issue}/comments"

    def load(self):
        snapshots, audits = [], []
        for comment in self.api.pages(self.route + "?per_page=100"):
            body = comment.get("body", "")
            if not (body.startswith(STATE_MARKER) or body.startswith(AUDIT_MARKER)):
                continue
            # A marker is never proof of authority. The callback must check both
            # bot identity and trusted workflow run/ref/SHA, not a self-claim.
            if not self.verify_writer(comment, self.control_plane_sha):
                continue
            if body.startswith(STATE_MARKER):
                snapshots.append((comment["id"], parse_comment(body, STATE_MARKER)))
            else:
                audits.append(parse_comment(body, AUDIT_MARKER))
        _check(len(snapshots) <= 1, "duplicate authoritative snapshot")
        _check(audits, "audit chain missing")
        _check(all(type(item.get("revision")) is int for item in audits), "invalid audit revision")
        audits.sort(key=lambda item: item["revision"])
        previous = ZERO
        validated = []
        expected_keys = {"revision", "previous_digest", "event_id", "effect_id", "from_state",
                         "to_state", "current_sha", "spec_digest", "reason", "evidence",
                         "new_state_digest", "control_plane_sha", "document", "digest"}
        for revision, item in enumerate(audits):
            _check(type(item) is dict and set(item) == expected_keys, "audit schema mismatch")
            _check(type(item["revision"]) is int and item["revision"] == revision, "audit gap/duplicate")
            _check(item["previous_digest"] == previous, "audit chain break")
            unsigned = {k: v for k, v in item.items() if k != "digest"}
            _check(hash_bytes(canonical(unsigned)) == item["digest"], "audit digest mismatch")
            document = item["document"]
            state = validate_document(document)
            _check(document["revision"] == revision and item["control_plane_sha"] ==
                   document["control_plane_sha"] == self.control_plane_sha, "control plane changed")
            _check(item["new_state_digest"] == hash_bytes(canonical(document)), "state digest mismatch")
            _check((item["to_state"], item["current_sha"], item["spec_digest"]) ==
                   (state.state.value, state.current_sha, state.spec_digest), "audit state binding")
            if validated:
                old = RunState.from_dict(validated[-1]["run"])
                _check(item["from_state"] == old.state.value and
                       (state.run_id, state.round_id) == (old.run_id, old.round_id), "audit continuity")
            previous = item["digest"]
            validated.append(document)
        snapshot_id = None
        needs_repair = True
        if snapshots:
            snapshot_id, snap = snapshots[0]
            _check(type(snap) is dict and set(snap) == {"document", "audit_head"}, "snapshot schema")
            document = snap["document"]
            validate_document(document)
            revision = document["revision"]
            _check(revision < len(validated) and document == validated[revision] and
                   snap["audit_head"] == audits[revision]["digest"], "unexplained snapshot")
            needs_repair = revision != len(validated) - 1
        # Returning recovered data is read-only; repair is a separate explicit write.
        return copy.deepcopy(validated[-1]), previous, snapshot_id, needs_repair

    def _write_comment(self, body):
        _check(len(body.encode("utf-8")) <= 60000, "comment too large")
        def reconcile():
            return [c for c in self.api.pages(self.route + "?per_page=100")
                    if c.get("body") == body and self.verify_writer(c, self.control_plane_sha)]
        return self.api.mutate_once("POST", self.route, {"body": body}, reconcile)

    def repair(self):
        doc, head, snapshot_id, needed = self.load()
        if not needed:
            return doc
        body = STATE_MARKER + "\n" + canonical({"document": doc, "audit_head": head}).decode("ascii")
        if snapshot_id is None:
            self._write_comment(body)
        else:
            self.api.request("PATCH", f"issues/comments/{snapshot_id}", {"body": body})
        return doc

    def save(self, document, *, expected_revision, event_id, effect_id="", reason, evidence,
             crash_after_audit=False):
        validate_document(document)
        _check(document["control_plane_sha"] == self.control_plane_sha, "untrusted control plane")
        if expected_revision == -1:
            relevant = [c for c in self.api.pages(self.route + "?per_page=100")
                        if c.get("body", "").startswith((STATE_MARKER, AUDIT_MARKER))
                        and self.verify_writer(c, self.control_plane_sha)]
            _check(not relevant and document["revision"] == 0, "intake already exists")
            previous, snapshot_id, from_state = ZERO, None, "INTAKE"
        else:
            old, previous, snapshot_id, repair = self.load()
            _check(old["revision"] == expected_revision and document["revision"] == expected_revision + 1,
                   "revision conflict")
            _check(not repair, "repair snapshot before new transition")
            from_state = RunState.from_dict(old["run"]).state.value
            _check(document["spec"] == old["spec"] and
                   document["submission_body_digest"] == old["submission_body_digest"],
                   "active canonical spec cannot be edited")
        entry = audit_entry(document, previous, event_id=event_id, effect_id=effect_id,
                            from_state=from_state, reason=reason, evidence=evidence)
        self._write_comment(AUDIT_MARKER + "\n" + canonical(entry).decode("ascii"))
        if crash_after_audit:
            raise StateBlocked("injected crash after audit before snapshot")
        body = STATE_MARKER + "\n" + canonical({"document": document, "audit_head": entry["digest"]}).decode("ascii")
        if snapshot_id is None:
            self._write_comment(body)
        else:
            # Unknown PATCH is not retried; next load reconciles with the audit.
            self.api.request("PATCH", f"issues/comments/{snapshot_id}", {"body": body})
        return document
