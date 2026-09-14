"""Frozen v1 bounded cumulative candidate data; never executes candidate bytes."""
import base64
import hashlib
import json
import re
from dataclasses import dataclass

WIRE_LIMIT = 65536
FILE_LIMIT = 16384
TOTAL_LIMIT = 32768
COUNT_LIMIT = 20
END_MARKER = "CANDIDATE_END_V1"
PROTECTED = ("AGENTS.md", ".ai-orchestrator.toml", ".gitattributes", ".gitmodules",
             "docs/PROJECT_CHARTER.md", "docs/PRD.md", "docs/ENGINEERING_DESIGN.md")
PROTECTED_PREFIXES = (".github/", "ai_dev_orchestrator/", "scripts/", "fixtures/")
IDENTITY_KEYS = {"run_id", "round_id", "attempt", "base_sha", "input_sha", "spec_digest",
                 "expected_revision", "expected_branch", "effect_id"}


class TransportBlocked(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def hash_bytes(value):
    return hashlib.sha256(value).hexdigest()


def _check(condition, message):
    if not condition:
        raise TransportBlocked(message)


def _keys(value, keys):
    _check(type(value) is dict and set(value) == set(keys), "invalid schema")


def _pairs(pairs):
    result = {}
    for k, v in pairs:
        _check(k not in result, "duplicate JSON key")
        result[k] = v
    return result


def path_policy(path):
    _check(type(path) is str and bool(path) and len(path.encode("utf-8")) <= 240, "invalid path")
    _check(not path.startswith(("/", "~")) and ":" not in path and "\\" not in path
           and not any(ord(c) < 32 for c in path)
           and all(p not in ("", ".", "..", ".git") for p in path.split("/")), "unsafe path")
    lower = path.casefold()
    _check(lower not in {p.casefold() for p in PROTECTED}
           and not lower.startswith(tuple(p.casefold() for p in PROTECTED_PREFIXES)), "protected path")


@dataclass(frozen=True)
class Blob:
    oid: str
    mode: str
    data: bytes


def _text(data):
    _check(type(data) is bytes and b"\0" not in data, "binary content")
    try:
        data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise TransportBlocked("binary content") from None


def encode(identity, base, changes, *, allowed_paths, allowed_deletes=()):
    """changes maps every cumulative changed path to bytes or explicit None deletion."""
    operations, manifest = [], []
    for path, content in sorted(changes.items()):
        old = base.get(path)
        kind = "delete" if content is None else ("replace" if old else "add")
        operations.append({"path": path, "kind": kind, "old_blob_sha": old.oid if old else None,
                           "content_base64": None if content is None else base64.b64encode(content).decode("ascii")})
        manifest.append({"path": path, "operation": kind, "old_blob_sha": old.oid if old else None,
                         "old_mode": old.mode if old else None, "new_mode": None if content is None else "100644",
                         "new_byte_length": 0 if content is None else len(content),
                         "new_content_sha256": None if content is None else hash_bytes(content)})
    payload = {"identity": identity, "operation_count": len(operations), "changed_paths": sorted(changes),
               "file_manifest": manifest, "operations": operations}
    wire = canonical({"transport_version": 1, "payload": payload, "payload_bytes": len(canonical(payload)),
                      "transport_digest": hash_bytes(canonical(payload)), "end_marker": END_MARKER})
    decode(wire, identity, base, allowed_paths=allowed_paths, allowed_deletes=allowed_deletes)
    return wire


def decode(wire, expected_identity, base, *, allowed_paths, allowed_deletes=()):
    _check(type(wire) is bytes and len(wire) <= WIRE_LIMIT, "wire overflow")
    try:
        envelope = json.loads(wire.decode("ascii"), object_pairs_hook=_pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise TransportBlocked("invalid/truncated wire") from None
    _keys(envelope, {"transport_version", "payload", "payload_bytes", "transport_digest", "end_marker"})
    _check(type(envelope["transport_version"]) is int and envelope["transport_version"] == 1
           and envelope["end_marker"] == END_MARKER, "version/end marker")
    _check(canonical(envelope) == wire, "noncanonical wire")
    payload = envelope["payload"]
    _keys(payload, {"identity", "operation_count", "changed_paths", "file_manifest", "operations"})
    identity = payload["identity"]
    _keys(identity, IDENTITY_KEYS)
    _check(identity == expected_identity and canonical(identity) == canonical(expected_identity), "identity mismatch")
    for key in ("base_sha", "input_sha"):
        _check(type(identity[key]) is str and re.fullmatch(r"[0-9a-f]{40}", identity[key]), "invalid SHA")
    _check(type(identity["spec_digest"]) is str and re.fullmatch(r"[0-9a-f]{64}", identity["spec_digest"]), "spec digest")
    for key in ("attempt", "expected_revision"):
        _check(type(identity[key]) is int and identity[key] >= 0, "invalid identity integer")
    _check(identity["attempt"] <= 3, "attempt limit")
    for key in IDENTITY_KEYS - {"attempt", "expected_revision"}:
        _check(type(identity[key]) is str and bool(identity[key].strip()), "identity string")
    _check(re.fullmatch(r"ai-orchestrator/round-[1-9][0-9]*", identity["expected_branch"]), "unexpected ref")
    encoded = canonical(payload)
    _check(type(envelope["payload_bytes"]) is int and envelope["payload_bytes"] == len(encoded)
           and envelope["transport_digest"] == hash_bytes(encoded), "transport digest/length mismatch")
    operations, paths, manifest = payload["operations"], payload["changed_paths"], payload["file_manifest"]
    _check(all(type(v) is list for v in (operations, paths, manifest)), "expected lists")
    _check(type(payload["operation_count"]) is int
           and payload["operation_count"] == len(operations) == len(paths) == len(manifest)
           and 0 < len(paths) <= COUNT_LIMIT, "count limit/no-op")
    for path in paths:
        path_policy(path)
    _check(paths == sorted(set(paths)) and len({p.casefold() for p in paths}) == len(paths), "duplicate/unsorted paths")
    changes = {}
    total = 0
    for path, op, meta in zip(paths, operations, manifest):
        _keys(op, {"path", "kind", "old_blob_sha", "content_base64"})
        _keys(meta, {"path", "operation", "old_blob_sha", "old_mode", "new_mode",
                     "new_byte_length", "new_content_sha256"})
        _check(path in allowed_paths and op["path"] == meta["path"] == path, "scope/manifest path mismatch")
        old = base.get(path)
        for other, blob in base.items():
            _check(not (other.casefold() == path.casefold() and other != path), "base case collision")
            _check(not path.startswith(other + "/") and not other.startswith(path + "/"), "tree path conflict")
        for other in paths:
            _check(other == path or not path.startswith(other + "/"), "candidate path conflict")
        if old:
            _check(old.mode == "100644", "mode/symlink/gitlink")
            _text(old.data)
        _check(op["old_blob_sha"] == meta["old_blob_sha"] == (old.oid if old else None), "old blob mismatch")
        kind = op["kind"]
        _check(kind in ("add", "replace", "delete") and meta["operation"] == kind, "operation mismatch")
        if kind == "delete":
            _check(old is not None and path in allowed_deletes and op["content_base64"] is None, "unauthorized deletion")
            data = None
        else:
            _check((old is None) == (kind == "add"), "add/replace mismatch")
            _check(type(op["content_base64"]) is str, "missing candidate bytes")
            try:
                data = base64.b64decode(op["content_base64"], validate=True)
            except (ValueError, UnicodeError):
                raise TransportBlocked("invalid base64") from None
            _check(base64.b64encode(data).decode("ascii") == op["content_base64"], "noncanonical base64")
            _text(data)
            _check(len(data) <= FILE_LIMIT and (old is None or old.data != data), "file limit/no-op")
            total += len(data)
        expected_meta = {"path": path, "operation": kind, "old_blob_sha": old.oid if old else None,
                         "old_mode": old.mode if old else None, "new_mode": None if data is None else "100644",
                         "new_byte_length": 0 if data is None else len(data),
                         "new_content_sha256": None if data is None else hash_bytes(data)}
        _check(canonical(meta) == canonical(expected_meta), "independent manifest mismatch")
        changes[path] = data
    _check(total <= TOTAL_LIMIT, "total text overflow")
    return changes
