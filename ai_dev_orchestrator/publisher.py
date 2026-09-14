"""Trusted Git-object reconstruction and guarded ordinary publication.

No candidate checkout execution, hooks, filters, tests, or executable manifests.
"""
import os
import base64
from pathlib import Path
import re
import subprocess

from .candidate_transport import Blob, TransportBlocked, decode


class PublicationBlocked(RuntimeError):
    pass


class Publisher:
    def __init__(self, checkout):
        self.checkout = Path(checkout).resolve()
        if not (self.checkout / ".git").is_dir() or (self.checkout / ".git").is_symlink():
            raise PublicationBlocked("fresh trusted Git checkout required")
        self.env = {k: v for k, v in os.environ.items()
                    if not k.upper().startswith(("GIT_", "GH_", "GITHUB_", "OPENAI_"))}
        self.env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                         "GIT_TERMINAL_PROMPT": "0", "GIT_ALLOW_PROTOCOL": "https",
                         "GIT_AUTHOR_NAME": "R2 Synthetic Publisher", "GIT_AUTHOR_EMAIL": "r2@example.invalid",
                         "GIT_COMMITTER_NAME": "R2 Synthetic Publisher", "GIT_COMMITTER_EMAIL": "r2@example.invalid",
                         "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
                         "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00"})

    def git(self, *args, data=None, extra_env=None):
        env = {**self.env, **(extra_env or {})}
        result = subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull,
            "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false",
            "-c", "core.fsmonitor=false", *args], cwd=self.checkout, env=env,
            input=data, capture_output=True, timeout=30)
        if result.returncode:
            raise PublicationBlocked("Git operation failed; reconcile before any retry")
        return result.stdout

    def tree(self, ref):
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            raise PublicationBlocked("full SHA required")
        result = {}
        for record in self.git("ls-tree", "-r", "-z", ref).split(b"\0"):
            if not record:
                continue
            info, raw_path = record.split(b"\t", 1)
            mode, kind, oid = info.decode("ascii").split()
            path = raw_path.decode("utf-8", "strict")
            data = self.git("cat-file", "blob", oid) if kind == "blob" else b""
            result[path] = Blob(oid, mode, data)
        return result

    def reconstruct(self, wire, identity, *, allowed_paths, allowed_deletes=()):
        base = self.tree(identity["base_sha"])
        self.git("cat-file", "-e", identity["input_sha"] + "^{commit}")
        changes = decode(wire, identity, base, allowed_paths=allowed_paths, allowed_deletes=allowed_deletes)
        self.git("read-tree", identity["base_sha"])
        for path, content in changes.items():
            oid = "0" * 40 if content is None else self.git("hash-object", "-w", "--stdin", data=content).decode().strip()
            mode = "0" if content is None else "100644"
            self.git("update-index", "-z", "--index-info",
                     data=f"{mode} {oid}\t{path}\0".encode("utf-8"))
        tree_sha = self.git("write-tree").decode().strip()
        rebuilt = self.tree(tree_sha)
        observed = {p for p in set(base) | set(rebuilt) if base.get(p) != rebuilt.get(p)}
        if observed != set(changes):
            raise TransportBlocked("reconstructed changed paths mismatch")
        for path, content in changes.items():
            if content is None:
                if path in rebuilt:
                    raise TransportBlocked("deletion mismatch")
            elif rebuilt[path].data != content or rebuilt[path].mode != "100644":
                raise TransportBlocked("reconstructed bytes/mode mismatch")
        message = f"R2 candidate effect {identity['effect_id']}\n"
        sha = self.git("commit-tree", tree_sha, "-p", identity["input_sha"], data=message.encode()).decode().strip()
        return sha, tree_sha

    def publish(self, candidate_sha, identity, api, token, *, control_plane_sha, dry_run=False):
        if not all(type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value)
                   for value in (candidate_sha, control_plane_sha, identity.get("input_sha"), identity.get("base_sha"))):
            raise PublicationBlocked("full verified SHA required")
        if dry_run or api.dry_run:
            return {"planned_candidate_sha": candidate_sha, "branch": identity["expected_branch"]}
        if api.repository != "zynis/ai-dev-orchestrator-r2-fixture":
            raise PublicationBlocked("R2 only authorizes the dedicated fixture")
        branch = identity["expected_branch"]
        if not re.fullmatch(r"ai-orchestrator/round-[1-9][0-9]*", branch):
            raise PublicationBlocked("unexpected target ref")
        if api.get("git/ref/heads/main")["object"]["sha"] != control_plane_sha:
            raise PublicationBlocked("control plane changed")
        # This GET must succeed and identify an active update restriction.
        # A 403 (including private-repository plan restrictions) stops publication.
        rules = api.get("rules/branches/main")
        if not isinstance(rules, list) or not any(r.get("type") == "update" for r in rules):
            raise PublicationBlocked("server protection unverified")
        from .github_api import GitHubError
        def remote_head():
            try:
                return api.get("git/ref/heads/" + branch)["object"]["sha"]
            except GitHubError as exc:
                if exc.status == 404:
                    return None
                raise
        head = remote_head()
        if head == candidate_sha:
            return {"candidate_sha": candidate_sha, "adopted": True}
        if head not in (None, identity["input_sha"]) or (head is None and identity["input_sha"] != identity["base_sha"]):
            raise PublicationBlocked("unexpected branch head")
        parent = self.git("rev-parse", candidate_sha + "^").decode().strip()
        if parent != identity["input_sha"]:
            raise PublicationBlocked("candidate parent mismatch")
        authorization = base64.b64encode(("x-access-token:" + token).encode()).decode("ascii")
        env = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.extraHeader",
               "GIT_CONFIG_VALUE_0": "Authorization: Basic " + authorization}
        try:
            self.git("push", "https://github.com/" + api.repository + ".git",
                     candidate_sha + ":refs/heads/" + branch, extra_env=env)
        except PublicationBlocked:
            if remote_head() != candidate_sha:
                raise PublicationBlocked("unknown publication outcome; no retry") from None
        if remote_head() != candidate_sha:
            raise PublicationBlocked("published SHA not verified")
        return {"candidate_sha": candidate_sha, "adopted": False}
