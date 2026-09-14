import argparse
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import time

from .candidate_transport import canonical, encode, hash_bytes
from .domain import (
    BoundResult, Delivery, Drift, Event, EventKind, Finding, Outcome, ReviewAccess,
    ReviewResult, RunState, Severity, State,
)
from .github_api import GitHubAPI, GitHubError
from .github_controller import Controller, canonical_submission
from .github_state import GitHubStateStore, StateBlocked, new_document, parse_comment, STATE_MARKER, AUDIT_MARKER
from .publisher import Publisher, PublicationBlocked

from .project_binding import ProjectBinding
from .github_runtime import require, output, summary, verify_artifact, issue_body

REPO = "zynis/ai-dev-orchestrator-r2-fixture"
OWNER = "zynis"
OWNER_ID = "30803451"
BOT = "github-actions[bot]"
WORKFLOWS = {".github/workflows/orchestrator-intake.yml",
             ".github/workflows/orchestrator-attempt.yml", ".github/workflows/orchestrator-recovery.yml"}
SCENARIOS = {"happy", "fix", "duplicate", "crash", "mutable", "hostile", "concurrent",
             "access", "dispatch-loss", "sit-fail"}
ISSUE_MARKER = "<!-- r2-control/v1 -->"
PR_MARKER = "<!-- r2-implementation/v1 -->"
VALUE_PATH = "synthetic_project/value.txt"


CONFIG = '''
schema_version = 1
[project]
name = "R2 synthetic fixture"
repository = "zynis/ai-dev-orchestrator-r2-fixture"
[platform]
agent_os = "linux"
sit_os = ["linux"]
[review]
required = true
independent = true
read_only = true
blocking_severities = ["P0", "P1"]
[[sit.commands]]
id = "integer"
command = "python3 synthetic_project/test_value.py"
shell = "bash"
timeout_seconds = 30
artifacts = ["reports/result.json"]
'''


def binding():
    return ProjectBinding(REPO, OWNER, OWNER_ID, "main", tuple(sorted(WORKFLOWS)),
                          "ai-orchestrator/round-", CONFIG, "r2-synthetic-v1")

def scenario(plan):
    return plan["spec"]["goal"].split("scenario=")[1]

class FixtureAdapter:
    executor_identity = 'mock-executor-job'
    reviewer_identity = 'mock-reviewer-job'

    def review_result(self, review, candidate, digest, evidence):
        return ReviewResult(candidate,digest,
            Outcome.BLOCKED if review['access'] != 'PASS' else Outcome(review['outcome']),
            evidence,self.reviewer_identity,True,0,int(review['p1']),0,
            (self.finding(review),) if review['p1'] else ())

    @staticmethod
    def submission(request, cp, binding, evidence):
        require(set(request) == {"submission_id", "parameters", "dry_run"}, "intake schema")
        sub = request["submission_id"]
        require(type(sub) is str and re.fullmatch(r"[a-z0-9-]{1,48}", sub), "submission ID")
        scenario = json.loads(request["parameters"])["scenario"]
        require(scenario in SCENARIOS and type(request["dry_run"]) is bool, "unsupported synthetic scenario")
        spec = {"submission_id":sub, "run_id":"r2-"+sub, "round_id":sub, "spec_revision":1,
                "target_repository":REPO, "base_sha":cp, "control_plane_sha":cp,
                "goal":"Synthetic value must equal 2; scenario=" + scenario, "background":"R2 fixture only",
                "in_scope":[VALUE_PATH], "out_of_scope":["all other paths"],
                "invariants":["No merge, provider, secret or business project"],
                "acceptance_criteria":["value=2"], "validation":["integer SIT then exact-value mock review"],
                "git_requirements":"one branch and draft PR", "review_access":"exact candidate SHA",
                "stop_conditions":["body edit stops"], "planner_identity":OWNER,
                "authorization_evidence":evidence}
        return sub, spec

    @staticmethod
    def after_start(doc, sub, cp):
        if 'scenario=concurrent' in doc['spec']['goal']:
            for n in (1, 2):
                doc['pending']['reconcile-'+sub+'-'+str(n)] = {'kind':'RECONCILE','attempt':0,
                    'expected_sha':cp,'event_id':'reconcile-'+str(n)}

    @staticmethod
    def after_intake(api, issue, spec):
        if 'scenario=mutable' in spec['goal'] and not issue['body'].endswith('\nUNTRUSTED BODY EDIT'):
            api.request('PATCH', f"issues/{issue['number']}", {'body':issue_body(spec)+'\nUNTRUSTED BODY EDIT'})

    @staticmethod
    def after_publish(plan):
        if scenario(plan) == 'crash' and not plan['recovered']:
            raise RuntimeError('INJECTED: branch/PR created; completion not persisted')

    @staticmethod
    def after_dispatch(runtime, api, cp, doc, eid, item, recovery, sent):
        goal=doc['spec']['goal']
        if 'scenario=duplicate' in goal and item['kind']=='START_FIX' and not recovery:
            sent.append(runtime.dispatch_one(api,cp,doc,eid,item))
        if 'scenario=dispatch-loss' in goal and item['kind']=='START_FIX' and not recovery:
            raise RuntimeError('INJECTED dispatch success then sender failure')

    @staticmethod
    def finding(review):
        return Finding('R2-SPEC-001',Severity.P1,Drift.CONTRADICTS,VALUE_PATH,
            'value must be 2','integer but business target wrong','set value to 2','repeat SIT and mock review')

    @staticmethod
    def mock_execute():
        plan = json.loads(os.environ["PLAN"])
        require(plan["control_plane_sha"] == os.environ["GITHUB_SHA"], "mock control source")
        ident = plan["identity"]
        value = b"1\n" if scenario(plan) in ("fix","duplicate","dispatch-loss") and ident["attempt"] == 0 else b"2\n"
        if scenario(plan) == "sit-fail" and ident["attempt"] == 0:
            value = b"not-an-integer\n"
        pub = Publisher(Path.cwd())
        wire = encode(ident,pub.tree(ident["base_sha"]),{VALUE_PATH:value},allowed_paths={VALUE_PATH})
        output("transport",wire.decode("ascii"))

    @staticmethod
    def sit():
        plan = json.loads(os.environ["PLAN"])
        candidate = os.environ["CANDIDATE_SHA"]
        root = Path(os.environ["CANDIDATE_DIR"]).resolve()
        env = {k:v for k,v in os.environ.items() if not k.startswith(("GH_","GITHUB_","ACTIONS_","RUNNER_"))
               and k not in ("PLAN","CANDIDATE_SHA","CANDIDATE_DIR","PYTHONPATH")}
        env.update({"GIT_TERMINAL_PROMPT":"0","GIT_CONFIG_GLOBAL":os.devnull,"GIT_CONFIG_NOSYSTEM":"1",
                    "SAFE_REPO":REPO,"SAFE_SHA":candidate,"SAFE_RUN":os.environ["GITHUB_RUN_ID"]})
        try:
            test = subprocess.run(["python3","synthetic_project/test_value.py"],cwd=root,env=env,
                                  capture_output=True,text=True,timeout=30)
            sit_outcome = "PASS" if test.returncode == 0 else "FAIL"
            exit_code = test.returncode
        except subprocess.TimeoutExpired:
            sit_outcome, exit_code = "BLOCKED", None
        hostile = None
        if scenario(plan) == "hostile":
            probe = subprocess.run(["python3","synthetic_project/hostile_probe.py"],cwd=root,env=env,
                                   capture_output=True,text=True,timeout=90)
            require(probe.returncode == 0,"hostile capability probe failed")
            hostile = json.loads(probe.stdout)
        report = {"candidate_sha":candidate,"spec_digest":plan["identity"]["spec_digest"],"outcome":sit_outcome,
                  "exit_code":exit_code,"positive_control":sit_outcome == "PASS","hostile":hostile}
        content = canonical(report).decode()
        artifact = {"path":"reports/result.json","content":content,"size":len(content),"digest":hash_bytes(content.encode())}
        output("report",artifact)
        output("outcome",sit_outcome)
        summary(report)

    @staticmethod
    def mock_review():
        plan = json.loads(os.environ["PLAN"])
        report = verify_artifact(json.loads(os.environ["SIT_REPORT"]))
        candidate = os.environ["CANDIDATE_SHA"]
        require(report["candidate_sha"] == candidate and report["spec_digest"] == plan["identity"]["spec_digest"],"SIT binding")
        rejected = 0
        for path in ("../escape",".git/config","/tmp/secret","home/.ssh/key"):
            bad = dict(json.loads(os.environ["SIT_REPORT"]),path=path)
            try: verify_artifact(bad)
            except StateBlocked: rejected += 1
        require(rejected == 4,"artifact negative policy")
        value = (Path(os.environ["CANDIDATE_DIR"])/VALUE_PATH).read_text().strip()
        result = {"candidate_sha":candidate,"spec_digest":plan["identity"]["spec_digest"],
                  "access":"BLOCKED" if scenario(plan) == "access" else "PASS",
                  "outcome":"PASS" if value == "2" else "FAIL","p1":value != "2",
                  "artifact_negative_tests":rejected}
        output("review",result)
        summary(result)

