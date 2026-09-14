"""Reusable GitHub orchestration. All project behavior enters through a trusted binding and adapter."""
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


BOT = "github-actions[bot]"
ISSUE_MARKER = "<!-- r2-control/v1 -->"
PR_MARKER = "<!-- r2-implementation/v1 -->"

def require(condition, reason):
    if not condition:
        raise StateBlocked(reason)

def output(name, value):
    if not isinstance(value, str):
        value = canonical(value).decode()
    require("\n" not in value and "\r" not in value, "output must be one canonical line")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(name + "=" + value + "\n")

def summary(value):
    print("R2_EVIDENCE "+json.dumps(value, sort_keys=True))
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as stream:
        stream.write("ORCHESTRATOR EVIDENCE\n\n" + json.dumps(value, sort_keys=True) + "\n")

def issue_body(spec):
    return ISSUE_MARKER + "\n" + canonical(spec).decode()

def identity_from(doc, event_id):
    pending = doc["pending"][event_id]
    run = RunState.from_dict(doc["run"])
    return {"run_id": run.run_id, "round_id": run.round_id, "attempt": pending["attempt"],
            "base_sha": run.base_sha, "input_sha": pending["expected_sha"],
            "spec_digest": run.spec_digest, "expected_revision": pending["dispatch_revision"],
            "expected_branch": doc["branch"], "effect_id": event_id}

def reserve_dispatch(doc):
    for item in doc["pending"].values():
        if item["kind"] in ("START_EXECUTOR", "START_FIX", "RECONCILE"):
            item.setdefault("dispatch_revision", doc["revision"] + 1)
    return doc

def verify_artifact(item):
    require(type(item) is dict and set(item) == {"path","content","size","digest"}, "artifact schema")
    require(item["path"] == "reports/result.json", "artifact path not allowlisted")
    raw = item["content"].encode()
    require(len(raw) <= 4096 and type(item["size"]) is int and len(raw) == item["size"]
            and hash_bytes(raw) == item["digest"], "artifact size/digest")
    return json.loads(item["content"])

class GitHubRuntime:
    def __init__(self, binding, adapter):
        self.binding, self.adapter = binding, adapter

    def api_client(self):
        return GitHubAPI(self.binding.repository, os.environ["GH_TOKEN"])

    def context(self, api):
        require(os.environ.get("GITHUB_REPOSITORY") == self.binding.repository, "unexpected repository")
        require(os.environ.get("GITHUB_REF") == "refs/heads/"+self.binding.branch, "untrusted workflow ref")
        cp = os.environ["GITHUB_SHA"]
        require(api.get("git/ref/heads/"+self.binding.branch)["object"]["sha"] == cp, "control plane drift")
        workflow_ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
        require(workflow_ref.startswith(self.binding.repository+"/") and workflow_ref.endswith("@refs/heads/"+self.binding.branch)
                and workflow_ref.split("@")[0].split(self.binding.repository + "/")[-1] in self.binding.workflows,
                "untrusted workflow")
        from .writer_authority import verify_source
        verify_source(api, self.binding, cp)
        return cp


    def run_url(self):
        return f"https://github.com/{self.binding.repository}/actions/runs/{os.environ['GITHUB_RUN_ID']}"

    def writer_verifier(self, api, cp):
        from .writer_authority import ReceiptAuthority
        return ReceiptAuthority(api, self.binding, cp)


    def store_for(self, api, issue, cp):
        authority = self.writer_verifier(api, cp)
        return GitHubStateStore(authority, issue, cp, authority)


    def find_issue(self, api, round_id):
        found = []
        for item in api.pages("issues?state=all&per_page=100"):
            if ("pull_request" in item or item.get("user",{}).get("login") != BOT
                    or not item.get("body", "").startswith(ISSUE_MARKER + "\n")):
                continue
            try:
                spec = json.loads(item["body"][len(ISSUE_MARKER)+1:].split("\n")[0])
            except ValueError:
                continue
            if spec.get("round_id") == round_id and item["user"]["login"] == BOT:
                found.append(item)
        require(len(found) == 1, "missing/duplicate control Issue")
        return found[0]

    def save_metadata(self, store, doc, reason, event_id):
        updated = copy.deepcopy(doc)
        updated["revision"] += 1
        store.save(updated, expected_revision=doc["revision"], event_id=event_id,
                   reason=reason, evidence=self.run_url())
        return updated

    def intake(self):
        api = self.api_client()
        cp = self.context(api)
        require(os.environ.get("GITHUB_ACTOR_ID") == self.binding.planner_id and os.environ.get("GITHUB_ACTOR") == self.binding.planner_login and os.environ.get("GITHUB_ACTOR") == self.binding.planner_login and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
                "PUBLIC-TRUST-01: intake requires platform Owner and explicit dispatch")
        request = json.loads(os.environ["SUBMISSION"])
        sub, spec = self.adapter.submission(request, cp, self.binding, self.run_url())
        spec = canonical_submission(spec, target_repository=self.binding.repository, base_sha=cp, planner_identity=self.binding.planner_login, authorized=True)
        if request["dry_run"]:
            api.dry_run = True
            facts = {name: len(list(api.pages(route))) for name, route in
                     (("issues","issues?state=all&per_page=100"),("comments","issues/comments?per_page=100"),
                      ("prs","pulls?state=all&per_page=100"),("refs","git/matching-refs/heads/"))}
            output("work", "false")
            summary({"dry_run":"PASS", "counts":facts, "planned":"CREATE_CONTROL_ISSUE", "mutations":0})
            return
        existing = [i for i in api.pages("issues?state=all&per_page=100")
                    if "pull_request" not in i and i.get("body","").startswith(ISSUE_MARKER+"\n")
                    and '"submission_id":"'+sub+'"' in i["body"] and i["user"]["login"] == BOT]
        require(len(existing) <= 1, "duplicate intake")
        if existing:
            issue = existing[0]
            stored = json.loads(issue["body"][len(ISSUE_MARKER)+1:])
            require(stored["goal"] == spec["goal"] and stored["base_sha"] == cp, "submission conflict")
            spec = stored
        else:
            body = issue_body(spec)
            issue = api.mutate_once("POST","issues",{"title":"Orchestrator "+sub, "body":body},
                lambda: [i for i in api.pages("issues?state=all&per_page=100") if i.get("body") == body and i["user"]["login"] == BOT])
        store = self.store_for(api, issue["number"], cp)
        comments = list(api.pages(f"issues/{issue['number']}/comments"))
        if not any(c.get("body","").startswith(AUDIT_MARKER) and c["user"]["login"] == BOT for c in comments):
            state = RunState(spec["run_id"],sub,hash_bytes(canonical(spec)),cp,cp)
            doc = new_document(state,spec,cp,issue_body(spec))
            doc["branch"] = self.binding.implementation_branch(issue["number"])
            store.save(doc,expected_revision=-1,event_id="intake-"+sub,reason="trusted intake",evidence=self.run_url())
            event = Event("start-"+sub,state.run_id,sub,EventKind.START,cp,state.spec_digest,0,self.run_url(),authorized=True)
            doc, _ = Controller(store).apply(event, expected_revision=0, actual_control_plane_sha=cp, issue_body=issue_body(spec))
            self.adapter.after_start(doc, sub, cp)
            reserve_dispatch(doc)
            doc = self.save_metadata(store,doc,"reserve explicit dispatch identities","reserve-"+sub)
        else:
            store.repair()
            doc = store.load()[0]
        self.adapter.after_intake(api, issue, spec)
        output("work", "true")
        output("round_id", sub)
        summary({"intake":"PASS","issue":issue["html_url"],"run_id":spec["run_id"],
                 "round_id":sub,"revision":doc["revision"],"control_plane_sha":cp})

    def enter_attempt(self):
        api = self.api_client()
        cp = self.context(api)
        require(os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and
                os.environ.get("GITHUB_ACTOR") in (self.binding.planner_login,BOT), "untrusted re-entry actor/event")
        request = json.loads(os.environ["REQUEST"])
        require(set(request) == {"run_id","round_id","event_id","expected_revision","expected_sha"}, "dispatch schema")
        issue = self.find_issue(api, request["round_id"])
        store = self.store_for(api,issue["number"],cp)
        doc = store.repair()
        run = RunState.from_dict(doc["run"])
        require(run.run_id == request["run_id"], "run mismatch")
        eid = request["event_id"]
        if issue["body"] != issue_body(doc["spec"]):
            event = Event("body-check-"+str(doc["revision"]), run.run_id,run.round_id,EventKind.START,
                          run.current_sha,run.spec_digest,run.auto_fix_count,self.run_url(),authorized=True)
            doc, _ = Controller(store).apply(event,expected_revision=doc["revision"],
                           actual_control_plane_sha=cp,issue_body=issue["body"])
            output("work","false")
            summary({"state":RunState.from_dict(doc["run"]).state.value,"body_conflict":True,"issue":issue["html_url"]})
            return
        if eid in doc["completed"]:
            output("work","false")
            summary({"duplicate":"ALREADY_COMPLETED","event_id":eid,"fix_count":run.auto_fix_count})
            return
        require(eid in doc["pending"], "no durable expected event")
        pending = doc["pending"][eid]
        require(str(pending["dispatch_revision"]) == str(request["expected_revision"]) and
                pending["expected_sha"] == request["expected_sha"], "dispatch reservation mismatch")
        if pending["kind"] == "RECONCILE":
            doc["completed"][eid] = {"status":"OBSERVED" if run.current_sha == request["expected_sha"] else "STALE_REJECTED",
                                     "actions_run":self.run_url()}
            del doc["pending"][eid]
            self.save_metadata(store,doc,"reconciliation signal consumed",eid)
            output("work","false")
            summary({"reconcile":eid,"logical_event":"consumed"})
            return
        require(pending["kind"] in ("START_EXECUTOR","START_FIX"), "not an execution intent")
        claimed = pending.get("claimed_run")
        recovered = bool(claimed and claimed != os.environ["GITHUB_RUN_ID"])
        if recovered:
            previous = api.get("actions/runs/"+claimed)
            require(previous["status"] == "completed" and previous["conclusion"] in ("failure","cancelled","timed_out"),
                    "previous attempt still active")
            require(pending.get("recovery_count",0) < 1, "automatic recovery limit reached")
            pending["recovery_count"] = pending.get("recovery_count",0)+1
        pending["claimed_run"] = os.environ["GITHUB_RUN_ID"]
        doc = self.save_metadata(store,doc,"claim execution intent",eid+"-claim-"+os.environ["GITHUB_RUN_ID"])
        plan = {"issue":issue["number"],"identity":identity_from(doc,eid),"spec":doc["spec"],
                "control_plane_sha":cp,"recovered":recovered}
        output("work","true")
        output("plan",plan)
        summary({"claim":eid,"recovered":recovered,"revision":doc["revision"]})

    def implementation_prs(self, prs, branch):
        return [p for p in prs if p.get("head",{}).get("ref") == branch
                and p.get("head",{}).get("repo",{}).get("full_name") == self.binding.repository]

    def validate_pr(self, pr, branch, body, candidate_sha=None):
        require(pr.get("user",{}).get("login") == BOT and pr.get("state") == "open"
                and pr.get("draft") is True and not pr.get("merged_at")
                and pr.get("body") == body
                and pr.get("head",{}).get("repo",{}).get("full_name") == self.binding.repository
                and pr.get("head",{}).get("ref") == branch
                and pr.get("base",{}).get("repo",{}).get("full_name") == self.binding.repository
                and pr.get("base",{}).get("ref") == self.binding.branch, "untrusted implementation PR association")
        if candidate_sha is not None:
            require(pr["head"]["sha"] == candidate_sha, "PR candidate SHA mismatch")

    def publish(self):
        api = self.api_client()
        cp = self.context(api)
        plan = json.loads(os.environ["PLAN"])
        require(cp == plan["control_plane_sha"], "publisher control source")
        ident = plan["identity"]
        import fnmatch
        require(ident["expected_branch"] == self.binding.implementation_branch(plan["issue"]), "publication branch binding")
        require(not any(fnmatch.fnmatchcase(path, pattern) for path in plan["spec"]["in_scope"]
                        for pattern in self.binding.config.protected_paths), "protected config scope")
        pub = Publisher(Path.cwd())
        candidate, tree = pub.reconstruct(os.environ["TRANSPORT"].encode("ascii"),ident,allowed_paths=set(plan["spec"]["in_scope"]))
        publication = pub.publish(candidate,ident,api,os.environ["GH_TOKEN"],control_plane_sha=cp,binding=self.binding)
        association = {"control_issue":plan["issue"],"run_id":ident["run_id"],"round_id":ident["round_id"],"spec_digest":ident["spec_digest"]}
        body = PR_MARKER+"\n"+canonical(association).decode()
        def existing():
            return self.implementation_prs(api.pages("pulls?state=all&per_page=100"), ident["expected_branch"])
        found = existing()
        require(len(found) <= 1, "duplicate PR")
        if found:
            pr = found[0]
            self.validate_pr(pr, ident["expected_branch"], body)
        else:
            pr = api.mutate_once("POST","pulls",{"title":"Implementation "+ident["round_id"],
                "head":ident["expected_branch"],"base":self.binding.branch,"body":body,"draft":True},
                lambda: [p for p in existing() if p["body"] == body])
        result = {"candidate_sha":candidate,"tree_sha":tree,"pr_number":pr["number"],
                  "pr_url":pr["html_url"],"adopted":publication["adopted"]}
        output("publication",result)
        output("candidate_sha",candidate)
        summary(result)
        self.adapter.after_publish(plan)


    def gate(self):
        api = self.api_client()
        cp = self.context(api)
        plan = json.loads(os.environ["PLAN"])
        publication = json.loads(os.environ["PUBLICATION"])
        report = verify_artifact(json.loads(os.environ["SIT_REPORT"]))
        review = json.loads(os.environ["REVIEW"]) if os.environ.get("REVIEW") else None
        ident = plan["identity"]
        candidate = publication["candidate_sha"]
        require(cp == plan["control_plane_sha"] and candidate == report["candidate_sha"],
                "job candidate binding")
        require(report["spec_digest"] == ident["spec_digest"], "job spec binding")
        if report["outcome"] == "PASS":
            require(review and review["candidate_sha"] == candidate and review["spec_digest"] == ident["spec_digest"],
                    "review missing or mismatched")
        require(api.get("git/ref/heads/"+ident["expected_branch"])["object"]["sha"] == candidate, "remote candidate changed")
        pr = api.get("pulls/"+str(publication["pr_number"]))
        association = {"control_issue":plan["issue"],"run_id":ident["run_id"],"round_id":ident["round_id"],
                       "spec_digest":ident["spec_digest"]}
        self.validate_pr(pr, ident["expected_branch"], PR_MARKER+"\n"+canonical(association).decode(), candidate)
        issue = api.get(f"issues/{plan['issue']}")
        store = self.store_for(api,plan["issue"],cp)
        doc = store.repair()
        require(doc["spec"] == plan["spec"], "frozen spec differs")
        controller = Controller(store)
        finding = self.adapter.finding(review) if review and review["p1"] else None
        payloads = [
            (EventKind.DELIVERY,Delivery(ident["run_id"],ident["round_id"],ident["attempt"],ident["base_sha"],
                ident["input_sha"],candidate,ident["spec_digest"],"mock-executor-job",self.run_url())),
            (EventKind.SIT,BoundResult(candidate,ident["spec_digest"],Outcome(report["outcome"]),self.run_url())),
        ]
        if report["outcome"] == "PASS":
            payloads += [
            (EventKind.ACCESS,ReviewAccess(candidate,ident["spec_digest"],Outcome(review["access"]),self.run_url(),"mock-reviewer-job")),
            (EventKind.REVIEW,ReviewResult(candidate,ident["spec_digest"],
                Outcome.BLOCKED if review["access"] != "PASS" else Outcome(review["outcome"]),
                self.run_url(),"mock-reviewer-job",True,0,int(review["p1"]),0,(finding,) if review["p1"] else ())),
            ]
        for kind,payload in payloads:
            current = RunState.from_dict(doc["run"])
            if current.state is State.HUMAN_DECISION_REQUIRED:
                break
            event = Event(ident["effect_id"]+"-"+kind.value,current.run_id,current.round_id,kind,
                          current.current_sha,current.spec_digest,current.auto_fix_count,self.run_url(),payload)
            doc, _ = controller.apply(event,expected_revision=doc["revision"],actual_control_plane_sha=cp,
                                       issue_body=issue["body"])
        doc["pr_number"] = publication["pr_number"]
        doc["completed"][ident["effect_id"]] = {"candidate_sha":candidate,"pr_number":doc["pr_number"],"run":self.run_url()}
        doc["pending"].pop(ident["effect_id"],None)
        for key in list(doc["pending"]):
            if doc["pending"][key]["kind"] not in ("START_EXECUTOR","START_FIX","RECONCILE"):
                doc["completed"][key] = {"status":"same-run dependency completed","run":self.run_url()}
                del doc["pending"][key]
        reserve_dispatch(doc)
        doc = self.save_metadata(store,doc,"complete attempt and reserve continuation",ident["effect_id"]+"-complete")
        current = RunState.from_dict(doc["run"])
        output("continue","true" if current.state is State.FIXING else "false")
        output("round_id",current.round_id)
        summary({"state":current.state.value,"revision":doc["revision"],"fix_count":current.auto_fix_count,
                 "candidate_sha":candidate,"pr":publication["pr_url"],"issue":issue["html_url"],
                 "control_plane_sha":cp})

    def dispatch_one(self, api, cp, doc, eid, item):
        run = RunState.from_dict(doc["run"])
        inputs = {"run_id":run.run_id,"round_id":run.round_id,"event_id":eid,
                  "expected_revision":str(item["dispatch_revision"]),"expected_sha":item["expected_sha"]}
        title = "Orchestrator attempt "+run.round_id+" "+eid
        def existing_runs():
            data = api.get("actions/workflows/orchestrator-attempt.yml/runs?event=workflow_dispatch&per_page=100")
            return [r for r in data["workflow_runs"] if r["display_title"] == title and r["head_sha"] == cp]
        try:
            api.request("POST","actions/workflows/orchestrator-attempt.yml/dispatches",{"ref":self.binding.branch,"inputs":inputs})
        except GitHubError as exc:
            if not exc.unknown_mutation or len(existing_runs()) != 1:
                raise
        return inputs

    def dispatcher(self, recovery=False):
        api = self.api_client()
        cp = self.context(api)
        if recovery:
            failed = api.get("actions/runs/"+os.environ["FAILED_RUN_ID"])
            for _ in range(15):
                if failed["status"] == "completed":
                    break
                time.sleep(1)
                failed = api.get("actions/runs/"+os.environ["FAILED_RUN_ID"])
            require(failed["head_sha"] == cp and failed["path"] == ".github/workflows/orchestrator-attempt.yml"
                    and failed["conclusion"] in ("failure","cancelled","timed_out")
                    and failed["actor"]["login"] in (self.binding.planner_login,BOT), "untrusted recovery signal")
            match = re.fullmatch(r"Orchestrator attempt ([a-z0-9-]+) ([a-z0-9-]+)",failed["display_title"])
            require(match,"unknown failed run identity")
            round_id = match.group(1)
        else:
            round_id = os.environ["ROUND_ID"]
        issue = self.find_issue(api,round_id)
        store = self.store_for(api,issue["number"],cp)
        doc = store.load()[0]
        if issue["body"] != issue_body(doc["spec"]):
            # Let the trusted attempt reader persist the explicit conflict state.
            pass
        sent=[]
        entries = sorted(doc["pending"].items(),key=lambda pair: pair[1]["kind"] != "RECONCILE")
        for eid,item in entries:
            if item["kind"] not in ("START_EXECUTOR","START_FIX","RECONCILE"):
                continue
            if recovery:
                runs = api.get("actions/workflows/orchestrator-attempt.yml/runs?event=workflow_dispatch&per_page=100")["workflow_runs"]
                matching = [r for r in runs if r["display_title"] == "Orchestrator attempt "+round_id+" "+eid and r["head_sha"] == cp]
                require(matching, "dispatch outcome unknown; no blind re-POST")
                if any(r["status"] != "completed" for r in matching):
                    sent.append({"event_id":eid,"adopted_active_run":True})
                    continue
            sent.append(self.dispatch_one(api,cp,doc,eid,item))
            self.adapter.after_dispatch(self, api, cp, doc, eid, item, recovery, sent)
        summary({"recovery":recovery,"dispatches":sent,"round_id":round_id})

    def request_recovery(self):
        api=self.api_client()
        self.context(api)
        api.request("POST","actions/workflows/orchestrator-recovery.yml/dispatches",
                    {"ref":self.binding.branch,"inputs":{"failed_run_id":os.environ["GITHUB_RUN_ID"]}})
        summary({"explicit_recovery_dispatch":os.environ["GITHUB_RUN_ID"]})
