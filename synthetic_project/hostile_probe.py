"""Harmless synthetic capability probes; no secrets, destructive data, or malware."""
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import urllib.error

assert os.environ["SAFE_REPO"] == "zynis/ai-dev-orchestrator-r2-fixture"
for name in ("GH_TOKEN","GITHUB_TOKEN","OPENAI_API_KEY","PRODUCTION_SECRET",
             "ACTIONS_ID_TOKEN_REQUEST_URL","ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
    assert name not in os.environ
config = subprocess.run(["git","config","--local","--get-regexp","extraheader|credential"],
                        capture_output=True,text=True)
assert not config.stdout.strip(), "checkout credential persisted"
push = subprocess.run(["git","-c","credential.helper=","push","origin",
                      "HEAD:refs/heads/hostile-denied-"+os.environ["SAFE_RUN"]],
                      capture_output=True,text=True,timeout=25)
assert push.returncode != 0, "candidate acquired Git write capability"
denied = {}
repo=os.environ["SAFE_REPO"]
for route, body in (
    ("git/refs", {"ref":"refs/heads/hostile-denied-"+os.environ["SAFE_RUN"],"sha":os.environ["SAFE_SHA"]}),
    ("issues", {"title":"DENIED synthetic hostile request"}),
    ("pulls", {"title":"DENIED","head":"main","base":"protected-sentinel"})):
    req=urllib.request.Request("https://api.github.com/repos/"+repo+"/"+route,
        data=json.dumps(body).encode(),method="POST",headers={"Accept":"application/vnd.github+json"})
    try:
        urllib.request.urlopen(req,timeout=15)
        raise AssertionError("unauthenticated write unexpectedly succeeded")
    except urllib.error.HTTPError as exc:
        assert exc.code in (401,403)
        denied[route]=exc.code
Path("not-allowlisted.txt").write_text("SYNTHETIC_NOT_EVIDENCE")
Path("reports").mkdir(exist_ok=True)
Path("reports/escape").symlink_to("../not-allowlisted.txt")
print(json.dumps({"no_write":True,"no_oidc":True,"no_secret":True,"checkout_clean":True,
                  "denied_http":denied,"unsafe_files_not_uploaded":True}))
