"""Compatibility names for the historical fixture harness; orchestration lives in github_runtime."""
from .github_runtime import *
from .r2_fixture import REPO, OWNER, OWNER_ID, binding, FixtureAdapter
runtime = GitHubRuntime(binding(), FixtureAdapter())
api_client = runtime.api_client
context = runtime.context
run_url = runtime.run_url
writer_verifier = runtime.writer_verifier
store_for = runtime.store_for
find_issue = runtime.find_issue
save_metadata = runtime.save_metadata
intake = runtime.intake
enter_attempt = runtime.enter_attempt
implementation_prs = runtime.implementation_prs
validate_pr = runtime.validate_pr
publish = runtime.publish
gate = runtime.gate
dispatch_one = runtime.dispatch_one
dispatcher = runtime.dispatcher
request_recovery = runtime.request_recovery
