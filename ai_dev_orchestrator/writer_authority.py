"""Platform job-log write receipts, not self-asserted run URLs.

Only completed allowlisted control jobs can attest a comment id + exact body
digest. A process may read back its own successful writes before its job closes.
Missing/expired logs fail closed. This uses no signing secret or OIDC capability.
"""
import base64
import json
import os
import re

from .candidate_transport import canonical, hash_bytes
from .github_state import StateBlocked, STATE_MARKER, AUDIT_MARKER

RECEIPT = 'ORCHESTRATOR_WRITE_RECEIPT '
WRITERS = {'orchestrator-intake.yml': ('intake',),
           'orchestrator-attempt.yml': ('controller', 'gate')}


def check(condition, reason):
    if not condition:
        raise StateBlocked(reason)


def inventory_policy(inventory, expected, default_permissions):
    check(default_permissions.get('default_workflow_permissions') == 'read',
          'unsafe repository default workflow permission')
    check(inventory == expected, 'workflow inventory/permission surface drift')
    return {'status': 'PASS', 'model': 'platform-job-log-receipts',
            'default_workflow_permissions': default_permissions,
            'workflow_inventory': inventory, 'allowed_issue_writers': WRITERS}


def verify_source(api, binding, cp):
    repo = api.get('')
    check(repo['default_branch'] == binding.branch, 'default branch drift')
    branch = api.get('branches/' + binding.branch)
    check(branch['protected'] and branch['commit']['sha'] == cp, 'protected control source drift')
    tree = api.get('git/trees/' + cp + '?recursive=1')
    check(not tree.get('truncated'), 'incomplete control inventory')
    blobs = {x['path']: x for x in tree['tree'] if x['type'] == 'blob'}
    manifest = api.get('git/blobs/' + blobs['.r2-source.json']['sha'])
    files = json.loads(base64.b64decode(manifest['content']))['files']
    workflows = {p for p in blobs if p.startswith('.github/workflows/')}
    check(workflows == {p for p in files if p.startswith('.github/workflows/')}, 'unknown workflow')
    check(set(binding.workflows) <= workflows, 'missing control workflow')
    for p in workflows:
        item = api.get('git/blobs/' + blobs[p]['sha'])
        raw = base64.b64decode(item['content'])
        check(hash_bytes(raw) == files[p], 'workflow digest drift')
    # Every install is exact; a new default SHA requires a new review/test target.
    return {'control_plane_sha': cp, 'workflow_inventory': sorted(workflows), 'status': 'PASS'}


class ReceiptAuthority:
    def __init__(self, api, binding, cp):
        self.api, self.binding, self.cp = api, binding, cp
        self.local = set()
        self.receipts = {}
        self.checked = False

    def preflight(self):
        if not self.checked:
            verify_source(self.api, self.binding, self.cp)
            self.checked = True

    def __call__(self, comment, expected_cp):
        if comment.get('user', {}).get('login') != 'github-actions[bot]' or comment.get('user', {}).get('id') != 41898282:
            return False
        self.preflight()
        check(expected_cp == self.cp, 'receipt control SHA')
        key = (comment['id'], hash_bytes(comment['body'].encode()))
        if key in self.local:
            return True
        raw = json.loads(comment['body'].split('\n', 1)[1])
        provenance = raw.get('_writer')
        check(type(provenance) is dict and set(provenance) == {'run_id', 'attempt', 'job'},
              'bot comment missing platform receipt identity')
        run_id, attempt, job_name = (provenance[k] for k in ('run_id', 'attempt', 'job'))
        check(str(run_id).isdecimal() and str(attempt).isdecimal(), 'invalid receipt run')
        cache_key = (str(run_id), str(attempt), job_name)
        if cache_key not in self.receipts:
            run = self.api.get(f'actions/runs/{run_id}/attempts/{attempt}')
            path = run['path']
            check(path in self.binding.workflows and run['head_sha'] == self.cp
                  and run['head_branch'] == self.binding.branch and run['event'] == 'workflow_dispatch', 'untrusted receipt workflow')
            check(job_name in WRITERS.get(path.rsplit('/', 1)[-1], ()), 'non-writer job receipt')
            jobs = self.api.get(f'actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100')
            check(jobs['total_count'] <= 100, 'job inventory truncated')
            match = [j for j in jobs['jobs'] if j['name'] == job_name and j['status'] == 'completed']
            check(len(match) == 1, 'writer job not completed/unique')
            log = self.api.job_logs(match[0]['id'])
            receipts = set()
            for line in log.splitlines():
                # Platform timestamp then exact marker. Ignore echoed commands/env/untrusted JSON.
                m = re.fullmatch(r'\d{4}-\d\d-\d\dT\S+Z ' + RECEIPT + r'(\{.*\})', line)
                if m:
                    value = json.loads(m[1])
                    if value.get('repository') == self.binding.repository and value.get('control_plane_sha') == self.cp:
                        receipts.add((value['comment_id'], value['body_digest']))
            self.receipts[cache_key] = receipts
        check(key in self.receipts[cache_key], 'comment has no matching trusted job write receipt')
        return True

    def get(self, route):
        return self.api.get(route)

    def pages(self, route):
        self.preflight()
        return self.api.pages(route)

    def _body(self, body):
        marker, value = body.split('\n', 1)
        data = json.loads(value)
        data['_writer'] = {'run_id': os.environ['GITHUB_RUN_ID'],
                           'attempt': os.environ['GITHUB_RUN_ATTEMPT'], 'job': os.environ['GITHUB_JOB']}
        return marker + '\n' + canonical(data).decode()

    def request(self, method, route, payload=None):
        self.preflight()
        body = payload.get('body', '') if payload else ''
        if method in ('POST', 'PATCH') and body.startswith((STATE_MARKER, AUDIT_MARKER)):
            workflow = os.environ.get('GITHUB_WORKFLOW_REF', '').split('@')[0].rsplit('/', 1)[-1]
            check(os.environ.get('GITHUB_JOB') in WRITERS.get(workflow, ()), 'not a state writer job')
            check(os.environ.get('GITHUB_SHA') == self.cp and
                  os.environ.get('GITHUB_REPOSITORY') == self.binding.repository, 'write context mismatch')
            body = self._body(body)
            result, headers = self.api.request(method, route, dict(payload, body=body))
            check(result.get('body') == body, 'write response mismatch')
            key = (result['id'], hash_bytes(body.encode()))
            self.local.add(key)
            print(RECEIPT + canonical({'repository': self.binding.repository, 'control_plane_sha': self.cp,
                                      'comment_id': key[0], 'body_digest': key[1]}).decode(), flush=True)
            return result, headers
        return self.api.request(method, route, payload)

    def mutate_once(self, method, route, payload, reconcile):
        # If response is lost before receipt, authority is unknown: never invent a receipt.
        return self.request(method, route, payload)[0]
