#!/usr/bin/env python3
"""Read GitHub configuration metadata using an existing authenticated gh session.

GET only. Never requests secret values, creates resources, changes settings, or runs
workflows. Output deliberately projects selected metadata rather than raw responses.
Run from an administrator's authorized network; do not pass tokens as arguments.
"""
import json
import re
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote

REPO = 'Prat007ai/cveharbor'
BASE = 'repos/' + REPO

def gh_get(endpoint):
    allowed = (
        r'user', re.escape(BASE), re.escape(BASE) + r'/branches/main',
        re.escape(BASE) + r'/rulesets(?:/\d+)?',
        re.escape(BASE) + r'/environments(?:/[^/?]+(?:/(?:secrets|deployment-branch-policies))?)?',
        re.escape(BASE) + r'/actions/(?:secrets|permissions/(?:workflow|selected-actions)|permissions)',
    )
    if not any(re.fullmatch(pattern, endpoint) for pattern in allowed):
        raise ValueError('Endpoint is not on the metadata audit allowlist')
    try:
        result = subprocess.run(['gh', 'api', '--method', 'GET', '--paginate', '--slurp', endpoint],
                                capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None, 'CLI unavailable or metadata request timed out'
    if result.returncode:
        status = re.search(r'HTTP\s+(\d{3})', result.stderr)
        return None, 'Metadata unavailable' + (' (HTTP ' + status[1] + ')' if status else '')
    try:
        pages = json.loads(result.stdout)
        return pages if isinstance(pages, list) else [pages], None
    except ValueError:
        return None, 'Invalid metadata response'

def collect(get=gh_get):
    unavailable = []
    def request(path):
        pages, error = get(path)
        if error:
            unavailable.append({'endpoint':path, 'reason':error})
            return None
        return pages
    def one(path):
        pages = request(path)
        return pages[0] if pages and isinstance(pages[0], dict) else {}
    def items(path, key=None):
        pages = request(path)
        if pages is None: return None
        return [entry for page in pages for entry in (page.get(key, []) if key else page)]
    def secrets(path):
        rows = items(path, 'secrets')
        return None if rows is None else [{'name':r.get('name'), 'updated_at':r.get('updated_at')} for r in rows]

    user = one('user')
    repo = one(BASE)
    branch = one(BASE + '/branches/main')
    rules = items(BASE + '/rulesets')
    rule_details = []
    for rule in rules or []:
        detail = one(BASE + '/rulesets/' + str(rule['id']))
        rule_details.append({
            'name':detail.get('name'), 'enforcement':detail.get('enforcement'),
            'target':detail.get('target'), 'conditions':detail.get('conditions'),
            'bypass_actors':detail.get('bypass_actors'),
            'rules':[{'type':r.get('type'), 'parameters':r.get('parameters')} for r in detail.get('rules',[])],
        })
    environment_rows = items(BASE + '/environments', 'environments')
    environments = []
    for row in environment_rows or []:
        name = row['name']
        path = BASE + '/environments/' + quote(name, safe='')
        detail = one(path)
        policies = items(path + '/deployment-branch-policies', 'branch_policies')
        protection = []
        for rule in detail.get('protection_rules', []):
            protection.append({
                'type':rule.get('type'), 'prevent_self_review':rule.get('prevent_self_review'),
                'wait_timer':rule.get('wait_timer'),
                'reviewers':[{'type':r.get('type'), 'login_or_slug':r.get('reviewer',{}).get('login') or r.get('reviewer',{}).get('slug')}
                             for r in rule.get('reviewers',[])],
            })
        environments.append({'name':name, 'protection_rules':protection,
            'can_admins_bypass':detail.get('can_admins_bypass'),
            'deployment_branch_policy':detail.get('deployment_branch_policy'),
            'allowed_refs':None if policies is None else [{'name':r.get('name'), 'type':r.get('type')} for r in policies],
            'secret_metadata':secrets(path + '/secrets')})
    workflow_permissions = one(BASE + '/actions/permissions/workflow')
    actions = one(BASE + '/actions/permissions')
    plan = user.get('plan') or {}
    # /user describes the caller, which may be a collaborator rather than the owner.
    owner = repo.get('owner', {})
    owner_plan = bool(user.get('login') and owner.get('type') == 'User'
                      and user['login'].lower() == str(owner.get('login', '')).lower())
    return {
        'checked_at':datetime.now(timezone.utc).isoformat(), 'repository':REPO,
        'metadata_only':True, 'production_operations_executed':0,
        'plan_name':plan.get('name') if owner_plan else None,
        'plan_verified':bool(owner_plan and plan.get('name')),
        'plan_identity_matches_owner':owner_plan,
        'visibility':repo.get('visibility'), 'private':repo.get('private'),
        'owner_type':repo.get('owner',{}).get('type'),
        'main_protected':branch.get('protected'),
        'main_legacy_protection':branch.get('protection'),
        'rulesets':None if rules is None else rule_details,
        'repository_secret_metadata':secrets(BASE + '/actions/secrets'),
        'environments':None if environment_rows is None else environments,
        'workflow_permissions':{k:workflow_permissions.get(k) for k in ('default_workflow_permissions','can_approve_pull_request_reviews')},
        'actions_policy':{k:actions.get(k) for k in ('enabled','allowed_actions')},
        'unavailable':unavailable,
        'limitations':['Null or unavailable metadata is not proof of absence.',
                      'Secret metadata establishes location, not token value, validity or Cloudflare scope.',
                      'This audit does not prove deployed runtime health or simulate enforcement.'],
    }

if __name__ == '__main__':
    report = collect()
    print(json.dumps(report, indent=2))
    raise SystemExit(1 if report['unavailable'] else 0)
