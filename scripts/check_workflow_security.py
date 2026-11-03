#!/usr/bin/env python3
"""Fail closed on workflow credential-boundary regressions; no network operations.

This is a review aid, not a replacement for GitHub environment and branch rules.
Old branch revisions remain unsafe while repository/org production secrets exist.
"""
import json
import re
import subprocess
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
MAIN = "github.repository == 'Prat007ai/cveharbor' && github.ref == 'refs/heads/main'"
MANUAL = MAIN + " && github.event_name == 'workflow_dispatch'"
RELEASE = MAIN + " && vars.PRODUCTION_DEPLOYMENTS_ENABLED == 'true'"
PHASE1 = 'd791cb8e84f85f980926dd1e1acfd0b369c64b46'
ENVIRONMENTS = {'cloudflare-worker-production', 'cloudflare-site-production', 'github-pages',
                'cloudflare-production-audit', 'cloudflare-notifications-production', 'cloudflare-phase1-staging', 'cloudflare-intelligence-data'}
SECRET_BOUNDARIES = {
    'cloudflare-intelligence-data': {'FEED_R2_ACCESS_KEY_ID','FEED_R2_SECRET_ACCESS_KEY'},
    'cloudflare-worker-production': {'CVEHARBOR_PROD_WORKER_TOKEN', 'CVEHARBOR_PROD_ACCOUNT_ID'},
    'cloudflare-site-production': {'CVEHARBOR_PROD_SITE_TOKEN', 'CVEHARBOR_PROD_ACCOUNT_ID', 'CVEHARBOR_SITE_GATE_PASSWORD'},
    'github-pages': {'CVEHARBOR_SITE_GATE_PASSWORD'},
    'cloudflare-production-audit': {'CLOUDFLARE_AUDIT_API_TOKEN', 'CLOUDFLARE_AUDIT_ACCOUNT_ID', 'CVEHARBOR_SITE_GATE_PASSWORD'},
    'cloudflare-notifications-production': {'CVEHARBOR_PROD_SMTP2GO_API_KEY'},
    'cloudflare-phase1-staging': {'CLOUDFLARE_STAGING_API_TOKEN', 'CLOUDFLARE_STAGING_ACCOUNT_ID'},
}
SENSITIVE = re.compile(r'secrets\.(?:FEED_R2_\w+|CLOUDFLARE_\w+|CF_\w+|CVEHARBOR_\w+|SITE_GATE_PASSWORD|(?:ALERT_)?SMTP2GO_API_KEY)')

class StrictLoader(yaml.SafeLoader):
    pass

def mapping(loader, node, deep=False):
    result = {}
    for key, value in node.value:
        key = loader.construct_object(key, deep=deep)
        if key in result:
            raise ValueError(f'duplicate YAML key: {key}')
        result[key] = loader.construct_object(value, deep=deep)
    return result

StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)

def load_workflow(text):
    doc = yaml.load(text, Loader=StrictLoader)
    if True in doc:  # GitHub uses YAML 1.2; PyYAML's default treats "on" as boolean.
        doc['on'] = doc.pop(True)
    return doc

def validate(doc, filename):
    errors = []
    def require(ok, message):
        if not ok: errors.append(message)
    events = doc.get('on', {})
    require(isinstance(events, dict), 'explicit event mapping required')
    require(not set(events).intersection({'pull_request_target','workflow_run'}), 'privileged trigger requires separate security review')
    require(doc.get('permissions') == {'contents':'read'}, 'workflow token must default to contents: read only')
    require(not SENSITIVE.search(json.dumps(doc.get('env', {}))), 'no workflow-wide production secrets')
    for name, job in doc.get('jobs', {}).items():
        label = filename + '/' + name
        raw = json.dumps(job)
        env = job.get('environment')
        env = env.get('name') if isinstance(env, dict) else env
        condition = job.get('if', '')
        require(job.get('runs-on') == 'ubuntu-latest', label + ': use an isolated hosted runner')
        require('uses' not in job, label + ': reusable credential forwarding requires separate review')
        require('secrets[' not in raw and 'toJSON(secrets)' not in raw and 'toJson(secrets)' not in raw,
                label + ': dynamic or bulk secret access is forbidden')
        permissions = job.get('permissions', doc['permissions'])
        require(isinstance(permissions, dict), label + ': explicit permissions required')
        if isinstance(permissions, dict):
            require(all(value != 'write' or key in {'pages','id-token'} and env in {'github-pages','cloudflare-site-production'}
                        for key,value in permissions.items()), label + ': repository/Actions write permissions are forbidden')
        require(not re.search(r'git\s+push\b', raw), label + ': publish evidence as artifacts, never push repository code')
        if SENSITIVE.search(raw): require(env in ENVIRONMENTS, label + ': privileged secrets need an approved environment')
        if env:
            require(env in ENVIRONMENTS, label + ': unknown or dynamic environment')
            requested = {m.group().split('.', 1)[1] for m in SENSITIVE.finditer(raw)}
            require(requested <= SECRET_BOUNDARIES.get(env, set()), label + ': credential is outside the environment boundary')
            prefix = MANUAL if filename == 'recovery-write-hold.yml' and name == 'control' else MAIN + " && vars.FEED_PUBLICATION_ENABLED == 'true'" if env == 'cloudflare-intelligence-data' else MANUAL if env in {'cloudflare-production-audit','cloudflare-notifications-production','cloudflare-phase1-staging'} else RELEASE
            require(condition == prefix or condition.startswith(prefix + ' && '), label + ': explicit main/event/release guard required')
            # The only extra ORs allowed are bootstrap's grouped event allowlist.
            require('||' not in condition or filename == 'bootstrap.yml' and name == 'sync' and condition == RELEASE + " && (github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && inputs.deploy == true))", label + ': guard may not be bypassed with OR')
        if env == 'cloudflare-intelligence-data':
            require(filename == 'publish-intelligence.yml' and name == 'collect', label + ': data credential caller not allowed')
            require('PRODUCTION_DEPLOYMENTS_ENABLED' not in condition and 'needs' not in job, label + ': feed cannot depend on application release')
            require(not re.search(r'wrangler|deploy_site_gate|git push|d1 execute|SMTP2GO', raw), label + ': feed job cannot deploy, mutate D1 or send mail')
        if env == 'cloudflare-phase1-staging':
            require(not re.search(r'secrets\.(?:CLOUDFLARE_(?!STAGING_)|CVEHARBOR_)', raw), label + ': staging may only request distinct staging credentials')
        if env == 'cloudflare-production-audit':
            require(not re.search(r'secrets\.CLOUDFLARE_(?!AUDIT_)', raw), label + ': diagnostics must use audit credentials')
            require(not re.search(r'--remote|wrangler[^\n]*deploy(?![^\n]*--dry-run)|secret put|bootstrap_cvie_shared', '\n'.join(s.get('run','') for s in job.get('steps',[]))), label + ': deployment/migration command in read-only job')
        if env == 'cloudflare-notifications-production':
            require("vars.PRODUCTION_EMAIL_TESTS_ENABLED == 'true'" in condition, label + ': real mail requires explicit opt-in')
        for step in job.get('steps', []):
            use = step.get('uses', '')
            require(bool(use) != ('run' in step), label + ': each step must have exactly one of uses or run')
            if 'run' in step:
                shell_source = re.sub(r'\$\{\{.*?\}\}', 'github_expression', step['run'])
                parsed = subprocess.run(['bash', '-n'], input=shell_source, text=True, capture_output=True)
                require(parsed.returncode == 0 and not parsed.stderr, label + ': invalid shell/heredoc syntax: ' + parsed.stderr.strip())
            if use:
                require(bool(re.fullmatch(r'actions/[\w-]+(?:/(?:restore|save))?@[a-f0-9]{40}', use)), label + ': action must be pinned to a reviewed commit')
            if use.startswith('actions/checkout@'):
                opts = step.get('with', {})
                require(opts.get('persist-credentials') is False, label + ': checkout must not persist token')
                ref = opts.get('ref')
                require(ref in (None, '${{ github.sha }}') or ref == PHASE1 and filename in {'security-phase1-audit.yml','security-phase1-staging.yml'}, label + ': do not check out mutable/arbitrary privileged source')
    return errors

def main():
    errors = []
    paths = sorted((ROOT/'.github/workflows').glob('*.yml'))
    for path in paths:
        try: errors.extend(validate(load_workflow(path.read_text()), path.name))
        except (ValueError,yaml.YAMLError) as exc: errors.append(path.name + ': ' + str(exc))
    if errors: raise SystemExit('\n'.join(errors))
    print(f'Workflow credential-boundary policy passed for {len(paths)} files.')

if __name__ == '__main__': main()
