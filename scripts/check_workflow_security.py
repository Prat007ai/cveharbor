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
REPAIR_WRITE = MANUAL + " && contains(fromJSON('[\"install\",\"resume\"]'), inputs.operation)"
REPAIR_READ = MANUAL + " && contains(fromJSON('[\"preflight\",\"verify\",\"reconcile\"]'), inputs.operation)"
RELEASE = MAIN + " && vars.PRODUCTION_DEPLOYMENTS_ENABLED == 'true'"
CATALOGUE = MANUAL + " && inputs.catalogue_commit == github.sha && inputs.deploy == false && github.run_attempt == 1 && vars.PRODUCTION_DEPLOYMENTS_ENABLED != 'true'"
PHASE1 = 'd791cb8e84f85f980926dd1e1acfd0b369c64b46'
STAGING_RELEASE = "github.repository == 'Prat007ai/cveharbor' && github.ref == 'refs/heads/codex/cvie-core-phase012' && ((github.event_name == 'workflow_dispatch' && inputs.operation != 'none') || (github.event_name == 'push' && github.run_attempt > 1 && contains(github.event.head_commit.message, '[staging-release]')))"
RECOVERY_SELECTOR = "((github.event_name == 'workflow_dispatch' && startsWith(inputs.operation, 'recovery-')) || (github.event_name == 'push' && contains(github.event.head_commit.message, '[staging-recovery]')))"
STAGING_RECOVERY = STAGING_RELEASE + " && " + RECOVERY_SELECTOR
STAGING_NORMAL = STAGING_RELEASE + " && !" + RECOVERY_SELECTOR
SIMPLE_STAGING = 'github.repository == \'Prat007ai/cveharbor\' && github.ref == \'refs/heads/main\' && github.event_name == \'workflow_dispatch\' && vars.SIMPLE_STAGING_ENABLED == \'true\' && inputs.candidate_operation == \'none\' && contains(fromJSON(\'["diagnose","readiness"]\'), inputs.simple_operation)'
CANDIDATE_STAGING = "github.repository == 'Prat007ai/cveharbor' && github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch' && vars.CF_STAGING_CANDIDATE_ENABLED == 'true' && vars.SIMPLE_STAGING_ENABLED == 'false' && inputs.candidate_operation != 'none'"
CATALOGUE_ENV = 'cloudflare-catalogue-42411365289'
ENVIRONMENTS = {'cloudflare-cvie-staging','cloudflare-worker-production', 'cloudflare-site-production', CATALOGUE_ENV, 'github-pages',
                'cloudflare-production-audit', 'cloudflare-notifications-production', 'cloudflare-phase1-staging', 'cloudflare-intelligence-data'}
SECRET_BOUNDARIES = {
    'cloudflare-cvie-staging': {'CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID','CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY','CF_STAGING_RECOVERY_ISOLATION','CF_STAGING_RECOVERY_RESTORE_RECEIPT','CF_STAGING_RECOVERY_RESTORE_SIGNATURE','CF_STAGING_RECOVERY_EVIDENCE','CF_STAGING_R2_ACCESS_KEY_ID','CF_STAGING_R2_SECRET_ACCESS_KEY','CF_STAGING_API_TOKEN','CF_STAGING_ACCOUNT_ID','CF_STAGING_ACCESS_ISSUER','CF_STAGING_ACCESS_AUD','CF_STAGING_ACCESS_CLIENT_ID','CF_STAGING_ACCESS_CLIENT_SECRET'},
    'cloudflare-intelligence-data': {'FEED_R2_ACCESS_KEY_ID','FEED_R2_SECRET_ACCESS_KEY'},
    'cloudflare-worker-production': {'CVEHARBOR_PROD_WORKER_TOKEN', 'CVEHARBOR_PROD_ACCOUNT_ID', 'CVEHARBOR_PROD_REPAIR_AUTHORIZATION', 'CVEHARBOR_PROD_REPAIR_EVIDENCE'},
    'cloudflare-site-production': {'CVEHARBOR_PROD_SITE_TOKEN', 'CVEHARBOR_PROD_ACCOUNT_ID', 'CVEHARBOR_SITE_GATE_PASSWORD'},
    CATALOGUE_ENV: {'CVEHARBOR_PROD_SITE_TOKEN', 'CVEHARBOR_PROD_ACCOUNT_ID', 'CVEHARBOR_SITE_GATE_PASSWORD'},
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
    publishers = {'deploy-worker-code.yml':'deploy','deploy-account-worker.yml':'deploy','activate-confirmation-domain.yml':'activate','bootstrap.yml':'sync'}
    if filename in publishers:
        jobs=doc.get('jobs',{})
        gate=jobs.get('release-ready',{})
        require(jobs.get(publishers[filename],{}).get('needs')=='release-ready' or jobs.get(publishers[filename],{}).get('needs')==['validate','release-ready'], filename+': production must depend on exact-commit application and security checks')
        runners=[s for s in gate.get('steps',[]) if s.get('run')=='python scripts/production_release_checks.py']
        require(len(runners)==1 and 'if' not in runners[0] and runners[0].get('env')=={'GH_TOKEN':'${{ github.token }}'} and not runners[0].get('continue-on-error'), filename+': production checks must run and succeed')
        require(gate.get('permissions')=={'contents':'read','actions':'read'} and not gate.get('environment'), filename+': check CI before production credentials/approval')
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
        catalogue_job = filename == 'bootstrap.yml' and name == 'catalogue-publish'
        require((env == CATALOGUE_ENV) == catalogue_job, label + ': one-time owner review is exclusive to the catalogue publisher')
        if env:
            require(env in ENVIRONMENTS, label + ': unknown or dynamic environment')
            requested = {m.group().split('.', 1)[1] for m in SENSITIVE.finditer(raw)}
            require(requested <= SECRET_BOUNDARIES.get(env, set()), label + ': credential is outside the environment boundary')
            prefix = REPAIR_WRITE if filename == 'production-compatibility-repair.yml' and name == 'change' else (CANDIDATE_STAGING if name == 'customer-candidate' else SIMPLE_STAGING if name == 'automatic-staging' else STAGING_RECOVERY if name == 'recovery' else STAGING_NORMAL) if env == 'cloudflare-cvie-staging' else MANUAL if filename == 'recovery-write-hold.yml' and name == 'control' else MAIN + " && vars.FEED_PUBLICATION_ENABLED == 'true'" if env == 'cloudflare-intelligence-data' else MANUAL if env in {'cloudflare-production-audit','cloudflare-notifications-production','cloudflare-phase1-staging'} else RELEASE
            if filename == 'session-navigation.yml' and name == 'publish':
                prefix = MANUAL + " && inputs.reviewed_commit == github.sha && github.run_attempt == 1 && vars.PRODUCTION_DEPLOYMENTS_ENABLED != 'true'"
                require(condition == prefix and env == 'cloudflare-site-production' and job.get('needs') == 'check',
                        label + ': reviewed SHA, production site environment and package checks required')
                require(job.get('concurrency') == {'group':'cveharbor-production-release','cancel-in-progress':False},
                        label + ': shared production release lock required')
                for step in job['steps']:
                    if SENSITIVE.search(json.dumps(step)):
                        require(step.get('run') == 'python scripts/session_navigation_release.py publish "$RUNNER_TEMP/catalogue"',
                                label + ': secrets restricted to the reviewed session publisher')
            if catalogue_job:
                prefix = CATALOGUE
                require(condition == CATALOGUE and job.get('needs') == 'catalogue-check',
                        label + ': exact manual catalogue gate and staging receipt required')
                require(job.get('concurrency') == {'group': 'cveharbor-production-release', 'cancel-in-progress': False},
                        label + ': shared production release lock required')
                for step in job['steps']:
                    if SENSITIVE.search(json.dumps(step)):
                        require(step.get('run') == 'python scripts/catalogue_promotion.py publish "$RUNNER_TEMP/catalogue"',
                                label + ': production secrets belong only to the catalogue publisher')
            if requested.intersection({'CVEHARBOR_PROD_REPAIR_AUTHORIZATION','CVEHARBOR_PROD_REPAIR_EVIDENCE'}):
                require(filename == 'production-compatibility-repair.yml' and name == 'change', label + ': repair evidence is exclusive to the repair executor')
            require(condition == prefix or condition.startswith(prefix + ' && '), label + ': explicit main/event/release guard required')
            # The only extra ORs allowed are bootstrap's grouped event allowlist.
            require('||' not in condition or env == 'cloudflare-cvie-staging' and filename == 'cvie-staging.yml' and name in {'release','recovery','automatic-staging','customer-candidate'} and condition == (CANDIDATE_STAGING if name == 'customer-candidate' else SIMPLE_STAGING if name == 'automatic-staging' else STAGING_RECOVERY if name == 'recovery' else STAGING_NORMAL) or filename == 'bootstrap.yml' and name == 'sync' and condition == RELEASE + " && (github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && inputs.deploy == true && !inputs.catalogue_commit))", label + ': guard may not be bypassed with OR')
        if env == 'cloudflare-cvie-staging':
            require(filename == 'cvie-staging.yml' and name in {'release','recovery','automatic-staging','customer-candidate'} and condition == (CANDIDATE_STAGING if name == 'customer-candidate' else SIMPLE_STAGING if name == 'automatic-staging' else STAGING_RECOVERY if name == 'recovery' else STAGING_NORMAL), label + ': only reviewed staging release caller is permitted')
            require(job.get('needs') == 'prepare', label + ': credential-free preparation required first')
            require('scripts/provision.mjs' not in raw and 'create-database' not in raw, label + ': initial provisioning is retired')
            if name == 'customer-candidate':
                require(job.get('concurrency') == {'group':'cveharbor-permanent-staging','cancel-in-progress':False}, label + ': serialize candidate operations')
                require(sum(s.get('run') == 'node staging/scripts/customer-candidate-execute.mjs' for s in job.get('steps',[])) == 1, label + ': one candidate entrypoint')
                for step in job.get('steps',[]):
                    if step.get('run') != 'node staging/scripts/customer-candidate-execute.mjs':
                        require(not SENSITIVE.search(json.dumps(step)), label + ': build without credentials')
            if name == 'automatic-staging':
                require(condition == SIMPLE_STAGING, label + ': automatic staging must be trusted main and opt-in')
                require(job.get('concurrency') == {'group':'cveharbor-permanent-staging','cancel-in-progress':False}, label + ': serialize staging writes')
                require('CF_STAGING_RECOVERY_EVIDENCE' not in raw and 'RECOVERY_R2' not in raw and 'CF_STAGING_APPROVED_COMMIT' not in raw, label + ': routine staging must derive source and not require manual recovery secrets')
                require(sum(s.get('run') == 'node staging/scripts/simple-release.mjs' for s in job.get('steps',[])) == 1, label + ': one reviewed staging entrypoint required')
            if name == 'release':
                require(not requested.intersection({'CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID','CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY','CF_STAGING_RECOVERY_ISOLATION','CF_STAGING_RECOVERY_RESTORE_RECEIPT','CF_STAGING_RECOVERY_RESTORE_SIGNATURE'}), label + ': recovery-only credentials cannot enter the release job')
                runners = [s for s in job.get('steps', []) if s.get('run') == 'node staging/scripts/release.mjs']
                expected_guards = {"env.CF_STAGING_PROVISION_ACTION == 'diagnose-schema'", "env.CF_STAGING_PROVISION_ACTION == 'adopt-schema'", "env.CF_STAGING_PROVISION_ACTION == 'migrate'", "env.CF_STAGING_PROVISION_ACTION != 'diagnose-schema' && env.CF_STAGING_PROVISION_ACTION != 'adopt-schema' && env.CF_STAGING_PROVISION_ACTION != 'migrate'"}
                require(len(runners) == 4 and {s.get('if') for s in runners} == expected_guards, label + ': diagnostic/adoption/migration/general dispatch must be exclusive')
                for step in runners:
                    if step.get('if') == "env.CF_STAGING_PROVISION_ACTION == 'adopt-schema'":
                        require(step.get('env') == {'CF_STAGING_API_TOKEN': '${{ secrets.CF_STAGING_API_TOKEN }}', 'CF_STAGING_RECOVERY_EVIDENCE': '${{ secrets.CF_STAGING_RECOVERY_EVIDENCE }}'}, label + ': adoption receives only staging D1 credential and private recovery evidence')
                    if step.get('if') == "env.CF_STAGING_PROVISION_ACTION == 'migrate'":
                        expected = {'CF_STAGING_API_TOKEN': '${{ secrets.CF_STAGING_API_TOKEN }}',
                                    'CF_STAGING_RECOVERY_EVIDENCE': '${{ secrets.CF_STAGING_RECOVERY_EVIDENCE }}',
                                    'CF_STAGING_ACCESS_ISSUER': '${{ vars.CF_STAGING_ACCESS_ISSUER || secrets.CF_STAGING_ACCESS_ISSUER }}',
                                    'CF_STAGING_ACCESS_AUD': '${{ vars.CF_STAGING_ACCESS_AUD || secrets.CF_STAGING_ACCESS_AUD }}',
                                    'CF_STAGING_ACCESS_CLIENT_ID': '${{ secrets.CF_STAGING_ACCESS_CLIENT_ID }}',
                                    'CF_STAGING_ACCESS_CLIENT_SECRET': '${{ secrets.CF_STAGING_ACCESS_CLIENT_SECRET }}'}
                        require(step.get('env') == expected, label + ': migration receives only staging D1/Access credentials and private recovery evidence')
            if name == 'recovery':
                require(job.get('concurrency') == {'group':'cveharbor-permanent-staging','cancel-in-progress':False}, label + ': recovery must serialize with staging mutations')
                require(job.get('timeout-minutes') == 30, label + ': bounded recovery window required')
                require(not re.search(r'upload-artifact|actions/cache|release\.mjs|wrangler|migrat|deploy|publish-synthetic', raw, re.I), label + ': recovery cannot upload artifacts/cache or enter release paths')
                allowed = {'CF_STAGING_ACCOUNT_ID','CF_STAGING_API_TOKEN','CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID','CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY','CF_STAGING_RECOVERY_ISOLATION','CF_STAGING_RECOVERY_RESTORE_RECEIPT','CF_STAGING_RECOVERY_RESTORE_SIGNATURE','CF_STAGING_ACCESS_CLIENT_ID','CF_STAGING_ACCESS_CLIENT_SECRET'}
                require(requested <= allowed, label + ': recovery cannot use publisher/deployment credentials')
                inventory = [s for s in job.get('steps',[]) if s.get('name') == 'Inspect staging recovery inventory only']
                require(len(inventory)==1 and inventory[0].get('if')=="env.CF_STAGING_PROVISION_ACTION == 'recovery-inventory'" and inventory[0].get('env')=={'CF_STAGING_API_TOKEN':'${{ secrets.CF_STAGING_API_TOKEN }}'} and inventory[0].get('run')=='node staging/recovery/recovery.mjs', label + ': inventory credential/dispatch boundary')
                require(any(s.get('run')=='node staging/recovery/recovery.mjs --check' and not s.get('env') for s in job.get('steps',[])), label + ': recovery requires credential-free source authorization')
                require(any('sudo swapoff -a' in s.get('run','') and not s.get('env') for s in job.get('steps',[])), label + ': recovery plaintext must not be swapped')
                runners = [s for s in job.get('steps',[]) if s.get('run')=='node staging/recovery/recovery.mjs']
                private_guard = "env.CF_STAGING_PROVISION_ACTION == 'recovery-snapshot' || env.CF_STAGING_PROVISION_ACTION == 'recovery-capture' || env.CF_STAGING_PROVISION_ACTION == 'recovery-verify'"
                require(len(runners)==2 and {s.get('if') for s in runners}=={"env.CF_STAGING_PROVISION_ACTION == 'recovery-inventory'",private_guard}, label + ': exclusive recovery operation dispatch required')
                expected_private = {'CF_STAGING_API_TOKEN':'${{ secrets.CF_STAGING_API_TOKEN }}',
                    'CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID':'${{ secrets.CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID }}',
                    'CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY':'${{ secrets.CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY }}',
                    'CF_STAGING_RECOVERY_CERT_PEM':'${{ vars.CF_STAGING_RECOVERY_CERT_PEM }}',
                    'CF_STAGING_RECOVERY_ISOLATION':'${{ secrets.CF_STAGING_RECOVERY_ISOLATION }}',
                    'CF_STAGING_RECOVERY_RESTORE_RECEIPT':'${{ secrets.CF_STAGING_RECOVERY_RESTORE_RECEIPT }}',
                    'CF_STAGING_RECOVERY_RESTORE_SIGNATURE':'${{ secrets.CF_STAGING_RECOVERY_RESTORE_SIGNATURE }}',
                    'CF_STAGING_ACCESS_CLIENT_ID':'${{ secrets.CF_STAGING_ACCESS_CLIENT_ID }}',
                    'CF_STAGING_ACCESS_CLIENT_SECRET':'${{ secrets.CF_STAGING_ACCESS_CLIENT_SECRET }}'}
                for step in job.get('steps',[]):
                    if step.get('if')==private_guard:
                        require(step.get('env')==expected_private and step.get('run')=='node staging/recovery/recovery.mjs', label + ': private recovery credential boundary')
                    elif step.get('name')!='Inspect staging recovery inventory only':
                        require(not SENSITIVE.search(json.dumps(step)), label + ': credential-free setup/cleanup required')

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
            # Credential-free probes can still access production. A PR event must
            # never execute the live confirmation-host checker; its .test.mjs
            # counterpart uses fixtures and remains allowed.
            if 'pull_request' in events and re.search(r'\bscripts/verify_confirmation_domain\.mjs(?:\s|$)', step.get('run', '')):
                main_job = (condition == MAIN or condition.startswith(MAIN + ' && ')) and '||' not in condition
                main_step = step.get('if') == MAIN + " && github.event_name == 'push'"
                require(main_job or main_step, label + ': live production confirmation probes must be excluded from PRs')
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
    if filename == 'production-compatibility-repair.yml':
        require(set(events)=={'workflow_dispatch'}, 'repair: manual dispatch only')
        require(doc.get('concurrency')=={'group':'cveharbor-production-release','cancel-in-progress':False}, 'repair: shared production concurrency required')
        jobs=doc.get('jobs',{})
        require(set(jobs)=={'validate','inspect','change'}, 'repair: exact three jobs required')
        for name,guard,environment in [('inspect',REPAIR_READ,'cloudflare-production-audit'),('change',REPAIR_WRITE,'cloudflare-worker-production')]:
            job=jobs.get(name,{})
            require(job.get('if')==guard and job.get('environment')==environment and job.get('needs')=='validate', 'repair: exact operation/approval boundary')
            require(job.get('timeout-minutes')==15,'repair: bounded execution')
            require(job.get('permissions')=={'contents':'read','actions':'read'},'repair: environment inspection uses read-only permissions')
            steps=job.get('steps',[])
            require(len(steps)==3 and steps[-1].get('run')=='node deployment/proposals/production-compatibility/procedure/execute.mjs','repair: single reviewed entrypoint')
            if name=='change':
                require(steps[-1].get('env',{}).get('PRODUCTION_COMPATIBILITY_REPAIR_ENABLED')=='${{ vars.PRODUCTION_COMPATIBILITY_REPAIR_ENABLED }}','repair: environment enable flag must reach runtime authorization')
                require('if' not in steps[-1] and not steps[-1].get('continue-on-error',False),'repair: disabled runtime must fail, not skip or ignore authorization')
            for step in steps[:-1]:require(not SENSITIVE.search(json.dumps(step)),'repair: setup must be credential-free')
            require(not re.search(r'upload-artifact|actions/cache|continue-on-error|wrangler|restore|deploy', '\n'.join(s.get('run', '')+s.get('uses','') for s in steps).replace('deployment/proposals/','proposal/')), 'repair: no public private-data artifacts, retry or deployment tools')
    return errors

def main():
    errors = []
    paths = sorted(p for p in (ROOT / '.github/workflows').iterdir() if p.suffix in {'.yaml', '.yml'})
    for path in paths:
        try: errors.extend(validate(load_workflow(path.read_text()), path.name))
        except (ValueError,yaml.YAMLError) as exc: errors.append(path.name + ': ' + str(exc))
    if errors: raise SystemExit('\n'.join(errors))
    print(f'Workflow credential-boundary policy passed for {len(paths)} files.')

if __name__ == '__main__': main()
