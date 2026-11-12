"""Scoped AI guidance release on the verified PR351 site and PR346 backend."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import catalogue_package as pkg
import catalogue_promotion as prod
import production_release_checks as checks
import team_release as team
import version_picker_release as publisher

BASE = 'fa8c4ee940f05264e2b1af9671deb0f7ebc21aa6'
PREDECESSOR = '332f5e1d6ad2d59e9615f42d63bab4b83426e6b217fd70c13f8667766f64df08'
CHANGED = {'advisory-details.js', 'ai-admin-ui.js', 'ai-assistance-ui.js', 'admin/ai-usage/index.html',
           'ai/index.html', 'customer-dashboard/index.html', 'customer-reports/index.html',
           'customer-security.js', 'inventory-assessment.js', 'organization-security.js',
           'team-workspace.js', 'workspace/index.html'}
ADDED = {'finding-ai.js', 'finding-ai.css', 'workspace-ai.js'}
WORKER = {'account-backend/src/ai-admin.js', 'account-backend/src/ai-allowance.js', 'account-backend/src/ai-routes.js'}


def overlay(out, names):
    with tempfile.TemporaryDirectory() as temp:
        for name in sorted(names):
            old, new = Path(temp)/'old', Path(temp)/'new'
            old.write_bytes(pkg.git('show', BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
            if name == 'customer-dashboard/index.html':
                # Production already has the independently released recipient UI.
                # Preserve its two cache keys while changing this compact HTML line.
                served = (out/name).read_bytes()
                pkg.require(served.count(b'status-recipients-1') == 2 and
                            served.replace(b'status-recipients-1', b'integrity-phase1-1') == old.read_bytes(),
                            'Unexpected dashboard HTML baseline')
                (out/name).write_bytes(new.read_bytes().replace(b'integrity-phase1-1', b'status-recipients-1'))
                continue
            (out/name).write_bytes(pkg.git('merge-file', '-p', str(out/name), str(old), str(new)))


def backend(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    team.previous(BASE, 'server_network_release.py', 'backend', out)
    pkg.require(team.identity(out) == PREDECESSOR, 'Unexpected serving backend')
    before = {n: (out/n).read_bytes() for n in pkg.files(out)}
    overlay(out, WORKER)
    config = out/'account-backend/wrangler.toml'
    content = config.read_text(encoding='utf-8')
    pkg.require(content.count('[vars]\n') == 1 and 'CVEHARBOR_AI_PERSONAL_ENABLED' not in content, 'Unexpected personal AI configuration')
    config.write_bytes(content.replace('[vars]\n', '[vars]\nCVEHARBOR_AI_PERSONAL_ENABLED = "true"\n').encode('utf-8'))
    pkg.require(pkg.files(out) == before.keys(), 'Unexpected backend assets')
    pkg.require({n for n in before if before[n] != (out/n).read_bytes()} == WORKER | {'account-backend/wrangler.toml'}, 'Unexpected backend changes')
    value = team.identity(out)
    if check:
        pkg.require(value == Path('release/finding-ai-backend.txt').read_text().strip(), 'Unreviewed backend')
    else:
        Path('release/finding-ai-backend.txt').write_bytes((value+'\n').encode())
    print(value)


def prepare(out):
    pkg.require(not out.exists(), 'Use a new site directory')
    with tempfile.TemporaryDirectory() as temp:
        prior = Path(temp)/'predecessor'
        pkg.git('-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(prior), BASE)
        try:
            shutil.copytree('collector-app/package', prior/'collector-app/package', dirs_exist_ok=True)
            env = {**os.environ, 'GITHUB_SHA': BASE}
            env.pop('GITHUB_ACTIONS', None)
            subprocess.run([sys.executable, 'scripts/dashboard_responsiveness_release.py', 'prepare', str(out)], cwd=prior, env=env, check=True)
        finally:
            pkg.git('worktree', 'remove', '--force', str(prior))
    shutil.rmtree(out/'before')
    shutil.copytree(out/'after', out/'before')
    overlay(out/'after', CHANGED)
    for name in ADDED:
        pkg.require(not (out/'after'/name).exists(), 'Unexpected existing asset')
        (out/'after'/name).write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
    pkg.require(pkg.files(out/'after') - pkg.files(out/'before') == ADDED, 'Unexpected site additions')
    pkg.require({n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes() != (out/'after'/n).read_bytes()} == CHANGED, 'Unexpected site changes')


def ready():
    prod.ready(Path('release/finding-ai-backend.txt').read_text().strip())


def run(action, out):
    if action == 'prepare': return prepare(out)
    if action in ('backend', 'record'): return backend(out, action != 'record')
    pr = team.reviewed('feature/finding-ai-guidance')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required application/security checks incomplete')
    if action == 'preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action == 'publish':
        publisher.publish(out, changed=CHANGED, added=ADDED, reviewed_pr=pr, ready=ready,
                          previous_version='00b77981-fa1a-4391-9bf6-066330401d7b',
                          previous_deployment='8f0aa527-d4a9-4797-bc62-8e04d38b8fc2', served_copy=out/'verified-origin')
    else: raise ValueError(action)


if __name__ == '__main__':
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
