"""Overlay the dashboard matching fix on the exact PR350 production release."""
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

BASE = 'd713715467756c2a9f8747209afd12a129ef967f'
CHANGED = {'inventory-assessment.js'}


def prepare(out):
    with tempfile.TemporaryDirectory() as temp:
        prior = Path(temp) / 'predecessor'
        pkg.git('-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(prior), BASE)
        try:
            shutil.copytree('collector-app/package', prior / 'collector-app/package', dirs_exist_ok=True)
            subprocess.run([sys.executable, 'scripts/inventory_actions_release.py', 'prepare', str(out)],
                           cwd=prior, check=True, env={**os.environ, 'GITHUB_SHA': BASE})
        finally:
            pkg.git('worktree', 'remove', '--force', str(prior))
    shutil.rmtree(out / 'before')
    shutil.copytree(out / 'after', out / 'before')
    for name in CHANGED:
        original = pkg.git('show', BASE + ':' + name)
        served = (out / 'before' / name).read_bytes()
        pkg.require(served.replace(b'\r\n', b'\n') == original, 'Unexpected predecessor ' + name)
        (out / 'after' / name).write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
    pkg.require(pkg.files(out / 'before') == pkg.files(out / 'after'), 'Asset inventory changed')
    delta = {name for name in pkg.files(out / 'before')
             if (out / 'before' / name).read_bytes() != (out / 'after' / name).read_bytes()}
    pkg.require(delta == CHANGED, 'Unexpected dashboard release contents')


def ready():
    prod.ready('332f5e1d6ad2d59e9615f42d63bab4b83426e6b217fd70c13f8667766f64df08')


def run(action, out):
    if action == 'prepare':
        return prepare(out)
    pr = team.reviewed('fix/dashboard-responsiveness')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required application/security checks incomplete')
    if action == 'preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action == 'publish':
        publisher.publish(out, changed=CHANGED, added=set(), reviewed_pr=pr, ready=ready,
                          previous_version='f511ccb5-b560-47fc-a6ec-8ba4d604b551',
                          previous_deployment='8ce32b4a-5a84-4ebd-91f3-5a942795b079',
                          served_copy=out / 'verified-origin')
    else:
        raise ValueError(action)


if __name__ == '__main__':
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
