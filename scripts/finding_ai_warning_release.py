"""Cooperative Workspace assessment on verified PR358."""
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

BASE = '25f7830e3108509a12d2622b5c8f24a46a2dc1dc'
CHANGED = {'inventory-assessment.js', 'workspace-ai.js'}


def prepare(out):
    with tempfile.TemporaryDirectory() as temp:
        prior = Path(temp) / 'predecessor'
        pkg.git('-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(prior), BASE)
        try:
            shutil.copytree('collector-app/package', prior / 'collector-app/package', dirs_exist_ok=True)
            subprocess.run([sys.executable, 'scripts/finding_ai_warning_release.py', 'prepare', str(out)],
                           cwd=prior, check=True, env={**os.environ, 'GITHUB_SHA': BASE})
        finally:
            pkg.git('worktree', 'remove', '--force', str(prior))
    shutil.rmtree(out / 'before')
    shutil.copytree(out / 'after', out / 'before')
    for name in CHANGED:
        original = pkg.git('show', BASE + ':' + name)
        served = (out / 'before' / name).read_bytes()
        revised = Path(name).read_bytes().replace(b'\r\n', b'\n')
        if served.replace(b'\r\n', b'\n') != original:
            # Preserve independently released production overlays. Apply only
            # this reviewed delta to the verified predecessor's serving bytes.
            with tempfile.TemporaryDirectory() as temp:
                old, new, live = Path(temp)/'old', Path(temp)/'new', Path(temp)/'live'
                old.write_bytes(original)
                live.write_bytes(served)
                new.write_bytes(revised)
                (out/'after'/name).write_bytes(pkg.git('merge-file', '-p', str(live), str(old), str(new)))
        else:
            pkg.require(served.replace(b'\r\n', b'\n') == original, 'Unexpected predecessor ' + name)
            (out / 'after' / name).write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
    pkg.require(pkg.files(out / 'before') == pkg.files(out / 'after'), 'Asset inventory changed')
    delta = {name for name in pkg.files(out / 'before')
             if (out / 'before' / name).read_bytes() != (out / 'after' / name).read_bytes()}
    pkg.require(delta == CHANGED, 'Unexpected dashboard release contents')


def ready():
    prod.ready('0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34')


def run(action, out):
    if action == 'prepare':
        return prepare(out)
    pr = team.reviewed('fix/workspace-priority-response')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required application/security checks incomplete')
    if action == 'preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action == 'publish':
        publisher.publish(out, changed=CHANGED, added=set(), reviewed_pr=pr, ready=ready,
                          previous_version='3964dc44-ffe1-4b94-a7c2-65b3662eb729',
                          previous_deployment='59442905-d85a-4436-aefe-7d5d5613dd50',
                          served_copy=out / 'verified-origin')
    else:
        raise ValueError(action)


if __name__ == '__main__':
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
