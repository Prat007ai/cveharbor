"""Responsive CVIE updates on verified PR357."""
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

BASE = 'f4128d1a83ad8d1d37f4ae2fc7f2fcb41c2526d4'
CHANGED = {'cvie.js', 'inventory.js', 'customer-security.js', 'app.js', 'finding-ai.js'}


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
        if name == 'cvie.js':
            # Main retains unreleased bounded-history state; production does not.
            # Insert only cache cleanup into each version's existing cleanup.
            marker = b'function clearPrivate(){'
            cleanup = marker+b'merge.cache=null;merge.snapshot=null;'
            pkg.require(original.count(marker)==1 and served.count(marker)==1 and revised.count(cleanup)==1,
                        'Unexpected CVIE cleanup structure')
            revised = revised.replace(cleanup, marker)
            served = served.replace(marker, cleanup)
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
    pr = team.reviewed('fix/cvie-ui-performance')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required application/security checks incomplete')
    if action == 'preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action == 'publish':
        publisher.publish(out, changed=CHANGED, added=set(), reviewed_pr=pr, ready=ready,
                          previous_version='ed41a3ef-49c8-4e67-89e5-93af8835028f',
                          previous_deployment='3cb3b722-b22c-4338-81ec-34689ca9c440',
                          served_copy=out / 'verified-origin')
    else:
        raise ValueError(action)


if __name__ == '__main__':
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
