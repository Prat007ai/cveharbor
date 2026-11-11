"""Build only the daily-history UI over the currently serving website."""
from pathlib import Path
import shutil
import sys
import os
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import production_release_checks as checks
import version_picker_release as publisher

BASE = '6a1d9b5a31e71b5712c8dcd5e65b57ed424aadb1'
CHANGED = {'workspace/index.html', 'workspace-dashboard.js', 'workspace-dashboard.css'}
VERSION = '0fe1de38-7ac4-4d62-9d60-d82008dc33aa'
DEPLOYMENT = '8576166b-0402-485a-842b-bb4c3d01139c'

def prepare(out):
    pkg.require(not out.exists(), 'Use a new package directory')
    team.previous(BASE, 'session_navigation_release.py', 'prepare', out, site_release='workspace-overview')
    shutil.copytree(out / 'after', out / 'before', dirs_exist_ok=True)
    for name in sorted(CHANGED):
        target = out / 'after' / name
        pkg.require(target.read_bytes() == pkg.git('show', BASE + ':' + name), 'Unexpected Workspace predecessor: ' + name)
        target.write_bytes(Path(name).read_bytes())
    before, after = pkg.files(out / 'before'), pkg.files(out / 'after')
    pkg.require(before == after, 'Asset inventory changed')
    pkg.require({p for p in before if (out/'before'/p).read_bytes() != (out/'after'/p).read_bytes()} == CHANGED, 'Unexpected website delta')

def ready():
    prod.ready(Path('release/workspace-history-backend.txt').read_text(encoding='utf-8').strip())

def run(action,out):
    if action=='prepare':
        prepare(out)
        return
    pr=team.reviewed('feature/workspace-daily-history')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required main checks incomplete')
    if action=='preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action=='publish':
        publisher.publish(out,changed=CHANGED,reviewed_pr=pr,ready=ready,
                          previous_version=VERSION,previous_deployment=DEPLOYMENT,served_copy=out/'verified-origin')
    else:
        raise ValueError(action)

if __name__ == '__main__':
    prepare(Path(sys.argv[1]).resolve())
