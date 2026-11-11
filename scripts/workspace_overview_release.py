"""Release only the reviewed Workspace presentation over the live website."""
import os
from pathlib import Path
import shutil

import catalogue_package as pkg
import catalogue_promotion as prod
import production_release_checks as checks
import team_release
import version_picker_release as publisher

BASE = 'f44bacc15906f99941591c60c10aa2bc66a1d830'
VERSION = 'cf692c90-6524-476a-83d2-ec8582e96acf'
DEPLOYMENT = '978f76c5-3cd0-4307-b74b-cee56dc84725'
BRANCH = 'feature/workspace-dark-redesign'
CHANGED = {'workspace/index.html', 'workspace-dashboard.js', 'workspace-dashboard.css'}


def prepare(out):
    team_release.previous(BASE, 'session_navigation_release.py', 'prepare', out,
                          site_release='account-responsive')
    shutil.copytree(out / 'after', out / 'before', dirs_exist_ok=True)
    for name in sorted(CHANGED):
        target = out / 'after' / name
        pkg.require(target.read_bytes() == pkg.git('show', BASE + ':' + name),
                    'Unexpected Workspace predecessor: ' + name)
        target.write_bytes(pkg.git('show', 'HEAD:' + name))
    before, after = pkg.files(out / 'before'), pkg.files(out / 'after')
    pkg.require(before == after, 'Workspace asset inventory changed')
    delta = {name for name in before if (out / 'before' / name).read_bytes() !=
             (out / 'after' / name).read_bytes()}
    pkg.require(delta == CHANGED, 'Unexpected Workspace package changes: ' + str(delta))


def ready():
    prod.ready(Path('release/cvie-refresh-backend.txt').read_text().strip())


def run(action, out):
    if action == 'prepare':
        prepare(out)
        return
    prs = prod.github('/commits/' + os.environ['GITHUB_SHA'] + '/pulls')
    matches = [p['number'] for p in prs if p['merged_at'] and p['base']['ref'] == 'main'
               and p['head']['ref'] == BRANCH]
    pkg.require(len(matches) == 1, 'Expected the reviewed Workspace PR')
    prod.evidence(matches[0])
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required main checks incomplete')
    if action == 'preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action == 'publish':
        publisher.publish(out, changed=CHANGED, reviewed_pr=matches[0], ready=ready,
                          previous_version=VERSION, previous_deployment=DEPLOYMENT,
                          served_copy=out / 'verified-origin')
    else:
        raise ValueError(action)
