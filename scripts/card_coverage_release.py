"""Publish the shared installed-version coverage changes over the verified Team & Access site."""
import json
import os
from pathlib import Path
import shutil
import time

import catalogue_package as pkg
import catalogue_promotion as prod
import team_release
import version_picker_release as picker

SITE = '9e89f410eb1c5a80ddfc0f526e1ed20c5faa6aca'
VERSION = 'a0cef238-ecdc-417f-be98-fdec4628fc81'
DEPLOYMENT = '038d4511-2a0e-46f0-8767-3d7195ec1670'
WORKER_MODULES = ('site-gate/version-scan.mjs', 'site-gate/catalogue-history.mjs', 'site-gate/vendor-scan.mjs')


def prepare(out):
    team_release.previous(SITE, 'session_navigation_release.py', 'prepare', out, site_release='team-access')
    shutil.copytree(out/'after', out/'before', dirs_exist_ok=True)
    for path in (picker.MODULE, *WORKER_MODULES):
        target = out/('after' if path == picker.MODULE else 'source')/path
        pkg.require(target.read_bytes() == pkg.git('show', SITE+':'+path), 'Unexpected site baseline for '+path)
        target.write_bytes(pkg.git('show', 'HEAD:'+path))


def ready():
    identities = {Path('release/team-backend-'+state+'.txt').read_text().strip() for state in ('enabled','disabled')}
    with prod.request('https://api.cveharbor.com/v1/release-readiness?coverage='+str(time.time_ns())) as response:
        state = json.load(response)
    pkg.require(state.get('ready') is True and state.get('schema') == 'phase1-integrity-recovery-v1'
                and state.get('release') in identities, 'Unexpected account backend readiness')


def run(action, out):
    if action == 'prepare':
        prepare(out)
        return
    prs = prod.github('/commits/'+os.environ['GITHUB_SHA']+'/pulls')
    matches = [pr['number'] for pr in prs if pr['merged_at'] and pr['base']['ref'] == 'main'
               and pr['head']['ref'] == 'fix/card-source-coverage']
    pkg.require(len(matches) == 1, 'Missing reviewed card coverage release')
    prod.evidence(matches[0])
    if action == 'preflight':
        prod.policy(picker.ENV)
        ready()
    elif action == 'publish':
        picker.publish(out, changed={picker.MODULE}, reviewed_pr=matches[0], ready=ready,
                       previous_version=VERSION, previous_deployment=DEPLOYMENT)
    else:
        raise ValueError(action)
