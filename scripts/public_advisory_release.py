"""Publish the corrected public-source scan scopes and Veeam evidence."""
import os
from pathlib import Path
import shutil

import catalogue_package as pkg
import catalogue_promotion as prod
import team_release
import version_picker_release as picker

BASE = 'd603c5084483a57a341d40b95560874fe91d354f'
VERSION = '7880dc83-e350-449e-8f02-806cb60f7f66'
DEPLOYMENT = '8f2c9d02-b538-42f9-92f7-374fe1e2427a'
CHANGED = {picker.MODULE}
WORKER = ('version-scan.mjs','catalogue-history.mjs','veeam-bulletins.mjs')


def prepare(out):
    team_release.previous(BASE,'session_navigation_release.py','prepare',out,site_release='team-harbor-design')
    shutil.copytree(out/'after',out/'before',dirs_exist_ok=True)
    for name in (*CHANGED,*WORKER):
        path = name if name in CHANGED else 'site-gate/'+name
        target = out/('after' if name in CHANGED else 'source')/path
        if name=='veeam-bulletins.mjs':
            pkg.require(not target.exists(),'Unexpected existing Veeam module')
        else:
            pkg.require(target.read_bytes()==pkg.git('show',BASE+':'+path),'Unexpected production baseline for '+name)
        target.write_bytes(pkg.git('show','HEAD:'+path))


def run(action, out):
    if action == 'prepare':
        prepare(out)
        return
    prs = prod.github('/commits/'+os.environ['GITHUB_SHA']+'/pulls')
    matches = [pr['number'] for pr in prs if pr['merged_at'] and pr['base']['ref']=='main'
               and pr['head']['ref']=='fix/public-advisory-scopes']
    pkg.require(len(matches)==1, 'Expected the reviewed public advisory release')
    prod.evidence(matches[0])
    def ready():
        prod.ready(Path('release/team-backend-enabled.txt').read_text().strip())
    if action == 'preflight':
        prod.policy(picker.ENV)
        ready()
    elif action == 'publish':
        picker.publish(out, changed=CHANGED, reviewed_pr=matches[0], ready=ready,
                       previous_version=VERSION, previous_deployment=DEPLOYMENT)
    else:
        raise ValueError(action)
