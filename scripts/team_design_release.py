"""Publish the three team screens over the verified card coverage website."""
import os
from pathlib import Path
import shutil

import catalogue_package as pkg
import catalogue_promotion as prod
import team_release
import version_picker_release as picker

BASE = '029a142e35fba419605d0e46cb41a58ebbb7bd68'
VERSION = 'a88d653e-b169-47cf-be53-1eb0151ef531'
DEPLOYMENT = '90e76413-d43d-4f7a-92e5-d203540f7e51'
CHANGED = {'team-access.css', 'team-admin.js', 'team-entry.js', 'team-ui.js', 'team-workspace.js'}
ADDED = {'assets/team-harbor/'+name+'.jpg' for name in ('invitation','harbor','network','shoreline')}
PREVIOUS_PACKAGE = 'card-source-coverage'
BRANCH = 'feature/team-harbor-design'

if os.environ.get('CVEHARBOR_SITE_RELEASE') == 'account-harbor-views':
    BASE = 'd603c5084483a57a341d40b95560874fe91d354f'
    VERSION = '7880dc83-e350-449e-8f02-806cb60f7f66'
    DEPLOYMENT = '8f2c9d02-b538-42f9-92f7-374fe1e2427a'
    PREVIOUS_PACKAGE = 'team-harbor-design'
    BRANCH = 'feature/account-harbor-views'
    CHANGED = {'account/index.html', 'team-admin.js'}
    ADDED = {'account-harbor.css'} | {'assets/team-harbor/'+name+'.jpg' for name in (
        'account-beacon', 'team-beacon', 'team-coast', 'org-panorama', 'tile-profile',
        'tile-authenticator', 'tile-recovery', 'tile-notifications', 'tile-session',
        'tile-workspace', 'symbol-members', 'symbol-active', 'symbol-pending', 'symbol-team', 'symbol-inventory')}


def prepare(out):
    team_release.previous(BASE, 'session_navigation_release.py', 'prepare', out, site_release=PREVIOUS_PACKAGE)
    shutil.copytree(out/'after', out/'before', dirs_exist_ok=True)
    for name in sorted(CHANGED | ADDED):
        asset = out/'after'/name
        if name in CHANGED:
            pkg.require(asset.read_bytes() == pkg.git('show', BASE+':'+name), 'Unexpected predecessor for '+name)
        else:
            pkg.require(not asset.exists(), 'Asset already exists: '+name)
        asset.parent.mkdir(parents=True, exist_ok=True)
        asset.write_bytes(pkg.git('show', 'HEAD:'+name))


def run(action, out):
    if action == 'prepare':
        prepare(out)
        return
    prs = prod.github('/commits/'+os.environ['GITHUB_SHA']+'/pulls')
    matches = [pr['number'] for pr in prs if pr['merged_at'] and pr['base']['ref']=='main'
               and pr['head']['ref']==BRANCH]
    pkg.require(len(matches)==1, 'Expected the reviewed team design release')
    prod.evidence(matches[0])
    def ready():
        prod.ready(Path('release/team-backend-enabled.txt').read_text().strip())
    if action == 'preflight':
        prod.policy(picker.ENV)
        ready()
    elif action == 'publish':
        picker.publish(out, changed=CHANGED, added=ADDED, reviewed_pr=matches[0], ready=ready,
                       previous_version=VERSION, previous_deployment=DEPLOYMENT)
    else:
        raise ValueError(action)
