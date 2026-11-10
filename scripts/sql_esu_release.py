"""Release the SQL ESU empty-state message on the verified production website."""
import os
import shutil
from pathlib import Path

import catalogue_package as pkg
import catalogue_promotion as prod
import team_release
import version_picker_release as picker


def run(action, out):
    if action == 'prepare':
        team_release.previous(team_release.SITE, 'session_navigation_release.py', 'prepare', out)
        shutil.copytree(out/'after', out/'before', dirs_exist_ok=True)
        asset = out/'after'/picker.MODULE
        pkg.require(asset.read_bytes() == pkg.git('show', team_release.SITE+':'+picker.MODULE),
                    'Unexpected production picker baseline')
        asset.write_bytes(pkg.git('show', 'HEAD:'+picker.MODULE))
        return
    sha = os.environ['GITHUB_SHA']
    matches = [p['number'] for p in prod.github('/commits/'+sha+'/pulls') if p['merged_at']
               and p['base']['ref'] == 'main' and p['head']['ref'] == 'fix/sql-esu-release-baseline']
    pkg.require(len(matches) == 1, 'Expected the reviewed SQL coverage change')
    prod.evidence(matches[0])
    def ready():
        prod.ready(Path('release/team-backend-disabled.txt').read_text().strip())

    if action == 'preflight':
        prod.policy(picker.ENV)
        ready()
    elif action == 'publish':
        picker.publish(out, changed={picker.MODULE}, reviewed_pr=matches[0], ready=ready,
                       previous_version='559aed2e-95b5-4b4c-834a-244fd4c3dcc0',
                       previous_deployment='a9c36b6f-1ada-4584-a70b-5de33098457d')
    else:
        raise ValueError(action)
