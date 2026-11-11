"""Isolated AI UI overlay over the verified PR337 website."""
from pathlib import Path
import tempfile
import subprocess
import shutil
import os
import sys
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import production_release_checks as checks
import version_picker_release as publisher

BASE='2f72ac9f3fb2d3d8e708ca4bc6e6f2f343584884'
VERSION='5471b3b6-eb78-4bee-a753-659e8675244f'
ADDED={'ai/index.html','admin/ai-usage/index.html','ai-common.js','ai-admin-ui.js','ai-assistance-ui.js','ai-navigation.js','ai-usage.css'}
CHANGED=ADDED|{'account/index.html','team-workspace.js'}

def prepare(out):
    pkg.require(not out.exists(),'Use a new package directory')
    with tempfile.TemporaryDirectory() as temporary:
        checkout=Path(temporary)/'base'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(checkout),BASE)
        try:
            env=dict(os.environ);env.pop('GITHUB_ACTIONS',None)
            subprocess.run([sys.executable,'scripts/workspace_history_site.py',str(out)],cwd=checkout,env=env,check=True)
        finally:pkg.git('worktree','remove','--force',str(checkout))
    shutil.copytree(out/'after',out/'before',dirs_exist_ok=True)
    for name in CHANGED:
        target=out/'after'/name
        if name not in ADDED:pkg.require(target.read_bytes()==pkg.git('show',BASE+':'+name),'Website predecessor differs: '+name)
        else:pkg.require(not target.exists(),'Unexpected existing AI asset')
        target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(Path(name).read_bytes())
    before,after=pkg.files(out/'before'),pkg.files(out/'after')
    pkg.require(set(after)-set(before)==ADDED,'Unexpected asset inventory')
    pkg.require({n for n in before if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==CHANGED-ADDED,'Unexpected site changes')

def ready():
    prod.ready(Path('release/organization-ai-backend.txt').read_text().strip())

def run(action,out):
    if action=='prepare':
        prepare(out)
        return
    pr=team.reviewed('feature/organization-ai-allowance')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required main checks incomplete')
    pkg.require(checks.check_ai_commit(os.environ['GITHUB_SHA']),'AI accounting checks incomplete')
    if action=='preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action=='publish':
        publisher.publish(out,changed=CHANGED-ADDED,added=ADDED,reviewed_pr=pr,ready=ready,
                          previous_version=VERSION,previous_deployment='c9beba0a-0541-4da5-bc9d-db98b9ca8f0e',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':prepare(Path(sys.argv[1]).resolve())
