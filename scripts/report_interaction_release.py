"""Scoped report responsiveness fix on the verified PR372 website."""
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

BASE = 'e4cc0870615e2d9452f4226813c074688d55fe7c'
BACKEND = 'f941196f5e69b909bc6697a4b9d195eb9767f56a3761a1c8dfe239e6b65dadd2'
CHANGED = {'inventory-assessment.js','customer-security.js'}

def prepare(out):
    pkg.require(not out.exists(), 'Use a new package directory')
    with tempfile.TemporaryDirectory() as temp:
        prior = Path(temp)/'predecessor'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),BASE)
        try:
            shutil.copytree('collector-app/package',prior/'collector-app/package',dirs_exist_ok=True)
            subprocess.run([sys.executable,'scripts/inventory_capacity_release.py','prepare',str(out)],cwd=prior,check=True,env={**os.environ,'GITHUB_SHA':BASE})
        finally:
            pkg.git('worktree','remove','--force',str(prior))
    shutil.rmtree(out/'before')
    shutil.copytree(out/'after',out/'before')
    for name in CHANGED:
        with tempfile.TemporaryDirectory() as temp:
            old,new=Path(temp)/'old',Path(temp)/'new'
            old.write_bytes(pkg.git('show',BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
            (out/'after'/name).write_bytes(pkg.git('merge-file','-p',str(out/'before'/name),str(old),str(new)))
    pkg.require(pkg.files(out/'before')==pkg.files(out/'after'),'Asset inventory changed')
    pkg.require({name for name in pkg.files(out/'before') if (out/'before'/name).read_bytes()!=(out/'after'/name).read_bytes()}==CHANGED,'Unexpected report release delta')

def ready():
    prod.ready(BACKEND)

def run(action,out):
    if action=='prepare':return prepare(out)
    pr=team.reviewed('fix/report-interaction-delay')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']) and checks.check_capacity_commit(os.environ['GITHUB_SHA']),'Required application/security/capacity checks incomplete')
    if action=='preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action=='publish':
        publisher.publish(out,changed=CHANGED,added=set(),reviewed_pr=pr,ready=ready,
            previous_version='c5528969-294e-4270-be8d-c0c019f21ef9',
            previous_deployment='f8fbee62-e88f-4267-9b6e-6fd7db3137ba',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
