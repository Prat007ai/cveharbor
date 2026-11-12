"""Add the native collector download to the verified PR347 website only."""
from pathlib import Path
import json
import os
import shutil
import tempfile
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import production_release_checks as checks
import version_picker_release as publisher

BASE='df3994351e2f58dcf540b5184540ddb49a7c709a'
CHANGED={'asset-import.js'}
ADDED={'collectors/windows/CVEHarbor-Collector.zip','collectors/windows/README.txt'}

def prepare(out):
    pkg.require(not out.exists(),'Use a new site directory')
    package=Path('collector-app/package')
    receipt=json.loads((package/'build-receipt.json').read_text())
    commit=os.environ.get('GITHUB_SHA') or pkg.git('rev-parse','HEAD').decode().strip()
    pkg.require(receipt['commit']==commit,'Collector artifact must come from this exact reviewed commit')
    pkg.require(set(receipt['files'])=={'CVEHarbor-Collector.zip','README.txt'},'Unexpected collector artifact inventory')
    for name,digest in receipt['files'].items():
        pkg.require(pkg.digest((package/name).read_bytes())==digest,'Collector artifact hash mismatch')
    team.previous(BASE,'inventory_experience_release.py','prepare',out)
    shutil.rmtree(out/'before');shutil.copytree(out/'after',out/'before')
    with tempfile.TemporaryDirectory() as temp:
        for name in sorted(CHANGED):
            old,new=Path(temp)/'old',Path(temp)/'new'
            old.write_bytes(pkg.git('show',BASE+':'+name));new.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
            target=out/'after'/name;target.write_bytes(pkg.git('merge-file','-p',str(target),str(old),str(new)))
    for name in ADDED:
        target=out/'after'/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes((package/Path(name).name).read_bytes())
    pkg.require(pkg.files(out/'after')-pkg.files(out/'before')==ADDED,'Unexpected additions')
    pkg.require(not pkg.files(out/'before')-pkg.files(out/'after'),'Unexpected deletions')
    pkg.require({n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==CHANGED,'Unexpected changes')

def ready():prod.ready('332f5e1d6ad2d59e9615f42d63bab4b83426e6b217fd70c13f8667766f64df08')

def run(action,out):
    if action=='prepare':return prepare(out)
    pr=team.reviewed('feature/windows-collector-app')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required application and security checks incomplete')
    if action=='preflight':prod.policy(publisher.ENV);ready()
    elif action=='publish':publisher.publish(out,changed=CHANGED,added=ADDED,reviewed_pr=pr,ready=ready,previous_version='838db59b-fb84-40bc-a286-c6bd91352681',previous_deployment='4b6413e3-0623-49aa-a60a-d28ef1f55abf',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':
    import sys
    run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
