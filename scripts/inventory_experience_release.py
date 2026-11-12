"""Website-only inventory UX release on the verified PR346 website/backend."""
from pathlib import Path
import os
import shutil
import sys
import tempfile
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import production_release_checks as checks
import version_picker_release as publisher

BASE='567ad065d108c6c174d73554d58c0b05325ed898'
CHANGED={'asset-import.js','inventory.js','styles.css','inventory-import.css','collectors/Export-CVEHarborInventory.ps1','collectors/README.txt'}

def prepare(out):
    pkg.require(not out.exists(),'Use a new site directory')
    team.previous(BASE,'server_network_release.py','prepare',out)
    shutil.rmtree(out/'before');shutil.copytree(out/'after',out/'before')
    with tempfile.TemporaryDirectory() as temp:
        for name in sorted(CHANGED):
            old,new=Path(temp)/'old',Path(temp)/'new'
            old.write_bytes(pkg.git('show',BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
            target=out/'after'/name
            target.write_bytes(pkg.git('merge-file','-p',str(target),str(old),str(new)))
    pkg.require(pkg.files(out/'before')==pkg.files(out/'after'),'Unexpected site additions/deletions')
    pkg.require({n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==CHANGED,'Unexpected site changes')

def ready():prod.ready('332f5e1d6ad2d59e9615f42d63bab4b83426e6b217fd70c13f8667766f64df08')

def run(action,out):
    if action=='prepare':return prepare(out)
    pr=team.reviewed('feature/inventory-upload-experience')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required checks incomplete')
    pkg.require(checks.check_inventory_commit(os.environ['GITHUB_SHA'],required_jobs=('collector','workflow','mapping','network')),'Inventory checks incomplete')
    if action=='preflight':prod.policy(publisher.ENV);ready()
    elif action=='publish':publisher.publish(out,changed=CHANGED,added=set(),reviewed_pr=pr,ready=ready,previous_version='f627a518-6d8b-451c-ae1a-bd4225860149',previous_deployment='44060340-1494-4ccb-9ce4-9049b027a8f8',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
