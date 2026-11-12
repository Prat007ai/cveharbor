"""Scoped network inventory release on the verified PR344 backend / PR345 website."""
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

BASE='a1b34899baab89348c2fb22aac831342d6d87212'
PREDECESSOR='ae8e1add427ec56e9950b742a8ada776dee6a79c798ca162cd09cb949e9c6c9a'
CHANGED={'server-security.js','server-security.css','customer-security.js','organization-security.js','asset-import.js','inventory.js','team-workspace.js','collectors/Export-CVEHarborInventory.ps1','collectors/README.txt'}
WORKER={'account-backend/src/inventory.js','account-backend/src/team-data.js'}
ADDED={'account-backend/src/server-network.js'}

def overlay(out,files):
    with tempfile.TemporaryDirectory() as temp:
        for name in sorted(files):
            old,new=Path(temp)/'old',Path(temp)/'new'
            old.write_bytes(pkg.git('show',BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
            (out/name).write_bytes(pkg.git('merge-file','-p',str(out/name),str(old),str(new)))

def backend(out,check=True):
    pkg.require(not out.exists(),'Use a new package directory')
    team.previous(BASE,'dotnet_mapping_release.py','build',out)
    pkg.require(team.identity(out)==PREDECESSOR,'Unexpected serving backend')
    before={n:(out/n).read_bytes() for n in pkg.files(out)}
    overlay(out,WORKER)
    for name in ADDED:
        pkg.require(not (out/name).exists(),'Unexpected existing module')
        (out/name).write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
    pkg.require(pkg.files(out)-before.keys()==ADDED,'Unexpected backend additions')
    pkg.require({n for n in before if before[n]!=(out/n).read_bytes()}==WORKER,'Unexpected backend changes')
    value=team.identity(out)
    if check:pkg.require(value==Path('release/server-network-backend.txt').read_text().strip(),'Unreviewed backend')
    else:Path('release/server-network-backend.txt').write_text(value+'\n')
    print(value)

def prepare(out):
    pkg.require(not out.exists(),'Use a new site directory')
    team.previous(BASE,'server_security_release.py','prepare',out)
    shutil.rmtree(out/'before');shutil.copytree(out/'after',out/'before')
    overlay(out/'after',CHANGED)
    pkg.require(pkg.files(out/'before')==pkg.files(out/'after'),'Unexpected site additions/deletions')
    pkg.require({n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==CHANGED,'Unexpected site changes')

def ready():prod.ready(Path('release/server-network-backend.txt').read_text().strip())

def run(action,out):
    if action=='prepare':return prepare(out)
    if action in ('backend','record'):return backend(out,action!='record')
    pr=team.reviewed('feature/server-network-inventory')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required checks incomplete')
    pkg.require(checks.check_inventory_commit(os.environ['GITHUB_SHA'],required_jobs=('collector','workflow','mapping','network')),'Network checks incomplete')
    if action=='preflight':prod.policy(publisher.ENV);ready()
    elif action=='publish':publisher.publish(out,changed=CHANGED,added=set(),reviewed_pr=pr,ready=ready,previous_version='b34f90e8-f23a-492e-9abc-809dd5f694f8',previous_deployment='99974604-ecb9-467b-953c-8d7fdfde093f',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
