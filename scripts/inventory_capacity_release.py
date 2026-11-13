"""Scoped capacity delta on verified PR361 website and existing AI backend."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import catalogue_package as pkg
import team_release as team

BASE = '3ce02f24cbcdfd33cd776c6fdd3e4e7a245ed97a'
PREDECESSOR = '0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34'
WORKER = {'account-backend/src/inventory.js', 'account-backend/src/team-data.js'}
ADDED_WORKER = {'account-backend/src/inventory-pages.js', 'account-backend/inventory-capacity-schema.sql'}
SITE = {'customer-security.js', 'inventory.js', 'workspace-ai.js', 'team-ui.js'}
ADDED_SITE = {'inventory-client.js'}

def overlay(out, names):
    with tempfile.TemporaryDirectory() as temp:
        old, new = Path(temp)/'old', Path(temp)/'new'
        for name in sorted(names):
            old.write_bytes(pkg.git('show', BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
            (out/name).write_bytes(pkg.git('merge-file', '-p', str(out/name), str(old), str(new)))

def backend(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    cached=os.environ.get('CAPACITY_BACKEND_BASELINE')
    if cached:
        pkg.require(not os.environ.get('GITHUB_ACTIONS'), 'CI must reproduce the baseline from reviewed source')
        pkg.require(team.identity(Path(cached)) == PREDECESSOR, 'Unverified local baseline')
        shutil.copytree(cached,out)
    else:
        team.previous(BASE,'finding_ai_release.py','backend',out)
    pkg.require(team.identity(out)==PREDECESSOR,'Unexpected serving backend')
    before={name:(out/name).read_bytes() for name in pkg.files(out)}
    overlay(out,WORKER)
    for name in ADDED_WORKER:(out/name).write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
    pkg.require(pkg.files(out)-before.keys()==ADDED_WORKER,'Unexpected backend additions')
    pkg.require({name for name in before if before[name]!=(out/name).read_bytes()}==WORKER,'Unexpected backend delta')
    value=team.identity(out)
    if check:pkg.require(value==Path('release/inventory-capacity-backend.txt').read_text().strip(),'Unreviewed backend identity')
    else:Path('release/inventory-capacity-backend.txt').write_bytes((value+'\n').encode())
    print(value)

def prepare(out):
    pkg.require(not out.exists(),'Use a new site directory')
    with tempfile.TemporaryDirectory() as temp:
        prior=Path(temp)/'predecessor'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),BASE)
        try:
            shutil.copytree('collector-app/package',prior/'collector-app/package',dirs_exist_ok=True)
            subprocess.run([sys.executable,'scripts/finding_ai_warning_release.py','prepare',str(out)],cwd=prior,check=True,env={**os.environ,'GITHUB_SHA':BASE})
        finally:
            pkg.git('worktree','remove','--force',str(prior))
    shutil.rmtree(out/'before')
    shutil.copytree(out/'after',out/'before')
    overlay(out/'after',SITE)
    for name in ADDED_SITE:(out/'after'/name).write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
    pkg.require(pkg.files(out/'after')-pkg.files(out/'before')==ADDED_SITE,'Unexpected site additions')
    pkg.require({name for name in pkg.files(out/'before') if (out/'before'/name).read_bytes()!=(out/'after'/name).read_bytes()}==SITE,'Unexpected site delta')

if __name__=='__main__':
    action=sys.argv[1]
    pkg.require(action in ('backend','record','prepare'),'Only local package preparation is available')
    out=Path(sys.argv[2]).resolve()
    if action=='prepare':prepare(out)
    else:backend(out,action!='record')
