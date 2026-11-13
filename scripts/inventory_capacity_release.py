"""Scoped capacity delta on verified PR361 website and existing AI backend."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import production_release_checks as checks
import version_picker_release as publisher

BASE = '3ce02f24cbcdfd33cd776c6fdd3e4e7a245ed97a'
PREDECESSOR = '0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34'
WORKER = {'account-backend/src/inventory.js', 'account-backend/src/team-data.js', 'account-backend/src/recovery-control.js'}
ADDED_WORKER = {'account-backend/src/inventory-pages.js', 'account-backend/src/inventory-read-db.js', 'account-backend/inventory-capacity-schema.sql'}
SITE = {'customer-security.js', 'inventory.js', 'workspace-ai.js', 'team-ui.js', 'cvie.js'}
ADDED_SITE = {'inventory-client.js'}

def overlay(out, names):
    with tempfile.TemporaryDirectory() as temp:
        old, new = Path(temp)/'old', Path(temp)/'new'
        for name in sorted(names):
            before = pkg.git('show', BASE+':'+name)
            after = Path(name).read_bytes().replace(b'\r\n', b'\n')
            if name == 'customer-security.js':
                # This unchanged main-only tracker link is absent from the
                # serving package. Exclude it on both sides before merging an
                # adjacent menu optimization; never reintroduce held UI.
                held = [line for line in before.splitlines(keepends=True)
                        if line.startswith(b" let tracker=$('customerRemediationLink');")]
                pkg.require(len(held)==1 and held[0] in after, 'Held tracker line changed')
                pkg.require(b'customerRemediationLink' not in (out/name).read_bytes(), 'Unexpected serving tracker')
                before, after = before.replace(held[0],b''), after.replace(held[0],b'')
            old.write_bytes(before)
            new.write_bytes(after)
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

def ready():
    prod.ready(PREDECESSOR)


def run(action, out):
    if action=='prepare':return prepare(out)
    if action in ('backend','record'):return backend(out,action!='record')
    pr=team.reviewed('release/backend-capacity')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required application/security checks incomplete')
    if action=='preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action=='publish':
        publisher.publish(out,changed=SITE,added=ADDED_SITE,reviewed_pr=pr,ready=ready,
                          previous_version='59156339-bd9c-4a68-8d3b-d0061179f0bc',
                          previous_deployment='07a11258-dab6-4b84-a31e-f9e11cfb9d34',
                          served_copy=out/'verified-origin')
    else:raise ValueError(action)


if __name__=='__main__':
    run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
