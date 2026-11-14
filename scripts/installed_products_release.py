"""Product assessment delta on the frozen, serving PR381 packages."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import version_picker_release as publisher
import production_release_checks as checks

BASE = '84553046ee8313723702a4db24a1df198abbb518'
SERVING = 'f00b4c4939ddf3d304fe525738d6fdbfedb57956'
PREDECESSOR = '1d687be8ff23a3785b466f41151a065f5dc4aa34aabaafb0b50b832b7021d50f'
WORKER = {'account-backend/src/'+n for n in ('agent-validation.js','agents.js','cvie-onboarding.js','cvie.js','index.js','product-identity.js')}
ADDED = {'account-backend/src/installed-product-identities.js'}
SITE = {'agent-ui.js','customer-security.js','inventory-assessment.js','inventory-matching.js','organization-security.js','server-security.js'}

def overlay(out, names):
    with tempfile.TemporaryDirectory() as temp:
        old, new = Path(temp)/'old', Path(temp)/'new'
        for n in sorted(names):
            old.write_bytes(pkg.git('show', BASE+':'+n).replace(b'\r\n',b'\n'))
            content=Path(n).read_bytes().replace(b'\r\n',b'\n')
            prefix=b"import {activeAssets,agentSchemaReady} from './agent-validation.js';\n" if n=='account-backend/src/cvie.js' else b''
            if prefix:
                pkg.require(content.count(prefix)==1 and prefix not in (out/n).read_bytes(),'Unexpected assessment import')
                content=content.replace(prefix,b'')
            new.write_bytes(content)
            (out/n).write_bytes(prefix+pkg.git('merge-file','-p',str(out/n),str(old),str(new)))

def backend(out, check=True):
    pkg.require(not out.exists(),'Use a new package directory')
    cached=os.environ.get('PRODUCTS_BACKEND_BASELINE')
    if cached:
        pkg.require(not os.environ.get('GITHUB_ACTIONS'),'CI must reproduce its baseline')
        pkg.require(team.identity(Path(cached))==PREDECESSOR,'Unexpected cached baseline')
        shutil.copytree(cached,out)
    else:team.previous(SERVING,'windows_agent_release.py','backend',out)
    pkg.require(team.identity(out)==PREDECESSOR,'Serving backend changed; review the new baseline')
    before={n:(out/n).read_bytes() for n in pkg.files(out)}
    overlay(out,WORKER)
    for n in ADDED:(out/n).write_bytes(Path(n).read_bytes().replace(b'\r\n',b'\n'))
    pkg.require(pkg.files(out)-before.keys()==ADDED,'Unexpected backend additions')
    pkg.require({n for n in before if before[n]!=(out/n).read_bytes()}==WORKER,'Unexpected backend delta')
    value=team.identity(out);receipt=Path('release/installed-products-backend.txt')
    if check:pkg.require(value==receipt.read_text().strip(),'Unreviewed product assessment package')
    else:receipt.write_bytes((value+'\n').encode())
    print(value)

def baseline_site(out):
    pkg.require(not out.exists(),'Use a new site directory')
    with tempfile.TemporaryDirectory() as temp:
        prior=Path(temp)/'base'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),SERVING)
        try:
            for n in ('collector-app/package','windows-agent/package/release'):
                shutil.copytree(n,prior/n,dirs_exist_ok=True)
            subprocess.run([sys.executable,'scripts/windows_agent_release.py','prepare',str(out)],cwd=prior,check=True,env={**os.environ,'GITHUB_SHA':SERVING})
        finally:pkg.git('worktree','remove','--force',str(prior))

def prepare(out):
    baseline_site(out)
    shutil.rmtree(out/'before');shutil.copytree(out/'after',out/'before')
    overlay(out/'after',SITE)
    pkg.require(pkg.files(out/'before')==pkg.files(out/'after'),'Site file inventory changed')
    pkg.require({n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==SITE,'Unexpected site delta')

def ready():
    prod.ready(Path('release/installed-products-backend.txt').read_text().strip())

def run(action,out):
    if action in ('backend','record'):return backend(out,action!='record')
    if action=='baseline-site':return baseline_site(out)
    if action=='prepare':return prepare(out)
    pr=team.reviewed('fix/agent-product-assessment')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']) and checks.check_products_commit(os.environ['GITHUB_SHA']),'Required exact-main product assessment checks incomplete')
    if action=='preflight':prod.policy(publisher.ENV);ready()
    elif action=='publish':
        publisher.publish(out,changed=SITE,reviewed_pr=pr,ready=ready,
            previous_version='6d3150d2-b073-40b5-b5dd-e701bedfb33c',previous_deployment='07ab4266-aa28-43ae-8588-605ff3260c68',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
