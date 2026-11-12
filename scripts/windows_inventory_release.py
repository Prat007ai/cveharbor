"""Scoped inventory import overlay on the verified PR342 production packages."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import sys
import tempfile
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import version_picker_release as publisher
import production_release_checks as checks

BASE = 'b48e89971106d837fc16acaa82d672f61f4f9725'
BACKEND = 'ce561b7756d14c874d353470c84b8c9228626e400df8d776dcb83ee03eadeb2a'
VERSION = 'ba6e8ba5-cd22-4d49-b95d-0d5ab377c4fa'
DEPLOYMENT = '3d42e375-a8ce-44a2-af09-15feccd484a8'
CHANGED = {'index.html','environments/index.html','inventory.js','cvie.js','team-workspace.js','customer-security.js','customer-dashboard/index.html','customer-reports/index.html'}
ADDED = {'asset-import.js','inventory-assessment.js','organization-security.js','inventory-import.css','collectors/Export-CVEHarborInventory.ps1','collectors/README.txt'}

def predecessor(script, out):
    pkg.require(not out.exists(), 'Use a new output directory')
    with tempfile.TemporaryDirectory() as temporary:
        checkout = Path(temporary)/'base'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(checkout),BASE)
        try:
            env=dict(os.environ);env.pop('GITHUB_ACTIONS',None)
            subprocess.run([sys.executable,'scripts/'+script,str(out)],cwd=checkout,env=env,check=True)
        finally:
            pkg.git('worktree','remove','--force',str(checkout))

def backend(out, check=True):
    predecessor('organization_ai_package.py',out)
    pkg.require(team.identity(out)==BACKEND,'Unexpected serving backend predecessor')
    name='account-backend/src/team-data.js'
    old=(out/name).read_bytes()
    pkg.require(old==pkg.git('show',BASE+':'+name),'Team data differs from reviewed predecessor')
    new=Path(name).read_bytes().replace(b'\r\n',b'\n')
    pkg.require(new==old.replace(b"read('a.id,a.name,e.name AS environment",b"read('a.id,a.environment_id,a.name,e.name AS environment"), 'Only environment ID projection may change')
    (out/name).write_bytes(new)
    value=team.identity(out)
    if check:pkg.require(value==Path('release/windows-inventory-backend.txt').read_text().strip(),'Unreviewed backend identity')
    print(value,flush=True)
    return value

def html_overlay(text, name):
    text=text.replace('</head>','<link rel="stylesheet" href="/inventory-import.css?v=windows-inventory-1"></head>')
    text=re.sub(r'/cvie\.js\?v=[^"\s]+', '/cvie.js?v=windows-inventory-1',text)
    if name in {'index.html','environments/index.html'}:
        text=re.sub(r'<script src="/inventory\.js\?v=[^"]+"></script>', '<script src="/asset-import.js?v=windows-inventory-1"></script><script src="/inventory-assessment.js?v=windows-inventory-1"></script><script src="/inventory.js?v=windows-inventory-1"></script>',text)
    else:
        text=re.sub(r'<script src="/customer-security\.js\?v=[^"]+"></script>', '<script src="/inventory-assessment.js?v=windows-inventory-1"></script><script src="/customer-security.js?v=windows-inventory-1"></script>',text)
    if name=='customer-dashboard/index.html':
        text=text.replace('</body>','<script type="module" src="/organization-security.js?v=windows-inventory-1"></script></body>')
    return text

def overlay(out):
    with tempfile.TemporaryDirectory() as temp:
        for name in sorted(CHANGED):
            if name.endswith('.html'):
                if name!='environments/index.html':
                    expected=html_overlay(pkg.git('show',BASE+':'+name).decode(),name)
                    pkg.require(expected==Path(name).read_text(encoding='utf-8'),'Unreviewed HTML edit: '+name)
                live=(out/'before'/name).read_text(encoding='utf-8')
                updated=html_overlay(live,name)
                pkg.require(updated!=live and '/inventory-assessment.js?v=windows-inventory-1' in updated,'Missing inventory entry point: '+name)
                (out/'after'/name).write_bytes(updated.encode())
                continue
            ancestor=Path(temp)/'ancestor';ancestor.write_bytes(pkg.git('show',BASE+':'+name))
            updated=Path(temp)/'updated';updated.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
            merged=pkg.git('merge-file','-p',str(out/'before'/name),str(ancestor),str(updated))
            (out/'after'/name).write_bytes(merged)
    for name in ADDED:
        target=out/'after'/name
        pkg.require(not target.exists(),'Unexpected existing new asset: '+name)
        target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
    before,after=pkg.files(out/'before'),pkg.files(out/'after')
    pkg.require(set(after)-set(before)==ADDED,'Unexpected asset additions')
    pkg.require({n for n in before if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==CHANGED,'Unexpected site changes')

def prepare(out):
    predecessor('organization_ai_site.py',out)
    shutil.rmtree(out/'before')
    shutil.copytree(out/'after',out/'before')
    overlay(out)

def ready():
    prod.ready(Path('release/windows-inventory-backend.txt').read_text().strip())

def run(action,out):
    if action=='prepare':return prepare(out)
    if action=='backend':return backend(out)
    pr=team.reviewed('feature/windows-inventory-assessment')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required checks incomplete')
    pkg.require(checks.check_inventory_commit(os.environ['GITHUB_SHA']),'Inventory checks incomplete')
    if action=='preflight':
        prod.policy(publisher.ENV);ready()
    elif action=='publish':
        publisher.publish(out,changed=CHANGED,added=ADDED,reviewed_pr=pr,ready=ready,
                          previous_version=VERSION,previous_deployment=DEPLOYMENT,served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':
    out=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None
    if sys.argv[1]=='record':backend(out,False)
    else:run(sys.argv[1],out)
