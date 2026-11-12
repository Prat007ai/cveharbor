"""Server dashboard overlay on the verified PR343 website; backend/AI unchanged."""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile
import catalogue_package as pkg
import team_release as team
import catalogue_promotion as prod
import production_release_checks as checks
import version_picker_release as publisher

BASE = 'efa4c40be1205e3ba99cbc6572c9f565077df2e2'
BACKEND = 'ae8e1add427ec56e9950b742a8ada776dee6a79c798ca162cd09cb949e9c6c9a'
VERSION = '7ffba3df-904c-42f3-aa73-3f22456b209a'
DEPLOYMENT = '2ce36ef1-19a7-49a0-8d28-9a76378adc50'
CHANGED = {'customer-security.js','organization-security.js','customer-dashboard/index.html','collectors/Export-CVEHarborInventory.ps1','collectors/README.txt'}
ADDED = {'server-security.js','server-security.css'}


def dashboard_html(text):
    text=text.replace('</head>','<link rel="stylesheet" href="/server-security.css?v=server-security-1"></head>')
    text=text.replace('<div id="customerDashboardAssessment"></div>','<div id="customerDashboardAssessment"></div><section id="customerDashboardServers" aria-label="Security by server"></section>')
    text=text.replace('<script src="/customer-security.js','<script src="/server-security.js?v=server-security-1"></script><script src="/customer-security.js')
    return text.replace('/customer-security.js?v=windows-inventory-1','/customer-security.js?v=server-security-1').replace('/organization-security.js?v=windows-inventory-1','/organization-security.js?v=server-security-1')

def prepare(out):
    pkg.require(not out.exists(), 'Use a new output directory')
    with tempfile.TemporaryDirectory() as temp:
        checkout=Path(temp)/'baseline'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(checkout),BASE)
        try:
            env=dict(os.environ);env.pop('GITHUB_ACTIONS',None)
            subprocess.run([sys.executable,'scripts/windows_inventory_release.py','prepare',str(out)],cwd=checkout,env=env,check=True)
        finally:
            pkg.git('worktree','remove','--force',str(checkout))
    overlay(out)

def overlay(out):
    with tempfile.TemporaryDirectory() as temp:
        shutil.rmtree(out/'before')
        shutil.copytree(out/'after',out/'before')
        for name in sorted(CHANGED):
            if name=='customer-dashboard/index.html':
                pkg.require(dashboard_html(pkg.git('show',BASE+':'+name).decode())==Path(name).read_text(encoding='utf-8'),'Unexpected dashboard HTML changes')
                value=dashboard_html((out/'before'/name).read_text(encoding='utf-8'))
                pkg.require('id="customerDashboardServers"' in value,'Missing server panel')
                (out/'after'/name).write_bytes(value.encode())
                continue
            ancestor=Path(temp)/'ancestor';ancestor.write_bytes(pkg.git('show',BASE+':'+name))
            updated=Path(temp)/'updated';updated.write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
            merged=pkg.git('merge-file','-p',str(out/'before'/name),str(ancestor),str(updated))
            (out/'after'/name).write_bytes(merged)
        for name in ADDED:
            pkg.require(not (out/'after'/name).exists(),'Unexpected existing asset: '+name)
            (out/'after'/name).write_bytes(Path(name).read_bytes().replace(b'\r\n',b'\n'))
    before,after=pkg.files(out/'before'),pkg.files(out/'after')
    pkg.require(set(after)-set(before)==ADDED and not set(before)-set(after),'Unexpected asset set')
    pkg.require({n for n in before if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==CHANGED,'Unexpected website changes')
    print('Verified server dashboard overlay: five changed and two added assets; backend and AI unchanged.')

def ready():
    prod.ready(BACKEND)

def run(action,out):
    if action=='prepare':return prepare(out)
    pr=team.reviewed('feature/server-security-dashboard')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']),'Required checks incomplete')
    pkg.require(checks.check_inventory_commit(os.environ['GITHUB_SHA']),'Inventory checks incomplete')
    if action=='preflight':prod.policy(publisher.ENV);ready()
    elif action=='publish':
        publisher.publish(out,changed=CHANGED,added=ADDED,reviewed_pr=pr,ready=ready,
                          previous_version=VERSION,previous_deployment=DEPLOYMENT,served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
