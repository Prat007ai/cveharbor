"""Windows agent delta on the verified serving packages; preserve paused AI and held UI."""
import json
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

BASE = '94c479d22355bd8f0b2545550bb5a8bd6383add9'
LIVE_BASE = '43fce637edfc8d1a557a7b4a93153fcb5f8070e3'
PREDECESSOR = '611f3576f8b30323f6a2d0625891b102515f5ab8805d37c18801f4ba6cc54047'
WORKER = {'account-backend/src/'+n for n in ('index.js','inventory.js','inventory-pages.js','team-data.js','workspace-summary.js','workspace-history.js')}
ADDED_WORKER = {'account-backend/src/'+n for n in ('agents.js','agent-validation.js','agent-mail.js')} | {'account-backend/agent-schema.sql'}
SITE = {'asset-import.js','customer-security.js','organization-security.js','server-security.js'}
ADDED_SITE = {'agent-ui.js','agent-ui.css','collectors/agent/CVEHarbor-Agent.msi'}

def overlay(out,names):
    with tempfile.TemporaryDirectory() as temp:
        old,new=Path(temp)/'old',Path(temp)/'new'
        for name in sorted(names):
            old.write_bytes(pkg.git('show',BASE+':'+name))
            after=Path(name).read_bytes().replace(b'\r\n',b'\n')
            if name=='account-backend/src/inventory-pages.js':
                # PR380 is not serving yet. Strip only its unchanged optimization
                # from both sides, preserving this release's agent metadata.
                def serving_shape(value):
                    block=b" // The owned environment set already enforces the selected customer's scope.\n // Avoid repeating an environment index lookup for every software row.\n const directAssets=resource==='assets'&&!team;\n"
                    pkg.require(block in value,'Unexpected held capacity optimization')
                    return value.replace(block,b'').replace(b'if(customer&&!directAssets)',b'if(customer)').replace(b" if(directAssets&&!customer){clauses.push('t.environment_id IN (SELECT id FROM inventory_environments WHERE user_id=?)');args.push(owner);}\n",b'').replace(b"(directAssets?'':def.join||'')",b"(def.join||'')")
                old.write_bytes(serving_shape(old.read_bytes()))
                after=serving_shape(after)
            prefix=b''
            if name=='account-backend/src/workspace-summary.js':
                prefix=b"import {activeAssets} from './agent-validation.js';\n"
                pkg.require(after.startswith(prefix),'Agent scope import changed')
                after=after[len(prefix):]
            if name=='account-backend/src/index.js':
                prefix=b"import {agentDeviceRoute,agentManagement} from './agents.js';\nimport {dispatchAgentMail} from './agent-mail.js';\n"
                pkg.require(after.startswith(prefix),'Agent routing imports changed')
                after=after[len(prefix):]
            new.write_bytes(after)
            (out/name).write_bytes(prefix+pkg.git('merge-file','-p',str(out/name),str(old),str(new)))

def installer():
    value=json.loads(Path('release/windows-agent-installer.json').read_text())
    pkg.require(value['channel']=='unsigned-evaluation' and len(value['sha256'])==64,'Unreviewed evaluation installer')
    for name in ['Agent.cs','Service.cs','Setup.cs','EnrollConsole.cs','AssemblyInfo.cs','setup.manifest','build.ps1','package.ps1']:
        n='windows-agent/'+name
        pkg.require(Path(n).read_bytes().replace(b'\r\n',b'\n')==pkg.git('show',value['source_commit']+':'+n).replace(b'\r\n',b'\n'),'Installer source changed: '+n)
    pkg.require(Path('collector-app/Inventory.cs').read_bytes().replace(b'\r\n',b'\n')==pkg.git('show',value['source_commit']+':collector-app/Inventory.cs').replace(b'\r\n',b'\n'),'Collector source changed since installer test')
    return value

def backend(out,check=True):
    pkg.require(not out.exists(),'Use a new package directory')
    cached=os.environ.get('AGENT_BACKEND_BASELINE')
    if cached:
        pkg.require(not os.environ.get('GITHUB_ACTIONS'),'CI must reproduce the baseline')
        pkg.require(team.identity(Path(cached))==PREDECESSOR,'Unexpected cached baseline')
        shutil.copytree(cached,out)
    else:team.previous(LIVE_BASE,'nvd_outage_release.py','backend',out)
    pkg.require(team.identity(out)==PREDECESSOR,'Serving backend changed; review the new baseline')
    before={n:(out/n).read_bytes() for n in pkg.files(out)}
    overlay(out,WORKER)
    for n in ADDED_WORKER:
        pkg.require(not (out/n).exists(),'Unexpected module collision')
        (out/n).write_bytes(Path(n).read_bytes().replace(b'\r\n',b'\n'))
    config=out/'account-backend/wrangler.toml'
    s=config.read_text()
    pkg.require('WINDOWS_AGENT_ENABLED' not in s and s.count('[vars]\n')==1,'Unexpected agent configuration')
    s=s.replace('[vars]\n','[vars]\nWINDOWS_AGENT_ENABLED = "true"\nAGENT_EMAIL_ENABLED = "true"\nAGENT_INVENTORY_SCHEMA = "1"\nAGENT_DISTRIBUTION = "evaluation"\nAGENT_SUPPORT_EMAIL = "prat.mahen@gmail.com"\nAGENT_INSTALLER_SHA256 = "'+installer()['sha256']+'"\n')
    s+='\n[[ratelimits]]\nname = "AGENT_RATE_LIMITER"\nnamespace_id = "23502"\nsimple = { limit = 60, period = 60 }\n\n[[ratelimits]]\nname = "AGENT_SOURCE_RATE_LIMITER"\nnamespace_id = "23503"\nsimple = { limit = 600, period = 60 }\n'
    config.write_bytes(s.encode())
    pkg.require(pkg.files(out)-before.keys()==ADDED_WORKER,'Unexpected backend additions')
    pkg.require({n for n in before if before[n]!=(out/n).read_bytes()}==WORKER|{'account-backend/wrangler.toml'},'Unexpected backend delta')
    value=team.identity(out);receipt=Path('release/windows-agent-backend.txt')
    if check:pkg.require(value==receipt.read_text().strip(),'Unreviewed backend identity')
    else:receipt.write_bytes((value+'\n').encode())
    print(value)

def prepare(out):
    pkg.require(not out.exists(),'Use a new site directory')
    with tempfile.TemporaryDirectory() as temp:
        prior=Path(temp)/'predecessor'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),BASE)
        try:
            shutil.copytree('collector-app/package',prior/'collector-app/package',dirs_exist_ok=True)
            subprocess.run([sys.executable,'scripts/inventory_capacity_release.py','prepare',str(out)],cwd=prior,check=True,env={**os.environ,'GITHUB_SHA':BASE})
        finally:pkg.git('worktree','remove','--force',str(prior))
    shutil.rmtree(out/'before');shutil.copytree(out/'after',out/'before')
    overlay(out/'after',SITE)
    for n in ('agent-ui.js','agent-ui.css'):(out/'after'/n).write_bytes(Path(n).read_bytes().replace(b'\r\n',b'\n'))
    record=installer();msi=Path('windows-agent/package/release/CVEHarbor-Agent.msi')
    import hashlib
    pkg.require(hashlib.sha256(msi.read_bytes()).hexdigest()==record['sha256'],'Installer digest differs from reviewed build')
    supplied=json.loads(msi.with_name('agent-release.json').read_text(encoding='utf-8-sig'))
    pkg.require(all(supplied[k]==record[k] for k in ('sha256','commit','channel','version')),'Installer provenance mismatch')
    destination=out/'after/collectors/agent';destination.mkdir(parents=True);shutil.copyfile(msi,destination/'CVEHarbor-Agent.msi')
    pkg.require(pkg.files(out/'after')-pkg.files(out/'before')==ADDED_SITE,'Unexpected site additions')
    pkg.require({n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes()!=(out/'after'/n).read_bytes()}==SITE,'Unexpected site delta')

def ready():
    prod.ready(Path('release/windows-agent-backend.txt').read_text().strip())

def run(action,out):
    if action in ('backend','record'):return backend(out,action!='record')
    if action=='prepare':return prepare(out)
    pr=team.reviewed('feature/windows-agent')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']) and checks.check_agent_commit(os.environ['GITHUB_SHA']),'Required exact-main agent checks incomplete')
    if action=='preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action=='publish':
        publisher.publish(out,changed=SITE,added=ADDED_SITE,reviewed_pr=pr,ready=ready,
            previous_version='c5528969-294e-4270-be8d-c0c019f21ef9',previous_deployment='f8fbee62-e88f-4267-9b6e-6fd7db3137ba',served_copy=out/'verified-origin')
    else:raise ValueError(action)

if __name__=='__main__':
    run(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
