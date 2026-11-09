"""Overlay the picker on the currently serving site, retaining its hourly R2 feed."""
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

import catalogue_package as pkg
import catalogue_promotion as prod
from feed_snapshot import FILES, decode

BASE='61344d38b5987fc24c0ecf8d35039aac808f1420'
PICKER_COMMIT='9982c9f1f5dcfdc3eaa1d95deaeacd67fa12253f'
VERSION='9060c8b1-8570-4dd6-8791-2a919ef0f639'
DEPLOYMENT='add65052-b67f-49cf-b4a6-53bfd9db93a5'
ENV='cloudflare-site-production'
CHANGED={'app.js','cvie.js','cvie.css'}
MODULE='technology-version-picker.mjs'
PIN=re.compile(rb'(src="/(?:data\.js|malware-data\.js|threat-data\.js|lifecycle\.js|patch-notes\.js)(?:\?[^"<>]*?)?)[?&]feed_version=[0-9a-f]{64}"')

def prepare(out):
    with tempfile.TemporaryDirectory() as temp:
        prior=Path(temp)/'baseline'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),BASE)
        try:
            subprocess.run([sys.executable,'scripts/intelligence_release.py','prepare',str(out)],cwd=prior,check=True)
        finally:
            pkg.git('worktree','remove','--force',str(prior))
    shutil.rmtree(out/'before')
    shutil.copytree(out/'after',out/'before')
    with tempfile.TemporaryDirectory() as temp:
        for name in CHANGED:
            ancestor=Path(temp)/'original'
            ancestor.write_bytes(pkg.git('show',BASE+':'+name))
            source=Path(temp)/'updated'
            source.write_bytes(pkg.git('show','HEAD:'+name))
            if name=='cvie.css':
                original,updated=ancestor.read_bytes(),source.read_bytes()
                pkg.require(updated.startswith(original),'Expected only additive picker styles')
                merged=(out/'before'/name).read_bytes()+updated[len(original):]
            else:
                merged=pkg.git('merge-file','-p',str(out/'before'/name),str(ancestor),str(source))
            (out/'after'/name).write_bytes(merged)
    (out/'after'/MODULE).write_bytes(pkg.git('show','HEAD:'+MODULE))
    # This release changes only the Worker's advisory requests. Compare the
    # assembled browser assets with the version already served by PR #302.
    for name in CHANGED | {MODULE}:
        pkg.require(pkg.git('show',PICKER_COMMIT+':'+name)==pkg.git('show','HEAD:'+name),
                    'Unexpected frontend change: '+name)
        shutil.copyfile(out/'after'/name,out/'before'/name)
    for name in ('worker.mjs','version-scan.mjs','version-products.json','version-releases.json'):
        path='site-gate/'+name
        (out/'source'/path).write_bytes(pkg.git('show','HEAD:'+path))

def readiness():
    prod.ready(Path('release/intelligence-baseline/backend-identity.txt').read_text().strip())

def normalized(path,live):
    value=prod.origin_bytes(path,live)
    return PIN.sub(rb'\1"',value) if path.endswith('.html') else value

def publish(out):
    password=os.environ['SITE_GATE_PASSWORD']
    auth='Basic '+base64.b64encode(('cveharbor:'+password).encode()).decode()
    with prod.request(prod.ORIGIN+'feed-health.json',{'Authorization':auth}) as health:
        version=health.headers.get('X-CVEHarbor-Feed-Version','')
        pkg.require(re.fullmatch('[0-9a-f]{64}',version),'Missing serving R2 snapshot')
    def asset(path,auth):
        name='data/feed-health.json' if path=='feed-health.json' else path
        if name not in FILES:return prod.protected_asset(path,auth)
        with prod.request(prod.ORIGIN+path+'?feed_version='+version,{'Authorization':auth}) as r:
            pkg.require(r.headers.get('X-CVEHarbor-Feed-Version')==version,'Incorrect feed snapshot')
            body=r.read()
            decode(name,body)
            return body
    def check(path,auth,expected):
        pkg.require(pkg.digest(normalized(path,asset(path,auth)))==expected,'Unexpected live bytes for '+path)
    prod.publish(out,site_env=ENV,pr_number=pr_number(),previous_version=VERSION,previous_deployment=DEPLOYMENT,
        changed=CHANGED | {MODULE},readiness=readiness,verify_served=check,read_asset=asset,canonical=normalized)
    with prod.request(prod.ORIGIN+'v1/version-picker/catalogue',{'Authorization':auth}) as r:
        live=json.load(r)
    pkg.require(set(live['cards'])==set(json.loads(Path('site-gate/version-products.json').read_text())['cards'])
        and all(live['releases'].get(key,{}).get('versions') for key in live['products']),'Incomplete live release picker')
    day=datetime.now(timezone.utc).date().isoformat()
    for query in ('product=runtime&version=8.0.12&months=3','product=react&version=19.0.0&months=12'):
        def verify_source():
            with prod.request(prod.ORIGIN+'v1/version-picker/scan?day='+day+'&'+query,{'Authorization':auth}) as r:
                page=json.load(r)
            pkg.require(isinstance(page.get('rows'),list) and 'range' in page,'Live source scan incomplete')
        prod.await_read(verify_source)

def pr_number():
    matches=[p['number'] for p in prod.github('/commits/'+os.environ['GITHUB_SHA']+'/pulls') if p['merged_at'] and p['head']['ref']=='fix/version-picker-cloudflare' and p['base']['ref']=='main']
    pkg.require(len(matches)==1,'Missing exact reviewed picker PR')
    return matches[0]

def run(action,out):
    if action=='prepare':prepare(out)
    elif action=='preflight':
        prod.evidence(pr_number())
        prod.policy(ENV)
        readiness()
    elif action=='publish':publish(out)
    else:raise ValueError(action)

