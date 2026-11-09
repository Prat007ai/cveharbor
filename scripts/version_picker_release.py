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
from urllib.error import HTTPError

import catalogue_package as pkg
import catalogue_promotion as prod
from feed_snapshot import FILES, decode

BASE='61344d38b5987fc24c0ecf8d35039aac808f1420'
VERSION='52dff137-fe84-48da-a8d1-dbae9403057d'
DEPLOYMENT='64bbcb6c-9f13-4cda-91ce-231c70e6fdb8'
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
    try:
        prod.protected_asset(MODULE,auth)
    except HTTPError as exc:
        if exc.code!=404:raise
    else:raise RuntimeError('Picker module already exists on production')
    prod.publish(out,site_env=ENV,pr_number=pr_number(),previous_version=VERSION,previous_deployment=DEPLOYMENT,
        changed=CHANGED,readiness=readiness,verify_served=check,read_asset=asset,canonical=normalized,added={MODULE})
    with prod.request(prod.ORIGIN+'v1/version-picker/catalogue',{'Authorization':auth}) as r:
        live=json.load(r)
    pkg.require(set(live['cards'])==set(json.loads(Path('site-gate/version-products.json').read_text())['cards'])
        and all(live['releases'].get(key,{}).get('versions') for key in live['products']),'Incomplete live release picker')

def pr_number():
    matches=[p['number'] for p in prod.github('/commits/'+os.environ['GITHUB_SHA']+'/pulls') if p['merged_at'] and p['head']['ref']=='feature/technology-version-picker' and p['base']['ref']=='main']
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

