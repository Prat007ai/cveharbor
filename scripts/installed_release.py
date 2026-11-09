"""Apply only the installed-release explorer to the published firewall website."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import catalogue_package as pkg
import catalogue_promotion as prod
import firewall_release as firewall
import version_picker_release as picker

LIVE_SITE = '58df925c25a5814407b56370a0114cf10c582f41'
BASE = 'ff21524332eaeb7483014cc3b7179a9f707817aa'
CHANGED = {'app.js', 'cvie.css', picker.MODULE}
MODULES = {'version-scan.mjs', 'version-products.json', 'version-releases.json'}

def prepare(out):
    with tempfile.TemporaryDirectory() as tmp:
        prior = Path(tmp)/'published'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),LIVE_SITE)
        try:
            subprocess.run([sys.executable,'scripts/session_navigation_release.py','prepare',str(out)],
                           cwd=prior,check=True,env={**os.environ,'CVEHARBOR_SITE_RELEASE':'firewall-digest'})
        finally:
            pkg.git('worktree','remove','--force',str(prior))
        shutil.copytree(out/'after',out/'before',dirs_exist_ok=True)
        for name in CHANGED:
            original, updated = Path(tmp)/'original', Path(tmp)/'updated'
            original.write_bytes(pkg.git('show', BASE+':'+name))
            updated.write_bytes(pkg.git('show', 'HEAD:'+name))
            target = out/'after'/name
            target.write_bytes(pkg.git('merge-file','-p',str(target),str(original),str(updated)))
        for name in MODULES:
            path = 'site-gate/'+name
            (out/'source'/path).write_bytes(pkg.git('show','HEAD:'+path))

def reviewed():
    sha = os.environ['GITHUB_SHA']
    candidates = [p['number'] for p in prod.github('/commits/'+sha+'/pulls') if p['merged_at']
                  and p['base']['ref']=='main' and p['head']['ref']=='feature/installed-release-explorer']
    pkg.require(len(candidates)==1,'Expected the reviewed installed-release explorer')
    prod.evidence(candidates[0])
    return candidates[0]

def healthy_backend():
    prod.await_read(firewall.ready)

def run(action,out):
    if action=='prepare':
        prepare(out)
        return
    pr = reviewed()
    if action=='preflight':
        prod.policy(picker.ENV)
        healthy_backend()
    elif action=='publish':
        picker.publish(out,changed=CHANGED,reviewed_pr=pr,ready=healthy_backend,
                       # Run 42688807113 uploaded this version but stopped before activation.
                       previous_upload='66ee47cd-e14b-456e-8e18-fe2d4a8766c1',
                       previous_version='28f26db5-bd5a-4e7e-b592-031c3aca8405',
                       previous_deployment='951a5c68-d87c-4f4e-9623-becb3c29b525')
    else:
        raise ValueError(action)
