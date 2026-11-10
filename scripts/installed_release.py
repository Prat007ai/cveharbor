"""Apply vendor scan evidence to the published installed-release explorer."""
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

LIVE_SITE = 'a36adf382569e5774b92cca1f95d54e95079df8d'
BASE = LIVE_SITE
CHANGED = {picker.MODULE}
MODULES = {'version-scan.mjs', 'catalogue-history.mjs'}

def prepare(out):
    with tempfile.TemporaryDirectory() as tmp:
        prior = Path(tmp)/'published'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),LIVE_SITE)
        try:
            subprocess.run([sys.executable,'scripts/session_navigation_release.py','prepare',str(out)],
                           cwd=prior,check=True,env={**os.environ,'CVEHARBOR_SITE_RELEASE':'installed-releases'})
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
                  and p['base']['ref']=='main' and p['head']['ref']=='fix/vendor-zero-scan-audit']
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
                       previous_version='ff45269c-0951-4b1b-884c-dda446327bda',
                       previous_deployment='91c6b82b-e08b-4ad2-b7ab-eb160abedf22')
    else:
        raise ValueError(action)
