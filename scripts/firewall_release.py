"""Assemble the newsletter on the production Worker and website baselines."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import catalogue_package as pkg
import catalogue_promotion as prod
import version_picker_release as picker

BASE = '652a6fdf01492a6d578f793be72a17541c13e74b'
BACKEND = '61344d38b5987fc24c0ecf8d35039aac808f1420'
VERSION = '936febdd-1808-4c4f-810b-d1a318ec0c94'
DEPLOYMENT = 'b8c33d71-effe-49be-a2c6-0fd60182b20f'


def reviewed_pr():
    prs = prod.github('/commits/' + os.environ['GITHUB_SHA'] + '/pulls')
    found = [p['number'] for p in prs if p['merged_at'] and p['base']['ref'] == 'main'
             and p['head']['ref'] == 'fix/firewall-confirm-browser']
    pkg.require(len(found) == 1, 'Expected reviewed firewall email design PR')
    delta = set(pkg.git('diff','--name-only','a090612334a24bdb5c4630fe03ee51db0e4babad',
                        os.environ['GITHUB_SHA']).decode().splitlines())
    pkg.require(delta == {'scripts/firewall_release.py','account-backend/src/firewall-templates.js',
                'account-backend/src/firewall-artwork.js','account-backend/src/index.js',
                'account-backend/tests/firewall-digest.test.mjs','release/firewall-backend-identity.txt'},
                'Unexpected changes outside the firewall email release')
    prod.evidence(found[0])
    return found[0]


def overlay(out, name, relative):
    with tempfile.TemporaryDirectory() as tmp:
        old, new = Path(tmp)/'old', Path(tmp)/'new'
        old.write_bytes(pkg.git('show', BASE + ':' + name))
        new.write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
        merged = pkg.git('merge-file', '-p', str(out/relative), str(old), str(new))
        (out/relative).write_bytes(merged)


def backend(out):
    with tempfile.TemporaryDirectory() as tmp:
        prior = Path(tmp)/'prior'
        pkg.git('-c','core.autocrlf=false','worktree','add','--detach',str(prior),BACKEND)
        try:
            subprocess.run([sys.executable,'scripts/intelligence_release.py','backend',str(out)],cwd=prior,check=True)
        finally:
            pkg.git('worktree','remove','--force',str(prior))
    # Main also contains held features. Insert only the reviewed firewall hooks.
    from difflib import SequenceMatcher
    name = 'account-backend/src/index.js'
    old = pkg.git('show', BASE+':'+name).decode().splitlines(keepends=True)
    new = Path(name).read_text().splitlines(keepends=True)
    target = out/name
    live = target.read_bytes().decode()
    added = 0
    for op, start, end, first, last in SequenceMatcher(None,old,new,autojunk=False).get_opcodes():
        if op == 'equal':
            continue
        pkg.require(op == 'insert', 'Only additive firewall hooks are allowed')
        addition = ''.join(new[first:last])
        if start and live.count(old[start-1]) == 1:
            live = live.replace(old[start-1],old[start-1]+addition,1)
        elif live.count(old[end]) == 1:
            live = live.replace(old[end],addition+old[end],1)
        else:
            raise ValueError('Missing unique production hook')
        added += 1
    pkg.require(added == 4, 'Unexpected number of firewall hooks')
    target.write_bytes(live.encode())
    for name in ('firewall-digest.js','firewall-templates.js','firewall-artwork.js'):
        target = out/'account-backend/src'/name
        pkg.require(not target.exists(), 'Unexpected firewall module in baseline')
        target.write_bytes(Path('account-backend/src',name).read_bytes().replace(b'\\r\\n',b'\\n'))


def ready():
    prod.ready(Path('release/firewall-backend-identity.txt').read_text().strip())


def site(action,out):
    if action == 'prepare':
        picker.prepare(out)
        shutil.copytree(out/'after',out/'before',dirs_exist_ok=True)
        overlay(out,'operations.js','after/operations.js')
    elif action == 'preflight':
        reviewed_pr()
        prod.policy(picker.ENV)
        ready()
    elif action == 'publish':
        picker.publish(out,changed={'operations.js'},previous_version=VERSION,previous_deployment=DEPLOYMENT,
                       reviewed_pr=reviewed_pr(),ready=ready)
    else:
        raise ValueError(action)


if __name__ == '__main__':
    if sys.argv[1] != 'backend':
        raise ValueError('Expected backend')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        reviewed_pr()
        prod.ready('b892d1d656658579e43277054bd05d5b8c7cdab89fbaf583f1652f08528f67a3')
    backend(Path(sys.argv[2]).resolve())

