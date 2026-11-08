"""Isolate manual labels and the severity layout on the verified production packages."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import customer_investigation_release as previous
import catalogue_package as package
import catalogue_promotion as promotion

BASE = 'feab635843d76a42103055ba7bcf16921c6a5106'
RUNTIME = ('assignment-acknowledgement.js','customer-remediation.js','remediation-identity.js','remediation.js','manual-assignment-context.js')
CHANGED = {'operations.js', 'remediation.css'} | previous.previous.ROUTES
PIN = Path('release/customer-investigation/manual-backend-identity.txt')


def backend(out):
    previous.reminder_backend(out, reviewed_ref=BASE)
    for name in RUNTIME:
        path = 'account-backend/src/' + name
        target = out/path
        if name == 'manual-assignment-context.js':
            package.require(not target.exists(), 'Unexpected production module')
        else:
            package.require(target.read_bytes() == package.git('show',BASE+':'+path), 'Unexpected live source for '+name)
        target.write_bytes(package.git('show','HEAD:'+path))


def site(out):
    previous.site(out, reviewed_ref=BASE)
    (out/'before').rename(out/'before_customer_release')
    (out/'after').rename(out/'before')
    shutil.copytree(out/'before',out/'after')
    for route in sorted(CHANGED):
        name = 'index.html' if route in previous.previous.ROUTES else route
        patch = package.git('diff','--no-ext-diff','--no-color',BASE,'HEAD','--',name)
        with tempfile.TemporaryDirectory(dir=out) as temp:
            path = Path(temp,name)
            target = out/'after'/route
            path.write_bytes(target.read_bytes())
            subprocess.run(['git','apply','--whitespace=nowarn','-'],input=patch,cwd=temp,
                           env={**os.environ,'GIT_CEILING_DIRECTORIES':str(out)},check=True)
            target.write_bytes(path.read_bytes())
    package.require({f for f in package.files(out/'after') if (out/'after'/f).read_bytes()!=(out/'before'/f).read_bytes()}==CHANGED,'Incorrect website scope')


def previous_ready():
    promotion.ready(Path('release/customer-investigation/reminder-backend-identity.txt').read_text().strip())


def ready():
    promotion.ready(PIN.read_text().strip())


def run(action,out):
    if action=='backend':
        backend(out)
        actual=subprocess.check_output(['node','--input-type=module','-e',"import {backendIdentity} from './scripts/build_release_identity.mjs';console.log(backendIdentity(process.argv[1]))",str(out)],text=True)
        package.require(actual.strip()==PIN.read_text().strip(),'Unexpected backend package')
    elif action=='prepare':
        site(out)
    elif action=='preflight':
        promotion.evidence(296)
        promotion.policy(previous.ENVIRONMENT)
        ready()
    elif action=='publish':
        promotion.publish(out,site_env=previous.ENVIRONMENT,pr_number=296,previous_version='a2b45aeb-a032-4cbf-8398-1cae7cf2c456',
                          previous_deployment='6eac0552-7600-4772-ac1a-8dea38f9142b',changed=CHANGED,readiness=ready)
    else:
        raise ValueError('Unknown release operation')


if __name__=='__main__':
    import sys
    run(sys.argv[1],Path(sys.argv[2]).resolve())
