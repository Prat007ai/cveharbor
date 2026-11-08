"""Promote the six reviewed changes on top of the serving PR 291 packages."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import assignment_release as previous
import catalogue_package as package
import catalogue_promotion as promotion
from session_navigation_release import ENVIRONMENT

BASE = '131951c029504940959f79374856c5a2c0d0a30b'
VERSION = '78a1823b-399f-46be-9bfa-50d7245bf6e9'
DEPLOYMENT = '8f1eada2-0fdd-4d1e-863d-f0546583444a'
SITE = {'operations.js', 'advisory-details.js', 'remediation.css', 'styles.css'} | previous.ROUTES
BACKEND = {'assignment-acknowledgement.js', 'assignment-template.js', 'assignment-fyi.js',
           'customer-remediation.js', 'remediation.js'}


def backend(out):
    previous.backend(out, reviewed_ref=BASE)
    for name in BACKEND:
        path = 'account-backend/src/' + name
        target = out / path
        package.require(target.read_bytes() == package.git('show', BASE + ':' + path),
                        'Production baseline differs for ' + path)
        target.write_bytes(package.git('show', 'HEAD:' + path))


def site(out):
    previous.site(out, reviewed_ref=BASE)
    (out / 'before').rename(out / 'before_assignment')
    (out / 'after').rename(out / 'before')
    shutil.copytree(out / 'before', out / 'after')
    for name in sorted(SITE):
        source = 'index.html' if name in previous.ROUTES else name
        target = out / 'after' / name
        patch = Path('release/customer-investigation', source + '.patch')
        if patch.is_file():
            with tempfile.TemporaryDirectory(dir=out) as scratch:
                candidate = Path(scratch, source)
                candidate.write_bytes(target.read_bytes())
                subprocess.run(['git', 'apply', '--whitespace=nowarn', str(patch.resolve())],
                               cwd=scratch, env={**os.environ, 'GIT_CEILING_DIRECTORIES': str(out)}, check=True)
                target.write_bytes(candidate.read_bytes())
        else:
            baseline = package.git('show', BASE + ':' + source)
            reviewed = package.git('show', 'HEAD:' + source)
            if source == 'remediation.css':
                package.require(reviewed.startswith(baseline), 'Expected only assignment and record style additions')
                target.write_bytes(target.read_bytes() + reviewed[len(baseline):])
            else:
                package.require(target.read_bytes() == baseline, 'Unexpected live source for ' + source)
                target.write_bytes(reviewed)
    package.require({n for n in package.files(out / 'after') if (out / 'before' / n).read_bytes() !=
                     (out / 'after' / n).read_bytes()} == SITE, 'Unexpected production website scope')


def ready():
    promotion.ready(Path('release/customer-investigation/backend-identity.txt').read_text().strip())


def run(action, out=None):
    if action == 'prepare':
        site(out)
    elif action == 'backend':
        backend(out)
    elif action == 'preflight':
        promotion.evidence(293)
        promotion.policy(ENVIRONMENT)
        ready()
    elif action == 'publish':
        promotion.publish(out, site_env=ENVIRONMENT, pr_number=293, previous_version=VERSION,
                          previous_deployment=DEPLOYMENT, changed=SITE, readiness=ready)
    else:
        raise ValueError('Unknown release action')


if __name__ == '__main__':
    import sys
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)

