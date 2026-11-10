"""Assemble PR 318 on the verified production packages."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import catalogue_package as pkg
import catalogue_promotion as prod
import version_picker_release as picker

FEATURE = '86b431c72fca8647aa0e08c3c7f3e220729bcbc7'
BASE = '6bf49474404eaeea3ca916a7dcc8a549c88b2611'
WORKER = 'ff21524332eaeb7483014cc3b7179a9f707817aa'
SITE = 'f13131b0905dee86bfbf694221822e8384da3cda'
SQL_SITE = '94378f48e8dde85b3de2109c841696c89b68a6c5'
PAGES = {'account/index.html', 'workspace/index.html'}
ASSETS = {'team-admin.js', 'team-entry.js', 'team-ui.js', 'team-workspace.js', 'team-access.css'}
MODULES = {'team-access.js', 'team-data.js', 'team-mail.js', 'team-invitation-art.js'}


def previous(commit, script, action, out, site_release='installed-releases'):
    with tempfile.TemporaryDirectory() as tmp:
        checkout = Path(tmp) / 'base'
        pkg.git('-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(checkout), commit)
        try:
            env = {**os.environ, 'CVEHARBOR_SITE_RELEASE': site_release}
            # Rebuild an already verified historical package. It is not a new GitHub deployment.
            env.pop('GITHUB_ACTIONS', None)
            subprocess.run([sys.executable, 'scripts/'+script, action, str(out)], check=True, cwd=checkout, env=env)
        finally:
            pkg.git('worktree','remove','--force',str(checkout))


def overlay(target, name):
    with tempfile.TemporaryDirectory() as tmp:
        old, new = Path(tmp)/'old', Path(tmp)/'new'
        old.write_bytes(pkg.git('show', BASE+':'+name))
        new.write_bytes(pkg.git('show', FEATURE+':'+name))
        prefix=b''
        if name=='account-backend/src/index.js':
            prefix=b"import {teamRoute} from './team-access.js';\n"
            pkg.require(new.read_bytes().startswith(prefix) and prefix not in target.read_bytes(),'Unexpected routing import')
            new.write_bytes(new.read_bytes()[len(prefix):])
        merged = pkg.git('merge-file','-p',str(target),str(old),str(new))
        target.write_bytes(prefix+merged)


def identity(out):
    return subprocess.check_output(['node','--input-type=module','-e',
        "import {backendIdentity} from './scripts/build_release_identity.mjs';console.log(backendIdentity(process.argv[1]))",
        str(out)],text=True).strip()


def backend(out, enabled):
    previous(WORKER,'firewall_release.py','backend',out)
    pkg.require(identity(out)==Path('release/firewall-backend-identity.txt').read_text().strip(),'Worker baseline mismatch')
    for name in ('index.js','inventory.js','customer-remediation.js'):
        relative='account-backend/src/'+name
        overlay(out/relative,relative)
    for name in MODULES:
        relative='account-backend/src/'+name
        pkg.require(not (out/relative).exists(),'Module collision')
        (out/relative).write_bytes(pkg.git('show',FEATURE+':'+relative))
    config=out/'account-backend/wrangler.toml'
    before=config.read_bytes()
    pkg.require(before.count(b'[vars]\n')==1 and b'TEAM_ACCESS_ENABLED' not in before,'Unexpected Worker settings')
    flag=b'true' if enabled else b'false'
    config.write_bytes(before.replace(b'[vars]\n',b'[vars]\nTEAM_ACCESS_ENABLED = "'+flag+b'"\n'))
    state = 'enabled' if enabled else 'disabled'
    expected = Path('release/team-backend-'+state+'.txt').read_text().strip()
    actual = identity(out)
    pkg.require(actual == expected, 'Team & Access '+state+' package differs from the reviewed build')
    print(actual,flush=True)


def prepare(out):
    previous(SQL_SITE, 'session_navigation_release.py', 'prepare', out, site_release='sql-esu-coverage')
    shutil.copytree(out/'after',out/'before',dirs_exist_ok=True)
    for name in PAGES:
        overlay(out/'after'/name,name)
    for name in ASSETS|{'team-invitation-art.js'}:
        relative='account-backend/src/'+name if name=='team-invitation-art.js' else name
        dest=out/'after'/name
        pkg.require(not dest.exists(),'Unexpected existing team asset')
        reviewed_asset = pkg.git('show', FEATURE+':'+relative)
        pkg.require(pkg.git('show', 'HEAD:'+relative) == reviewed_asset,
                    'Team website asset changed since PR 318: '+relative)
        dest.write_bytes(reviewed_asset)


def refresh_backend(out):
    backend(out, True)
    module = 'account-backend/src/cvie-records.js'
    target = out/module
    pkg.require(target.read_bytes() == pkg.git('show', 'f44bacc15906f99941591c60c10aa2bc66a1d830:'+module),
                'Advisory query module differs from the serving predecessor')
    target.write_bytes(pkg.git('show', 'HEAD:'+module))
    pkg.require(identity(out) == Path('release/cvie-refresh-backend.txt').read_text().strip(),
                'CVIE refresh package differs from the reviewed build')


def reviewed(branch='release/organization-team-access'):
    prs = prod.github('/commits/'+os.environ['GITHUB_SHA']+'/pulls')
    matches = [p['number'] for p in prs if p['merged_at'] and p['base']['ref']=='main'
               and p['head']['ref']==branch]
    pkg.require(len(matches)==1,'Expected reviewed team release package')
    prod.evidence(matches[0])
    return matches[0]


def site(action,out):
    if action=='prepare':
        prepare(out)
        return
    pr=reviewed()
    def ready():
        prod.ready(Path('release/team-backend-disabled.txt').read_text().strip())
    if action=='preflight':
        prod.policy(picker.ENV)
        ready()
    elif action=='publish':
        picker.publish(out,changed=PAGES,added=ASSETS|{'team-invitation-art.js'},reviewed_pr=pr,ready=ready,
                       previous_version='8bb8db48-be38-4a72-a6b2-c5b19da84034',
                       previous_deployment='f9a0a3d2-2f0e-4449-8c0c-656cd4017481')
    else:
        raise ValueError(action)


if __name__=='__main__':
    action=sys.argv[1]
    output=Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None
    if action == 'cvie-refresh':
        refresh_backend(output)
    elif action in ('disabled','enabled'):
        backend(output,action=='enabled')
    else:
        site(action,output)
