"""Release only the CVIE evidence query and R2 readers on the serving packages."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

import catalogue_package as pkg
import catalogue_promotion as prod
import manual_customer_release as previous
from feed_snapshot import check_manifest, decode, digest

BASE = 'f4d3ef9ba79294b5ccd19cf23b8cc92717357741'
VERSION = '6c07c5e5-5301-454e-966a-e0625ec43a5b'
DEPLOYMENT = '072a3b38-409b-45fa-b46d-9d3717336c75'
ENV = 'cloudflare-site-production'
PIN = Path('release/intelligence-baseline/backend-identity.txt')


def backend(out):
    previous.run('backend', out)
    for name in ('src/cvie-records.js', 'src/intelligence-store.js', 'wrangler.toml'):
        relative = 'account-backend/' + name
        target = out / relative
        pkg.require(target.read_bytes() == pkg.git('show', BASE + ':' + relative), 'Unexpected baseline: ' + name)
        target.write_bytes(Path(relative).read_bytes())
    path = 'account-backend/src/index.js'
    # index.js on main also contains held features. Apply only the reviewed error-handler change.
    patch = pkg.git('diff', '--unified=1', BASE, 'HEAD', '--', path)
    subprocess.run(['git','apply','--whitespace=nowarn','-'], cwd=out, input=patch, check=True,
                   env={**os.environ, 'GIT_CEILING_DIRECTORIES': str(out.parent)})
    actual = subprocess.check_output(['node','--input-type=module','-e',
        "import {backendIdentity} from './scripts/build_release_identity.mjs';console.log(backendIdentity(process.argv[1]))",
        str(out)], text=True).strip()
    pkg.require(actual == PIN.read_text().strip(), 'Unexpected intelligence backend package')


def site(out):
    previous.site(out)
    shutil.copytree(out / 'after', out / 'before', dirs_exist_ok=True)
    source = out / 'source'
    for name in ('site-gate/worker.mjs','site-gate/wrangler.json','account-backend/src/intelligence-store.js'):
        dest = source / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(name, dest)


def receipt():
    run_id = os.environ['FEED_RUN_ID']
    pkg.require(re.fullmatch(r'[1-9][0-9]*', run_id), 'Invalid data run')
    run = prod.github('/actions/runs/' + run_id)
    pkg.require(run['path'] == '.github/workflows/publish-intelligence.yml' and run['head_branch'] == 'main'
                and run['head_sha'] == os.environ['GITHUB_SHA'] and run['status'] == 'completed'
                and run['event'] in ('workflow_dispatch','schedule'), 'Unverified publication run')
    r = json.loads(Path(os.environ['FEED_RECEIPT']).read_bytes())
    check_manifest({'schema':1,'files':r['files']})
    pkg.require(re.fullmatch(r'manifests/[0-9a-f]{64}\.json',r['manifest'])
                and r['collection']['advisories']['status'] == 'published', 'Missing fresh advisory snapshot')
    return r


def verify_published(r):
    version = r['manifest'][10:-5]
    pinned = re.compile(rb'(src="/(?:data\.js|malware-data\.js|threat-data\.js|lifecycle\.js|patch-notes\.js)(?:\?[^"<>]*?)?)[?&]feed_version=[a-f0-9]{64}"')
    def verify(path,auth,expected):
        source = 'data/feed-health.json' if path == 'feed-health.json' else path
        if source in r['files']:
            url = prod.ORIGIN + path + '?feed_version=' + version
            with prod.request(url, {'Authorization':auth}) as response:
                pkg.require(response.headers.get('X-CVEHarbor-Feed-Version') == version, 'Unexpected data version: ' + path)
                body = decode(source, response.read())
            pkg.require(digest(body) == r['files'][source]['sha256'], 'Published data differs: ' + path)
            if path == 'feed-health.json':
                health = json.loads(body)
                from datetime import datetime, timezone
                age = (datetime.now(timezone.utc) - datetime.fromisoformat(health['last_successful_update'])).total_seconds()
                pkg.require(-300 <= age <= 8*3600 and health['mode'] in ('live','partial'), 'Stale advisory health')
            return
        if path.endswith('.html'):
            live = prod.origin_bytes(path, prod.protected_asset(path,auth))
            pkg.require(digest(pinned.sub(rb'\1"',live)) == expected, 'Serving HTML changed: ' + path)
        else:
            prod.verify_asset(path,auth,expected)
    return verify


def run(action,out):
    if action == 'prepare':
        site(out)
    elif action == 'backend':
        backend(out)
    elif action == 'preflight':
        prod.evidence(298)
        prod.policy(ENV)
        previous.ready()
        receipt()
    elif action == 'publish':
        prod.publish(out, site_env=ENV, pr_number=298, previous_version=VERSION, previous_deployment=DEPLOYMENT,
                     changed=set(), readiness=previous.ready, verify_served=verify_published(receipt()))
    else:
        raise ValueError(action)

if __name__ == '__main__':
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
