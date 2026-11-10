"""Publisher evidence for installed bundles and separately configured renderers."""
import base64
import hashlib
import io
import json
import re
import tarfile
from urllib.request import Request

SITEFINITY = 'https://community.progress.com/s/article/Sitefinity-Critical-Security-Advisory-for-Addressing-Security-Vulnerabilities-in-Next-js-October-2026'
REACT_PACKAGES = {'react-server-dom-parcel', 'react-server-dom-webpack', 'react-server-dom-turbopack'}


def component_row(advisory, items, scope, evidence):
    return dict(id=advisory.get('cve_id') or advisory['ghsa_id'], published=advisory['published_at'],
                scope=scope, title=advisory['summary'], summary=(advisory.get('description') or '')[:1800],
                status='Published component advisory', severity=advisory.get('severity'),
                url=advisory['html_url'], sources=[{'url':advisory['html_url'],'label':'Security advisory'}],
                affected='; '.join(items), evidence=evidence)


def renderer_history(start, out, load):
    target = out['react~components']
    page = 1
    while True:
        rows = load(f'https://api.github.com/repos/facebook/react/security-advisories?per_page=100&page={page}')
        for a in rows:
            if a.get('withdrawn_at') or a['published_at'] < start:
                continue
            packages = [v for v in a['vulnerabilities'] if v['package']['name'] in REACT_PACKAGES]
            if packages:
                row = component_row(a, [v['package']['name']+' '+v['vulnerable_version_range'] for v in packages],
                                    'optional', 'Optional server component · verify package and version')
                row['remediation'] = '; '.join(v['package']['name']+' · '+v['patched_versions']
                                              for v in packages if v.get('patched_versions'))
                target[row['id']] = row
        if len(rows) < 100:
            break
        page += 1
    # Progress maps upstream Next.js advisories to renderer builds in KB 000306531.
    target = out['sitefinity~components']
    if start <= '2026-11-03':
        for ghsa, affected, fixed in [('GHSA-vcvr-r3jv-pc5j','15.4.8631 through 15.4.8639','15.4.8640'),
                                      ('GHSA-673q-mjm6-r5xr','15.4.8631 through 15.4.8640 and 15.4.8641-rc.1532528','15.4.8641')]:
            a = load('https://api.github.com/advisories/'+ghsa)
            if a.get('withdrawn_at'):
                continue
            row = component_row(a, ['Sitefinity Next.js renderer '+affected], 'optional',
                                'Optional Next.js renderer · verify build and site customizations')
            row.update(published='2026-11-03T00:00:00Z', status='Progress Sitefinity notice · KB 000306531',
                       summary='Progress identifies exposure in customized sites that use the affected renderer functionality. Check the separately installed renderer build.',
                       remediation='Progress lists renderer '+fixed+' as the first stable release carrying this fix.')
            row['sources'].insert(0, {'url':SITEFINITY,'label':'Progress renderer notice'})
            target[row['id']] = row


def bundled_packages(version, load, fetch):
    metadata = load('https://registry.npmjs.org/npm/'+version)
    url = 'https://registry.npmjs.org/npm/-/npm-'+version+'.tgz'
    if metadata['dist']['tarball'] != url or metadata['version'] != version:
        raise ValueError('Unexpected npm release identity')
    with fetch(url) as response:
        raw = response.read(32*1024*1024+1)
    digest = base64.b64encode(hashlib.sha512(raw).digest()).decode()
    if len(raw)>32*1024*1024 or 'sha512-'+digest != metadata['dist']['integrity']:
        raise ValueError('Unverified npm release archive')
    packages = set()
    installed_paths = set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
        for member in archive:
            if not member.isfile() or not re.fullmatch(r'package/(?:node_modules/(?:@[^/]+/)?[^/]+/)+package\.json',member.name):
                continue
            manifest = json.load(archive.extractfile(member))
            # Aliases can have a different directory name from their published package.
            installed_paths.add(member.name.rsplit('/node_modules/',1)[1].removesuffix('/package.json'))
            packages.add((manifest['name'],manifest['version']))
    required = set(metadata.get('bundleDependencies') or metadata.get('bundledDependencies') or [])
    if not packages or not required or required - installed_paths:
        raise ValueError('Incomplete npm bundle')
    return packages


def npm_history(start, out, versions, load, fetch):
    releases = {v:bundled_packages(v,load,fetch) for v in versions}
    packages = sorted(set.union(*releases.values()))
    matches = {}
    for i in range(0,len(packages),100):
        batch = packages[i:i+100]
        queries = [{'package':{'ecosystem':'npm','name':p},'version':v} for p,v in batch]
        with fetch(Request('https://api.osv.dev/v1/querybatch', data=json.dumps({'queries':queries}).encode(),
                           headers={'Content-Type':'application/json','User-Agent':'CVEHarbor advisory history'})) as r:
            results = json.load(r)['results']
        if len(results) != len(batch) or any(r.get('next_page_token') for r in results):
            raise ValueError('Incomplete bundled-package advisory query')
        matches.update({pair:[a['id'] for a in r.get('vulns',[])] for pair,r in zip(batch,results)})
    advisories = {}
    for version, pairs in releases.items():
        target = out['npm@'+version+'~components']
        for name, installed in sorted(pairs):
            for ident in matches[name,installed]:
                if ident not in advisories:
                    advisories[ident] = load('https://api.osv.dev/v1/vulns/'+ident)
                a = advisories[ident]
                if a.get('withdrawn') or a['published'] < start:
                    continue
                cve = next((v for v in a.get('aliases',[]) if v.startswith('CVE-')),ident)
                url = 'https://osv.dev/vulnerability/'+ident
                row = target.setdefault(cve, dict(id=cve, scope='bundled', title=a.get('summary') or cve,
                    published=a['published'], summary=(a.get('details') or '')[:1800], status='Verified npm bundle contents',
                    evidence='Affected package version shipped inside npm '+version, url=url, affected='',
                    sources=[{'url':r['url']} for r in a.get('references',[]) if r.get('url','').startswith('https://')][:10]
                           + [{'url':'https://registry.npmjs.org/npm/'+version,'label':'npm release manifest'}]))
                row['affected'] = ', '.join(filter(None,[row['affected'], name+' '+installed]))
