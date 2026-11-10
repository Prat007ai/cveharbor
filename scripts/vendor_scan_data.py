"""Publish the vendor evidence used by installed SQL Server 2019 and Ubuntu Noble scans."""
import argparse
import bz2
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import html
import json
from pathlib import Path
import re
from urllib.request import Request, urlopen

import ijson

MSRC = 'https://api.msrc.microsoft.com/cvrf/v3.0/'
USNS = 'https://usn.ubuntu.com/usn-db/database.json.bz2'
CVE = re.compile(r'CVE-\d{4}-\d{4,}')
SQL = re.compile(r'Microsoft SQL Server 2019 for x64-based Systems(?: \((GDR|CU\s*\d+)\))?', re.I)


def read(url):
    return urlopen(Request(url, headers={'User-Agent': 'CVEHarbor vendor advisories', 'Accept': 'application/json'}), timeout=90)


def document(url):
    with read(url) as response:
        return json.load(response)


def plain(value):
    return html.unescape(re.sub(r'<[^>]+>', ' ', value)).strip()


def sql_month(month):
    data = document(MSRC + 'cvrf/' + month)
    products = {}
    for product in data['ProductTree']['FullProductName']:
        match = SQL.fullmatch(product['Value'])
        if match:
            products[product['ProductID']] = (match.group(1) or 'unspecified').replace(' ', '').upper()
    # A SQL KB can explicitly include a CVE omitted from the product-status
    # matrix. Verify the product bulletin and associate only its own fixes.
    bulletins = {}
    for vuln in data['Vulnerability']:
        for fix in vuln.get('Remediations', []):
            build = fix.get('FixedBuild', '')
            kb = (fix.get('Description') or {}).get('Value', '')
            for pid in set(fix.get('ProductID', [])) & products.keys():
                if fix['Type'] == 2 and re.fullmatch(r'15\.0\.\d+\.\d+', build or '') and re.fullmatch(r'\d{7}',kb):
                    bulletins[kb] = {'branch': products[pid], 'build': build, 'kb': kb}
    article_fixes = {}
    for kb, fix in bulletins.items():
        with read('https://support.microsoft.com/help/'+kb) as response:
            article = response.read().decode('utf-8')
        title = re.search(r'<title[^>]*>(.*?)</title>', article, re.I | re.S)
        if not title or 'sql server 2019' not in plain(title[1]).lower():
            raise ValueError('Could not validate SQL Server 2019 bulletin KB'+kb)
        linked = set(re.findall(r'https://msrc\.microsoft\.com/update-guide/(?:[a-z-]+/)?vulnerability/(CVE-\d{4}-\d{4,})', article, re.I))
        for cve in linked:
            article_fixes.setdefault(cve.upper(), []).append(fix)
    rows = []
    for v in data['Vulnerability']:
        affected = {p for s in v.get('ProductStatuses', []) if s['Type'] == 3 for p in s['ProductID'] if p in products}
        if (not affected and v['CVE'] not in article_fixes) or not CVE.fullmatch(v['CVE']):
            continue
        fixes = []
        for fix in v.get('Remediations', []):
            if fix['Type'] != 2 or not re.fullmatch(r'15\.0\.\d+\.\d+', fix.get('FixedBuild') or ''):
                continue
            for p in sorted(affected.intersection(fix.get('ProductID', []))):
                fixes.append({'branch': products[p], 'build': fix['FixedBuild'], 'kb': fix.get('Description', {}).get('Value', '')})
        for fix in article_fixes.get(v['CVE'], []):
            if fix not in fixes:
                fixes.append(fix)
        revisions = sorted(r['Date'] for r in v['RevisionHistory'])
        description = next((n.get('Value', '') for n in v.get('Notes', []) if n.get('Title') == 'Description'), '')
        score = max((s['BaseScore'] for s in v.get('CVSSScoreSets', []) if affected.intersection(s.get('ProductID', []))), default=None)
        rows.append({'id': v['CVE'], 'title': v['Title']['Value'], 'published': revisions[0][:19]+'Z',
                     'updated': revisions[-1][:19]+'Z', 'summary': plain(description), 'cvss': score, 'fixes': fixes})
    return rows


def microsoft(start, now):
    updates = document(MSRC+'updates')['value']
    months = sorted({u['ID'] for u in updates if re.fullmatch(r'\d{4}-[A-Z][a-z]{2}', u['ID'])
                     and start[:7] <= u['InitialReleaseDate'][:7] <= now[:7]})
    if len(months) < 12:
        raise ValueError('Incomplete MSRC monthly document directory')
    by_id = {}
    with ThreadPoolExecutor(max_workers=3) as pool:
        for rows in pool.map(sql_month, months):
            for row in rows:
                if row['published'] >= start and (row['id'] not in by_id or row['updated'] > by_id[row['id']]['updated']):
                    by_id[row['id']] = row
    return list(by_id.values())


def ubuntu(start):
    rows = []
    with read(USNS) as response, bz2.BZ2File(response) as archive:
        for key, notice in ijson.kvitems(archive, ''):
            release = notice['releases'].get('noble')
            if release is None:
                continue
            published = datetime.fromtimestamp(float(notice['timestamp']), timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            if published < start:
                continue
            if not re.fullmatch(r'\d+-\d+', key) or notice['id'].removeprefix('USN-') != key:
                raise ValueError('Unexpected notice identity')
            packages = {p: v.get('version') for p, v in release.get('sources', {}).items()}
            binaries = {p: v.get('version') for p, v in release.get('binaries', {}).items()}
            rows.append({'id': 'USN-'+key, 'title': notice['title'], 'published': published,
                         'summary': notice['description'], 'cves': [c for c in notice['cves'] if CVE.fullmatch(c)],
                         'packages': packages, 'binaries': binaries})
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    now = datetime.now(timezone.utc)
    stamp = now.strftime('%Y-%m-%dT%H:%M:%SZ')
    start = (now - timedelta(days=400)).date().isoformat()
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
    else:
        from feed_snapshot import S3Store
        store = S3Store()
    for product in ['sql2019', 'ubuntu-noble']:
        prefix = 'picker/vendor-v1/'+product+'/'
        revision = None
        if not args.output:
            previous, _ = store.get(prefix+'current.json')
            cached = json.loads(previous) if previous else {}
            if product == 'ubuntu-noble':
                # Canonical can issue several USNs between full database imports.
                # Check its public revision each run; only download again on change.
                request = Request(USNS, method='HEAD', headers={'User-Agent':'CVEHarbor vendor advisories'})
                with urlopen(request, timeout=30) as response:
                    revision = response.headers.get('ETag') or response.headers.get('Last-Modified')
            if cached:
                age = now - datetime.fromisoformat(cached['checked'])
                if age < timedelta(hours=12) and (product == 'sql2019' or
                        (revision and revision == cached.get('sourceRevision'))):
                    print(product, 'already refreshed')
                    continue
        rows = microsoft(start, stamp) if product == 'sql2019' else ubuntu(start)
        if not rows:
            raise ValueError('No vendor evidence for '+product)
        rows.sort(key=lambda r: (r['published'], r['id']), reverse=True)
        # Store each month independently; clients read at most four per quarter.
        # Publish the directory last, pointing only at verified, immutable objects.
        from hashlib import sha256
        months = {}
        for row in rows:
            months.setdefault(row['published'][:7], []).append(row)
        directory = {}
        def save(key, body, immutable):
            if args.output:
                (args.output/key.split('/')[-1]).write_bytes(body)
            elif immutable:
                store.immutable(key, body)
            else:
                _, etag = store.get(key)
                store.compare_set(key, body, etag)
        for month, entries in months.items():
            body = json.dumps(entries, separators=(',', ':'), ensure_ascii=False).encode()
            digest = sha256(body).hexdigest()
            save(prefix+digest+'.json', body, True)
            directory[month] = digest
        manifest = {'product': product, 'from': start, 'checked': stamp, 'months': directory}
        if revision:
            manifest['sourceRevision'] = revision
        digest = sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        manifest['snapshot'] = digest
        save(prefix+digest+'.json', json.dumps(manifest).encode(), True)
        save(prefix+'current.json' if not args.output else product+'.json', json.dumps(manifest).encode(), False)
        print(product, len(rows), 'vendor records; latest', rows[0]['published'], flush=True)


if __name__ == '__main__':
    main()
