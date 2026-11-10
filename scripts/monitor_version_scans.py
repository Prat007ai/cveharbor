"""Probe installed-product scans and reconcile empty result categories with public upstream evidence."""
import argparse
import base64
import calendar
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import time
from urllib.parse import urlencode

from catalogue_promotion import ORIGIN, request

CONFIG = json.loads((Path(__file__).resolve().parents[1]/'site-gate/version-products.json').read_text())
COMPONENTS = {'react':'optional', 'sitefinity':'optional', 'npm':'bundled'}


def period_start(day, months):
    year, month = divmod(day.year * 12 + day.month - 1 - months, 12)
    boundary = date(year, month+1, min(day.day, calendar.monthrange(year, month+1)[1]))
    return (boundary + timedelta(days=1)).isoformat()


def live_get(path):
    secret = os.environ['SITE_GATE_PASSWORD']
    auth = base64.b64encode(('cveharbor:'+secret).encode()).decode()
    for attempt in range(3):
        try:
            with request(ORIGIN+'v1/version-picker/'+path, {'Authorization':'Basic '+auth}) as response:
                return json.load(response)
        except (OSError, ValueError):
            if attempt == 2:
                raise
            time.sleep(2**attempt)


def targets(catalogue):
    cards = catalogue['cards']
    if {k:set(v) for k,v in cards.items()} != {k:set(v) for k,v in CONFIG['cards'].items()}:
        raise ValueError('Production technology cards differ from the reviewed inventory')
    ids = {key for products in cards.values() for key in products}
    if ids != set(catalogue['products']) or ids != set(CONFIG['products']):
        raise ValueError('Product coverage incomplete')
    for key in sorted(ids):
        releases = catalogue['releases'][key]
        versions = [releases['versions'][0]['version']]
        if key == 'ubuntu':
            # Noble uses its own Canonical notice path, regardless of the newest Ubuntu line.
            versions.append('24.04.5')
        for version in dict.fromkeys(versions):
            for months in (3,12):
                yield key,version,months


def probe(target, day, read=live_get):
    key,version,months = target
    result = dict(key=key,version=version,months=months,present=[])
    required = {'direct'}
    if key in COMPONENTS:
        required.add(COMPONENTS[key])
    cursor,quarter = '',0
    seen = set()
    present = set()
    try:
        while True:
            if (cursor,quarter) in seen:
                raise ValueError('repeated cursor')
            seen.add((cursor,quarter))
            page = read('scan?'+urlencode(dict(product=key,version=version,months=months,day=day,
                                               cursor=cursor,quarter=quarter)))
            if not isinstance(page['rows'],list) or not isinstance(page.get('componentRows',[]),list):
                raise ValueError('invalid scan rows')
            for row in [*page['rows'], *page.get('componentRows',[])]:
                if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not row['id'].strip():
                    raise ValueError('missing advisory identity')
            if page['rows']:
                present.add('direct')
            for row in page.get('componentRows',[]):
                if row['id'] and row['scope'] in ('bundled','optional'):
                    present.add(row['scope'])
            if required <= present:
                break
            if page['next']:
                cursor=page['next']
                if not isinstance(cursor,str) or len(cursor)>2048:
                    raise ValueError('invalid cursor')
            elif page['nextQuarter'] is not None:
                if page['nextQuarter']!=quarter+1 or page['nextQuarter']>=months//3:
                    raise ValueError('invalid quarter')
                quarter=page['nextQuarter']
                cursor=''
            else:
                break
        result['present']=sorted(present)
        result['empty']=sorted(required-present)
    except (OSError, KeyError, TypeError, ValueError) as exc:
        result['error']=type(exc).__name__+' while reading production'
    return result


def compare(results, day, expected, errors):
    failures = []
    report = []
    for scan in results:
        key,version,months = scan['key'],scan['version'],scan['months']
        label = f"{CONFIG['products'][key]['name']} {version} · {months} months"
        if scan.get('error'):
            failures.append(label+' — incomplete: '+scan['error'])
            continue
        for category in scan['empty']:
            ref = (key,version,category)
            since = period_start(day,months)
            matches = [r for r in expected.get(ref,[]) if since <= r['published'][:10] <= day.isoformat()]
            if matches:
                witness = max(matches,key=lambda row:row['published'])
                failures.append(f"{label} — zero {category} results. Vendor evidence: {witness['id']} ({witness['url']})")
            if errors.get(ref):
                failures.append(label+' — incomplete '+category+' check: '+', '.join(sorted(set(errors[ref]))))
            if not matches and not errors.get(ref):
                report.append(label+' — no matching public '+category+' advisory found'+
                              ('; private ESU coverage unverified' if key in ('sql2014','sql2016') else ''))
    return failures, report


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('action',choices=('probe','compare'))
    ap.add_argument('file',type=Path)
    args=ap.parse_args()
    if args.action=='probe':
        day=datetime.now(timezone.utc).date()-timedelta(days=1)
        catalogue=live_get('catalogue')
        with ThreadPoolExecutor(max_workers=3) as pool:
            scans=list(pool.map(lambda target:probe(target,day.isoformat()),targets(catalogue)))
        args.file.write_text(json.dumps(dict(day=day.isoformat(),cards=len(catalogue['cards']),scans=scans)))
        print(f"Probed {len(scans)} scan windows across {len(catalogue['cards'])} cards.")
    else:
        from monitor_vendor_sources import evidence
        audit=json.loads(args.file.read_text())
        day=date.fromisoformat(audit['day'])
        expected,errors=evidence(audit['scans'],period_start(day,12))
        failures,empty=compare(audit['scans'],day,expected,errors)
        lines=[f"## Daily production scan check · {day} UTC",
               f"{audit['cards']} cards · {len({s['key'] for s in audit['scans']})} products · {len(audit['scans'])} scan windows",
               '',f"**{len(failures)} exceptions**",'',*['- '+s for s in failures],
               '', '<details><summary>Empty results checked against public sources</summary>','',
               *['- '+s for s in empty], '', '</details>']
        report='\n'.join(lines)+'\n'
        print(report,flush=True)
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a',encoding='utf-8') as f:f.write(report)
        if failures:raise SystemExit(1)


if __name__=='__main__':
    main()
