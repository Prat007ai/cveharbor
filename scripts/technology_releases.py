"""Collect dated product releases. Keep the last verified result on individual source failure."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from functools import lru_cache
from html import unescape
import json
from pathlib import Path
import re
from urllib.parse import quote
from urllib.request import Request, urlopen

from collect_sql_updates import MicrosoftSqlParser

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT / 'site-gate/version-products.json').read_text())
SEED = ROOT / 'site-gate/version-releases.json'
KEY = 'picker/releases-v2.json'
RAW = 'https://raw.githubusercontent.com/endoflife-date/release-data/main/releases/'
INDEX = 'https://builds.dotnet.microsoft.com/dotnet/release-metadata/'
MS = 'https://learn.microsoft.com/en-us/'
PAGES = {
    'windows11': MS+'windows/release-health/windows11-release-information',
    'server': MS+'windows/release-health/windows-server-release-info',
    'exchange': MS+'exchange/new-features/build-numbers-and-release-dates',
    'sharepoint': MS+'officeupdates/sharepoint-updates',
    'sql': MS+'troubleshoot/sql/general/determine-version-edition-update-level',
    'esxi': 'https://knowledge.broadcom.com/external/article/316595',
    'forti': 'https://raw.githubusercontent.com/godstoge/fortios_release_dates/main/README.md',
    'android':'https://endoflife.date/api/v1/products/android/',
    'sophos': 'https://docs.sophos.com/nsg/licenses/index.html',
}
FORMATS = {'maria':r'\d+\.\d+\.\d+', 'sql2022':r'16\.0\.\d+\.\d+', 'kendo':r'(?:20\d\d)\.[1-4]\.\d{2,4}', 'triple':r'\d+\.\d+\.\d+', 'twoThree':r'\d+\.\d+(?:\.\d+)?',
           'four':r'\d+\.\d+\.\d+\.\d+', 'win':r'\d{5}\.\d+', 'android':r'\d+(?:\.\d+){0,2}',
           'sdk':r'\d+\.\d+\.\d{3}', 'sfos':r'\d+\.\d+ (?:GA|MR\d+) Build \d+', 'build':r'\d{6,9}'}

FORMATS.update({f'sql{year}': rf'{major}\.0\.\d+\.\d+' for year, major in
                [(2025,17),(2022,16),(2019,15),(2017,14),(2016,13),(2014,12)]})
FORMATS.update(ubuntu=r'\d{2}\.(?:04|10)(?:\.\d+)?', osPoint=r'\d+(?:\.\d+)?',
               integer=r'\d+', amazon=r'(?:2|20\d{2})(?:\.\d+\.\d{8}\.\d+)?')

def distribution(product):
    slug = product['source'].split(':')[1]
    url = 'https://endoflife.date/api/v1/products/'+slug+'/'
    releases = []
    for row in json.loads(read(url))['result']['releases']:
        if row['isEol'] is False:
            support = 'Security support'
        elif row.get('isEoes') is False:
            support = 'Extended support · check entitlement'
        else:
            continue
        latest = row.get('latest') or {}
        version = latest.get('name') or row['name']
        if not re.fullmatch(FORMATS[product['format']], version):
            raise ValueError('Unrecognized distribution version '+version)
        releases.append({'version':version, 'date':latest.get('date') or row['releaseDate'],
                         'line':row['name'], 'support':support})
    return url, releases

@lru_cache(maxsize=80)
def read(url):
    with urlopen(Request(url, headers={'User-Agent':'CVEHarbor-release-directory/1.0'}), timeout=18) as response:
        body = response.read(35_000_001)
    if len(body)>35_000_000:
        raise ValueError('Oversize response')
    return body.decode('utf-8-sig')

def day(value):
    for fmt in ('%Y-%m-%d','%Y/%m/%d','%B %d, %Y','%b %d, %Y','%m/%d/%Y'):
        try:
            return datetime.strptime(value.strip(),fmt).date().isoformat()
        except ValueError:
            pass
    return ''

def table(url):
    parser=MicrosoftSqlParser()
    parser.feed(read(url))
    return [cells for _,cells in parser.rows]

def rows(product):
    kind, key = product['source'].split(':',1)
    if kind=='release':
        url=RAW+key+'.json'
        versions=json.loads(read(url))['versions']
        return url, [(v,info['date']) for v,info in versions.items()]
    if kind=='npm':
        url='https://registry.npmjs.org/'+quote(key,safe='')
        data=json.loads(read(url))
        return url, [(v,date[:10]) for v,date in data['time'].items() if v in data['versions'] and 'deprecated' not in data['versions'][v]]
    if kind=='PyPI':
        url='https://pypi.org/pypi/'+key+'/json'
        return url, [(v,min(f['upload_time_iso_8601'] for f in files if not f['yanked'])[:10]) for v,files in json.loads(read(url))['releases'].items() if any(not f['yanked'] for f in files)]
    if kind=='NuGet':
        url='https://api.nuget.org/v3/registration5-semver1/'+key.lower()+'/index.json'
        releases=[]
        for page in json.loads(read(url))['items']:
            for item in (page.get('items') or json.loads(read(page['@id']))['items']):
                entry=item['catalogEntry']
                if entry.get('listed',True):
                    releases.append((entry['version'],entry['published'][:10]))
        return url,releases
    if kind=='dotnet':
        url=INDEX+'releases-index.json'
        releases=[]
        for channel in json.loads(read(url))['releases-index']:
            if channel['support-phase']=='preview' or not re.fullmatch(r'\d+\.\d+',channel['channel-version']):
                continue
            for item in json.loads(read(INDEX+channel['channel-version']+'/releases.json'))['releases']:
                builds=(item.get('sdks') or [item.get('sdk',{})]) if key=='sdk' else [item.get(key,{})]
                releases.extend((build['version'],item['release-date']) for build in builds if build and build.get('version'))
        return url,releases
    url=PAGES[key]
    releases=[]
    if key=='forti':
        return url,re.findall(r'\|\s*(\d+\.\d+\.\d+)\s*\|\s*(\d{4}-\d\d-\d\d)\s*\|',read(url))
    if key=='android':
        return url,[(entry['name'],entry['releaseDate']) for entry in json.loads(read(url))['result']['releases']]
    if key=='sophos':
        plain=' '.join(unescape(re.sub('<[^>]+>',' ',read(url))).split())
        for major,release,build in re.findall(r'(\d+\.\d+)\s*[-–]?\s*(GA|MR\s*\d+)\s*\(?Build\s*(\d+)',plain,re.I):
            releases.append((major+' '+release.upper().replace(' ','')+' Build '+build,''))
        return url,releases
    for cells in table(url):
        line=' '.join(cells)
        if key=='exchange' and not re.search(r'Exchange Server SE\b|Subscription Edition',line,re.I):continue
        if key=='sharepoint' and 'Subscription Edition' not in line:continue
        if key=='esxi' and not re.search(r'ESXi\b',line,re.I):continue
        pattern={'windows11':r'\d{5}\.\d+', 'server':r'\d{5}\.\d+', 'sql':FORMATS[product['format']],
                 'sharepoint':r'16\.0\.\d+\.\d+', 'exchange':r'15\.2\.\d+\.\d+', 'esxi':r'\d{7,9}'}[key]
        version=next((v for v in cells if re.fullmatch(pattern,v)),None)
        date=next((day(c) for c in cells if day(c)),'')
        if version and date:releases.append((version,date))
    return url,releases

def supported_lines(product, ordered, dates):
    slug = product.get('lifecycle')
    if not slug:
        return {}
    url = 'https://endoflife.date/api/v1/products/'+slug+'/'
    releases = json.loads(read(url))['result']['releases']
    choices = []
    for release in releases:
        extended = release.get('isEol') is True and release.get('isEoes') is False
        if release.get('isEol') is not False and not extended:
            continue
        line = release['name']
        prefix = line
        if slug == 'windows-server':
            prefix = (release.get('latest') or {}).get('name','').removeprefix('10.0.')
        if not re.fullmatch(r'\d+(?:\.\d+)*', prefix):
            continue
        version = next((v for v in ordered if v == prefix or v.startswith(prefix+'.')), None)
        if version:
            choices.append({'version':version, 'date':dates[version], 'line':line,
                            'support':'Extended support · check entitlement' if extended else 'Supported line'})
    return {'supported':choices, 'lifecycleUrl':url}

def collect_one(item):
    key,product=item
    try:
        if product['source'].startswith('distribution:'):
            url, versions = distribution(product)
            return key, {'url':url, 'checked':datetime.now(timezone.utc).isoformat(),
                         'order':'release line', 'versions':versions}
        url,raw=rows(product)
        latest={}
        for v,date in raw:
            if re.fullmatch(FORMATS[product['format']],v) and (not date or day(date)):
                latest[v]=max(latest.get(v,''),date)
        ordered=sorted(latest,key=lambda v:(latest[v],tuple(map(int,re.findall(r'\d+',v)))),reverse=True)
        if not ordered:raise ValueError('No matching stable releases')
        # Keep the quick list short while exposing other release lines on demand.
        # Windows build trains and SQL build numbers use different version components.
        def line(version):
            parts=version.split('.')
            if product['source']=='ms:sql':
                return product['name']
            if product['format'] in ('build','sfos'):
                return product['name']
            return parts[0]
        by_line={}
        for v in ordered:
            by_line.setdefault(line(v), []).append({'version':v,'date':latest[v]})
        return key,{'lines':{name:values[:10] for name,values in by_line.items()},
                    **supported_lines(product, ordered, latest),'url':url,'checked':datetime.now(timezone.utc).isoformat(),
                    'order':'publication' if all(latest.values()) else 'version',
                    'versions':[{'version':v,'date':latest[v]} for v in ordered[:10]]}
    except Exception as exc:
        print(key,type(exc).__name__,str(exc)[:100],flush=True)
        return key,None

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--publish',action='store_true')
    options=parser.parse_args()
    old=json.loads(SEED.read_text()) if SEED.exists() else {}
    if options.publish:
        from feed_snapshot import S3Store
        store=S3Store()
        raw,etag=store.get(KEY)
        if raw:old.update(json.loads(raw))
        now=datetime.now(timezone.utc)
        if raw and all(entry.get('checked','')[:10]==now.date().isoformat() for entry in old.values()) and set(old)==set(CONFIG['products']):return
    with ThreadPoolExecutor(max_workers=6) as pool:
        for key,data in pool.map(collect_one,CONFIG['products'].items()):
            if data:old[key]=data
    print('Products with release lists:',len(old),'/',len(CONFIG['products']))
    encoded=json.dumps(old,indent=2,sort_keys=True).encode()+b'\n'
    if options.publish:store.compare_set(KEY,encoded,etag)
    else:SEED.write_bytes(encoded)

if __name__=='__main__':main()
