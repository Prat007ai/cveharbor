"""Build the installed-product advisory history from publisher records and distribution notices."""
import argparse
import bz2
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import time
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
from urllib.parse import quote, urlencode, urljoin
from urllib.request import Request, urlopen
from zipfile import ZipFile
import xml.etree.ElementTree as ET

import ijson
from catalogue_vendor_bulletins import sql_bulletins, sophos_bulletins

ROOT = Path(__file__).resolve().parents[1]
CONFIG = json.loads((ROOT/'site-gate/version-products.json').read_text())['products']
PREFIX = 'picker/history-v1/'
DISTROS = {'AlmaLinux':'almalinux', 'Alpine':'alpine-linux', 'Debian':'debian', 'Rocky Linux':'rocky-linux',
           'Red Hat':'rhel', 'SUSE':'sles', 'openSUSE':'opensuse', 'Android':'android'}
# Vendor and product names must both match. Topic labels are broader than installations.
RULES = {
    'win11': ('microsoft',r'windows 11(?: version .+)?'), 'server': ('microsoft',r'windows server (?:20\d\d|2008 r2).*'),
    'exchange': ('microsoft',r'(?:microsoft )?exchange server subscription edition.*'),
    'sharepoint': ('microsoft',r'(?:microsoft )?sharepoint server subscription edition.*'),
    'runtime': ('microsoft',r'\.net(?: \d+(?:\.\d+)?(?: runtime| installed on .+)?)?'),
    'aspnet': ('microsoft',r'asp\.net core(?: .+)?'), 'sdk': ('microsoft',r'\.net(?: core)? sdk(?: .+)?'),
    'wordpress': ('wordpress(?: foundation)?|automattic',r'wordpress(?: core)?'),
    'linux': ('linux',r'linux(?: kernel)?'), 'php': ('php(?: group)?',r'php'),
    'python': ('python software foundation|python',r'cpython|python'), 'mysql': ('oracle(?: corporation)?',r'mysql server'),
    'maria': ('mariadb(?: foundation| corporation)?',r'mariadb(?: server)?'),
    'veeam': ('veeam(?: software)?',r'(?:veeam )?backup (?:and|&) replication.*'),
    'docker': ('moby|docker',r'moby|docker engine(?: overlay network driver)?'),
    'k8s': ('kubernetes',r'kubernetes'), 'mongo': (r'mongodb(?:,? inc\.?)?',r'mongodb server'),
    'ios': ('apple',r'ios(?: and ipados)?'), 'node': (r'nodejs|node\.js|openjs foundation',r'node\.?js'),
    'drupal': ('drupal',r'drupal(?: core)?'), 'forti': ('fortinet',r'fortios'),
    'sophos': ('sophos',r'(?:sophos )?firewall(?: os)?|sfos|xg firewall'),
    'esxi': ('vmware|broadcom',r'(?:vmware )?esxi?(?: .*)?'), 'sitefinity': ('progress(?: software)?',r'sitefinity(?: cms)?'),
}
for key, year in [('sql2025',2025),('sql',2022),('sql2017',2017),('sql2016',2016),('sql2014',2014)]:
    RULES[key] = ('microsoft',rf'(?:microsoft )?sql server {year}(?: .*)?')


@lru_cache(maxsize=65536)
def identify(vendor, product):
    return [key for key,(v,p) in RULES.items() if re.fullmatch(v,vendor,re.I) and re.fullmatch(p,product,re.I)]


def fetch(url):
    for attempt in range(3):
        try:
            return urlopen(Request(url,headers={'User-Agent':'CVEHarbor advisory history','Accept':'*/*'}),timeout=90)
        except OSError:
            if attempt==2:raise
            time.sleep(2**attempt)


def load_json(url):
    with fetch(url) as f:
        return json.load(f)


def archive(tmp,name,url):
    path=tmp/(name+'.zip')
    if not path.exists():
        with fetch(url) as src,path.with_suffix('.part').open('wb') as dest:
            shutil.copyfileobj(src,dest,1024*1024)
        path.with_suffix('.part').replace(path)
    return path


def records(path, cve_only=False):
    with ZipFile(path) as z:
        for f in z.infolist():
            if f.filename.endswith('.json') and (not cve_only or re.search(r'(?:^|/)CVE-\d{4}-\d+\.json$',f.filename)):
                yield json.loads(z.read(f))


def compact(text,limit=1800):
    text=' '.join(str(text or '').split())
    return text if len(text)<=limit else text[:limit].rsplit(' ',1)[0]+'… See the source for full details.'


def put(out,key,row):
    if not row['id'] or not row['published']:
        raise ValueError('Missing advisory identity or date')
    out[key][row['id']]=row


def cve_history(tmp,start,out):
    release=load_json('https://api.github.com/repos/CVEProject/cvelistV5/releases/latest')
    if release['published_at'][:10] < (datetime.now(timezone.utc)-timedelta(days=2)).date().isoformat():
        raise ValueError('CVE Program bulk publication is stale')
    assets=release['assets']
    full=next(a for a in assets if 'all_CVEs_at_midnight' in a['name'])
    outer=archive(tmp,'cves',full['browser_download_url'])
    inner=tmp/'records.zip'
    if not inner.exists():
        with ZipFile(outer) as z,z.open('cves.zip') as src,inner.open('wb') as dest:shutil.copyfileobj(src,dest,1024*1024)
    delta=next((a for a in assets if '_delta_CVEs_' in a['name']),None)
    node={c:a for a in load_json('https://raw.githubusercontent.com/nodejs/security-wg/main/vuln/core/index.json').values()
          for c in (a.get('cve') or [])}
    changes={}
    if delta:
        for v in records(archive(tmp,'delta-'+str(delta['id']),delta['browser_download_url'])):
            if isinstance(v,dict) and 'cveMetadata' in v:changes[v['cveMetadata']['cveId']]=v
    from itertools import chain
    for v in chain((v for v in records(inner, cve_only=True) if v.get('cveMetadata',{}).get('cveId') not in changes), changes.values()):
        meta=v.get('cveMetadata',{})
        if meta.get('state')!='PUBLISHED' or meta.get('datePublished','')<start:continue
        cna=v['containers']['cna']
        matches=defaultdict(list)
        for a in cna.get('affected',[]):
            for key in identify(a.get('vendor','').strip(),a.get('product','').strip()):
                matches[key].append(a)
        refs=[r['url'] for r in cna.get('references',[]) if r.get('url','').startswith('https://')]
        # The Node.js project publishes its own security releases through HackerOne
        # with unspecified affected fields on some CVE records.
        if meta['cveId'] in node or any(re.match(r'https://nodejs\.org/(?:en/)?blog/vulnerability/',u) for u in refs):
            matches.setdefault('node',[])
        title=cna.get('title','')
        desc=next((d['value'] for d in cna.get('descriptions',[]) if d.get('lang','').startswith('en')),'')
        if 'server' in matches and re.search(r'\bhyper-v\b',title,re.I):matches['hyperv']=matches['server']
        for key,entries in matches.items():
            numeric=set();conditions=[]
            for a in entries:
                product=a['product']
                for rule in a.get('versions',[]):
                    if rule.get('status')!='affected' or rule.get('versionType')=='git':continue
                    lo=rule.get('version','');upper=rule.get('lessThan') or rule.get('lessThanOrEqual','')
                    inclusive='lessThanOrEqual' in rule
                    conditions.append(product+' · '+lo+((' through ' if inclusive else ' to before ')+upper if upper else ''))
                    if (not rule.get('changes') and rule.get('versionType','custom') in ['custom','semver','version']
                        and re.fullmatch(r'\d+(?:\.\d+){0,3}',lo) and re.fullmatch(r'\d+(?:\.\d+){0,3}',upper)):
                        numeric.add((lo,upper,inclusive))
            metrics=[m for entry in cna.get('metrics',[]) for name,m in entry.items() if name.startswith('cvss') and isinstance(m,dict)]
            ident=meta['cveId'];url='https://www.cve.org/CVERecord?id='+ident
            row=dict(id=ident,published=meta['datePublished'],title=compact(title or desc or ident,170),summary=compact(desc),
                     status='Published CVE record · '+cna.get('providerMetadata',{}).get('shortName','CVE Program'),
                     url=url,sources=[{'url':u} for u in refs[:12]]+[{'url':url,'label':'CVE Program record'}],
                     affected=compact('; '.join(dict.fromkeys(conditions)),1800),ranges=sorted(numeric),
                     evidence='Product advisory · check edition and vendor conditions')
            if metrics:row.update(cvss=metrics[0].get('baseScore'),severity=str(metrics[0].get('baseSeverity','unrated')).lower())
            if key=='node' and ident in node:
                a=node[ident];row.update(affected=a.get('vulnerable',''),remediation=a.get('patched',''))
                row['sources'].insert(0,{'url':a['ref'],'label':'Node.js security release'})
            put(out,key,row)


def osv_row(v,items,status):
    ident=next((i for i in v.get('aliases',[]) if i.startswith('CVE-')),v['id']) if status=='Reviewed package advisory' else v['id']
    refs=[{'url':r['url'],'label':r.get('type','Source').title()} for r in v.get('references',[]) if r.get('url','').startswith('https://')]
    url='https://osv.dev/vulnerability/'+quote(v['id'])
    fixes=[];ranges=[]
    for a in items:
        pkg=a.get('package',{}).get('name','')
        for rg in a.get('ranges',[]):
            lower=None
            for ev in rg.get('events',[]):
                if 'introduced' in ev:lower=ev['introduced']
                upper=ev.get('fixed') or ev.get('last_affected')
                if upper:
                    fixes.append(pkg+' · '+upper+(' (last affected)' if 'last_affected' in ev else ' (fixed)'))
                    if lower is not None and rg['type']=='SEMVER':ranges.append((lower,upper,'last_affected' in ev))
                    lower=None
    summary=compact(v.get('details') or v.get('summary') or v['id'])
    return dict(id=ident,title=compact(v.get('summary') or summary,165),published=v['published'],summary=summary,
                affected=compact(', '.join(dict.fromkeys(a.get('package',{}).get('name','') for a in items))),
                remediation=compact('; '.join(dict.fromkeys(fixes))),url=url,status=status,ranges=ranges,
                evidence='Package advisory · compare installed version' if status=='Reviewed package advisory' else 'Distribution notice · verify installed packages',
                sources=refs[:12]+[{'url':url,'label':v['id']}])


def packages(tmp,start,out):
    names={}
    for key,p in CONFIG.items():
        if p['match'].startswith('osv:'):
            _,eco,name=p['match'].split(':');names[eco,name.lower()]=key
    path=archive(tmp,'ghsa','https://codeload.github.com/github/advisory-database/zip/refs/heads/main')
    with ZipFile(path) as z:
        for f in z.infolist():
            if '/github-reviewed/' not in f.filename or not f.filename.endswith('.json'):continue
            v=json.loads(z.read(f))
            if v.get('withdrawn') or v['published']<start:continue
            match=defaultdict(list)
            for a in v.get('affected',[]):
                p=a.get('package',{});key=names.get((p.get('ecosystem'),p.get('name','').lower()))
                if key:match[key].append(a)
            for key,items in match.items():put(out,key,osv_row(v,items,'Reviewed package advisory'))


def release_line(eco,entry):
    name=entry.get('package',{}).get('ecosystem','')
    if not name.startswith(eco+':'):return None
    name=name[len(eco)+1:]
    if eco=='Red Hat':
        m=re.fullmatch(r'enterprise_linux:(\d+(?:\.\d+)?)(?:::[a-z0-9_-]+)?',name)
    elif eco=='SUSE':
        m=re.fullmatch(r'Linux Enterprise Server (\d+(?:\.\d+)?)(?: SP(\d+))?',name)
        if m and m[2]:return m[1]+'.'+m[2]
    elif eco=='openSUSE':m=re.fullmatch(r'Leap (\d+\.\d+)',name)
    else:m=re.fullmatch(r'v?(\d+(?:\.\d+)?)',name)
    return m[1] if m else None


def distro_history(tmp,start,out):
    for eco,key in DISTROS.items():
        path=archive(tmp,eco,'https://storage.googleapis.com/osv-vulnerabilities/'+quote(eco)+'/all.zip')
        for v in records(path):
            if v.get('withdrawn') or v.get('published','')<start:continue
            if eco=='Red Hat' and not v['id'].startswith('RHSA-'):continue
            if eco=='AlmaLinux' and not v['id'].startswith('ALSA-'):continue
            groups=defaultdict(list)
            for a in v.get('affected',[]):
                if eco=='Android':
                    lines={m[1] for ver in a.get('versions',[]) if (m:=re.match(r'^(\d+)(?:[.-]|$)',ver))}
                else:lines={release_line(eco,a)}
                for line in lines:
                    if line:groups[line].append(a)
            for line,items in groups.items():
                put(out,key+'@'+line,osv_row(v,items,'Distribution security advisory · '+eco))


def distro_row(ident,title,date,url,summary,packages=()):
    return dict(id=ident,title=compact(title,165),published=date,summary=compact(summary),affected=compact(', '.join(packages)),
                url=url,sources=[{'url':url,'label':'Vendor security notice'}],status='Vendor security notice',
                evidence='Distribution notice · verify installed packages')


def other_distributions(start,out):
    for line in ['2','2023']:
        for a in load_json('https://alas.aws.amazon.com/alas'+line+'.json')['advisories']:
            date=a['date_released'].replace(' ','T')+':00Z'
            if date<start:continue
            ident=a['advisory_id'];pkgs=a['affected_packages']
            put(out,'amazon-linux@'+line,distro_row(ident,ident+' · '+', '.join(pkgs),date,
                urljoin('https://alas.aws.amazon.com',a['links']['self']),', '.join(a['cve']),pkgs))
    for year in range(int(start[:4]),datetime.now(timezone.utc).year+1):
        url='https://linux.oracle.com/security/oval/com.oracle.elsa-'+str(year)+'.xml.bz2'
        with fetch(url) as src,bz2.BZ2File(src) as archive:
            for _,definition in ET.iterparse(archive,events=['end']):
                if not definition.tag.endswith('}definition'):continue
                meta=definition.find('{*}metadata')
                if meta is None:continue
                issued=meta.find('.//{*}issued')
                if issued is not None and issued.get('date','')>=start:
                    ref=next((r for r in meta.findall('{*}reference') if r.get('ref_id','').startswith('ELSA-')),None)
                    if ref is not None:
                        for name in meta.findall('.//{*}platform'):
                            m=re.fullmatch(r'Oracle Linux (\d+)',name.text or '')
                            if m:put(out,'oracle-linux@'+m[1],distro_row(ref.get('ref_id'),meta.findtext('{*}title'),issued.get('date')+'T00:00:00Z',
                                ref.get('ref_url') or 'https://linux.oracle.com/errata/',meta.findtext('{*}description')))
                definition.clear()
    def fedora_page(page):
        params=urlencode(dict(type='security',status='stable',pushed_since=start,rows_per_page=100,page=page))
        return load_json('https://bodhi.fedoraproject.org/updates/?'+params)
    def accept(data):
        for a in data['updates']:
            date=(a.get('date_stable') or '').replace(' ','T')+'Z'
            if not a['release']['name'].startswith('F') or not date[:1].isdigit() or date<start:continue
            put(out,'fedora@'+a['release']['version'],distro_row(a['alias'],a['title'],date,a['url'],a['notes']))
    first=fedora_page(1)
    accept(first)
    with ThreadPoolExecutor(max_workers=4) as pool:
        for data in pool.map(fedora_page,range(2,first['pages']+1)):accept(data)


def dotnet(start,out):
    base='https://builds.dotnet.microsoft.com/dotnet/release-metadata/'
    for channel in load_json(base+'releases-index.json')['releases-index']:
        if channel.get('eol-date') and channel['eol-date']<start:continue
        for r in load_json(channel['releases.json'])['releases']:
            if r['release-date']<start:continue
            for c in r.get('cve-list',[]):
                for key,field in [('sdk','sdk'),('aspnet','aspnetcore-runtime'),('runtime','runtime')]:
                    field_data=r.get(field) or {}
                    if 'version' not in field_data:continue
                    ident=c['cve-id'];line=channel['channel-version'];build=field_data['version']
                    if not re.fullmatch(r'\d+(?:\.\d+){2}',build):continue
                    out[key+'@'+line].setdefault(ident,dict(id=ident,title=ident+' · .NET '+r['release-version']+' security release',
                        published=r['release-date']+'T00:00:00Z',summary='Microsoft lists this CVE in the .NET security release. Check the bulletin for affected components.',
                        remediation='Component shipped in release: '+build,url=c['cve-url'],status='Microsoft .NET release bulletin',
                        evidence='Shared .NET release bulletin · verify component',sources=[{'url':c['cve-url'],'label':'Microsoft advisory'}]))


def other_ubuntu(start,out):
    series={s['name']:s['version'] for s in load_json('https://api.launchpad.net/1.0/ubuntu/series')['entries']}
    with fetch('https://usn.ubuntu.com/usn-db/database.json.bz2') as src,bz2.BZ2File(src) as f:
        for ident,n in ijson.kvitems(f,''):
            date=datetime.fromtimestamp(float(n['timestamp']),timezone.utc).isoformat()
            if date<start:continue
            for code,release in n['releases'].items():
                if code=='noble' or code not in series:continue
                packages=[k+' '+(v.get('version') or '') for k,v in release.get('sources',{}).items()]
                row=distro_row('USN-'+ident,n['title'],date,'https://ubuntu.com/security/notices/USN-'+ident,
                               n['description'],packages)
                put(out,'ubuntu@'+series[code],row)


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--cache',type=Path)
    ap.add_argument('--output',type=Path)
    args=ap.parse_args()
    now=datetime.now(timezone.utc);stamp=now.isoformat();start=(now-timedelta(days=400)).date().isoformat()
    if not args.output:
        from feed_snapshot import S3Store
        store=S3Store();old,etag=store.get(PREFIX+'current.json')
        if old and now-datetime.fromisoformat(json.loads(old)['checked'])<timedelta(hours=22):return
    with tempfile.TemporaryDirectory() as tmp:
        cache=args.cache or Path(tmp);out=defaultdict(dict)
        for name, collect, args_ in [('CVE Program',cve_history,(cache,start,out)),('Reviewed packages',packages,(cache,start,out)),
                                      ('.NET releases',dotnet,(start,out)),('Distribution exports',distro_history,(cache,start,out)),
                                      ('Vendor errata',other_distributions,(start,out)),('Ubuntu',other_ubuntu,(start,out)),
                                      ('SQL bulletins',sql_bulletins,(start,out)),('SFOS bulletins',sophos_bulletins,(start,out))]:
            print('Reading',name,flush=True)
            collect(*args_)
            print(name,'complete;',sum(map(len,out.values())),'records',flush=True)
        if len(out['linux'])<100 or len(out['server'])<100 or not out['next'] or len(out)<65:
            raise ValueError('Incomplete vendor history inputs')
        directory={}
        def write(key,data):
            if args.output:
                args.output.mkdir(exist_ok=True,parents=True);(args.output/key).write_bytes(data)
            else:store.immutable(PREFIX+key,data)
        for key,rows in out.items():
            entries=sorted(rows.values(),key=lambda r:(r['published'],r['id']),reverse=True)
            pages=[]
            for i in range(0,len(entries),160):
                page=entries[i:i+160];body=json.dumps(page,ensure_ascii=False,separators=(',',':')).encode()
                h=hashlib.sha256(body).hexdigest()
                write(h+'.json',body);pages.append([page[-1]['published'][:10],page[0]['published'][:10],h])
            directory[key]=pages
        data={'from':start,'checked':stamp,'products':directory,'audited':sorted(CONFIG)}
        digest=hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest()
        data['snapshot']=digest;body=json.dumps(data,separators=(',',':')).encode()
        write(digest+'.json',body)
        if args.output:(args.output/'current.json').write_bytes(body)
        else:store.compare_set(PREFIX+'current.json',body,etag)
        print('Published advisory history for',len(CONFIG),'products;',sum(map(len,out.values())),'product and release matches.')


if __name__=='__main__':
    main()
