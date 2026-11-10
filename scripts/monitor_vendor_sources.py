"""Read public upstream records for empty production scans. No production-data credentials."""
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlencode
from urllib.error import HTTPError
import re
import json
import os

from catalogue_promotion import request

import catalogue_advisory_data as vendor
from catalogue_components import renderer_history, npm_history
from vendor_scan_data import microsoft, ubuntu, MSRC, document

OWNERS = {
    'office':'microsoftgraph/msgraph-sdk-javascript', 'crm':'microsoft/PowerPlatform-DataverseServiceClient',
    'bi':'microsoft/PowerBI-JavaScript', 'ai':'Azure/azure-sdk-for-python', 'azure':'Azure/azure-cli',
    'aws':'aws/aws-cli', 'requests':'psf/requests', 'angular':'angular/angular', 'next':'vercel/next.js',
    'react':'react/react', 'ts':'microsoft/TypeScript', 'jquery':'jquery/jquery', 'bootstrap':'twbs/bootstrap',
    'telerik':'telerik/kendo-react', 'lodash':'lodash/lodash', 'npm':'npm/cli'
}
MS_PRODUCTS = {'win11':r'Windows 11 Version .+', 'server':r'Windows Server (?:2008|2012|2016|2019|2022|2025).*',
               'exchange':r'(?:Microsoft )?Exchange Server Subscription Edition.*',
               'sharepoint':r'(?:Microsoft )?SharePoint Server Subscription Edition.*'}
DISTROS = {'ubuntu','debian','rhel','almalinux','rocky-linux','oracle-linux','sles','opensuse',
           'amazon-linux','fedora','centos-stream','alpine-linux','android'}
DOTNET = {'aspnet','runtime','sdk'}


def github_json(url):
    if not url.startswith('https://api.github.com/'):
        raise ValueError('Unexpected GitHub API host')
    headers = {'Accept':'application/vnd.github+json'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization']='Bearer '+os.environ['GITHUB_TOKEN']
    for _ in range(3):
        try:
            with request(url,headers) as response:
                return json.load(response)
        except HTTPError as exc:
            target = exc.headers.get('Location','')
            if exc.code not in (301,302,307,308) or not target.startswith('https://api.github.com/'):
                raise
            url=target
    raise ValueError('Too many advisory redirects')


def package_notices(key, package, start):
    _,ecosystem,name=package.split(':')
    eco={'npm':'npm','NuGet':'nuget','PyPI':'pip'}[ecosystem]
    params={'affects':name,'ecosystem':eco,'type':'reviewed','published':'>='+start}
    sources=[('https://api.github.com/advisories',params)]
    if key in OWNERS:
        sources.append(('https://api.github.com/repos/'+OWNERS[key]+'/security-advisories',{}))
    matches={}
    for url,query in sources:
        page=1
        while True:
            records=github_json(url+'?'+urlencode({**query,'per_page':100,'page':page}))
            if not isinstance(records,list):
                raise ValueError('Incomplete GitHub advisory response')
            for row in records:
                if row.get('withdrawn_at') or row['published_at'][:10]<start:
                    continue
                if not any(((v.get('package') or {}).get('name') or '').lower()==name.lower()
                           and (v['package'].get('ecosystem') or '').lower()==eco for v in row['vulnerabilities']):
                    continue
                ident=row.get('cve_id') or row['ghsa_id']
                matches[ident]=dict(id=ident,published=row['published_at'],url=row['html_url'])
            if len(records)<100:
                break
            page+=1
    return matches


def msrc_matrix(start,out):
    months={u['ID'] for u in document(MSRC+'updates')['value']
            if re.fullmatch(r'\d{4}-[A-Z][a-z]{2}',u['ID']) and u['InitialReleaseDate'][:7]>=start[:7]}
    if len(months)<12:raise ValueError('Incomplete Microsoft directory')
    for month in sorted(months):
        data=document(MSRC+'cvrf/'+month)
        names={p['ProductID']:p['Value'] for p in data['ProductTree']['FullProductName']}
        for advisory in data['Vulnerability']:
            when=min(r['Date'] for r in advisory['RevisionHistory'])
            if when[:10]<start:continue
            ids={i for r in advisory.get('Remediations',[]) if r['Type']==2 for i in r.get('ProductID',[])}
            for key,pattern in MS_PRODUCTS.items():
                if any(re.fullmatch(pattern,names.get(i,''),re.I) for i in ids):
                    ident=advisory['CVE']
                    out[key][ident]=dict(id=ident,published=when,url='https://msrc.microsoft.com/update-guide/vulnerability/'+ident)


def scopes(key,version):
    major=version.split('.')[0]
    series='.'.join(version.split('.')[:2])
    if key=='rhel':return {key+'@'+major,key+'@'+series}
    if key in DISTROS:
        use_major=key in {'debian','almalinux','rocky-linux','oracle-linux','amazon-linux','fedora','android'}
        return {key+'@'+(major if use_major else series)}
    if key in DOTNET:return {key,key+'@'+series}
    return {key}


def evidence(scans,start):
    needed={(s['key'],s['version'],category) for s in scans for category in s.get('empty',[])}
    direct={key for key,v,cat in needed if cat=='direct'}
    expected=defaultdict(list)
    errors=defaultdict(list)
    history=defaultdict(dict)
    def collect(name, refs, read):
        if not refs:return
        try:
            read()
        except Exception as exc:
            print(f'Incomplete evidence for {name}: {type(exc).__name__}',flush=True)
            for ref in refs:errors[ref].append(name)
    def refs(keys):
        return {ref for ref in needed if ref[0] in keys and ref[2]=='direct'}
    packages={k for k in direct if vendor.CONFIG[k]['match'].startswith('osv:')}
    for key in sorted(packages):
        collect('package advisories for '+key,refs({key}),
                lambda:history[key].update(package_notices(key,vendor.CONFIG[key]['match'],start)))
    unsupported=direct-set(vendor.RULES)-packages-DISTROS-DOTNET-{'sql2019','hyperv'}
    for ref in refs(unsupported):errors[ref].append('no reviewed vendor mapping')
    with TemporaryDirectory() as tmp:
        cna_keys=direct-DISTROS-{'sql2019'}
        collect('CVE Program publisher records',refs(cna_keys),
                lambda:vendor.cve_history(Path(tmp),start,history))
        collect('Microsoft product matrix',refs(MS_PRODUCTS),lambda:msrc_matrix(start,history))
        collect('Microsoft SQL servicing notices',refs({'sql','sql2025','sql2017','sql2016','sql2014'}),
                lambda:vendor.sql_bulletins(start,history))
        if 'sql2019' in direct:
            def sql2019():
                for row in microsoft(start,datetime.now(timezone.utc).isoformat()):
                    history['sql2019'][row['id']]={**row,'url':'https://msrc.microsoft.com/update-guide/vulnerability/'+row['id']}
            collect('Microsoft SQL Server 2019',refs({'sql2019'}),sql2019)
        collect('Microsoft .NET releases',refs(DOTNET),lambda:vendor.dotnet(start,history))
        collect('distribution advisories',refs(set(vendor.DISTROS.values())),lambda:vendor.distro_history(Path(tmp),start,history))
        collect('vendor errata',refs({'fedora','amazon-linux','oracle-linux'}),lambda:vendor.other_distributions(start,history))
        collect('CentOS changelogs',refs({'centos-stream'}),lambda:vendor.centos_changes(start,history))
        collect('MariaDB notices',refs({'maria'}),lambda:vendor.mariadb_bulletins(start,history))
        collect('Sophos notices',refs({'sophos'}),lambda:vendor.sophos_bulletins(start,history))
        noble={r for r in refs({'ubuntu'}) if r[1].startswith('24.04')}
        def canonical_noble():
            for row in ubuntu(start):
                history['ubuntu@24.04'][row['id']]={**row,'url':'https://ubuntu.com/security/notices/'+row['id']}
        collect('Canonical Noble notices',noble,canonical_noble)
        collect('other Canonical series',refs({'ubuntu'})-noble,lambda:vendor.other_ubuntu(start,history))
    optional={r for r in needed if r[2]=='optional'}
    def veeam_notices():
        for ident,kb,when,lines in [('CVE-2026-98432','4966','2026-11-06',('12.3.','13.1.')),
                                   ('KB4879','4879','2026-07-14',('13.',))]:
            url='https://www.veeam.com/kb'+kb
            with vendor.fetch(url) as response:
                html=response.read().decode()
            if when not in html or ('12.3.0.65' if kb=='4879' else ident) not in html:
                raise ValueError('Veeam impact statement could not be verified')
            for ref in veeam_refs:
                if ref[1].startswith(lines):
                    expected[ref].append(dict(id=ident,published=when,url=url))
    veeam_refs={r for r in optional if r[0]=='veeam'}
    collect('Veeam impact statements',veeam_refs,veeam_notices)
    collect('renderer maintainer notices',optional-veeam_refs,lambda:renderer_history(start,history,vendor.load_json))
    bundled={r for r in needed if r[2]=='bundled'}
    collect('npm archive and OSV',bundled,
            lambda:npm_history(start,history,sorted({v for k,v,c in bundled}),vendor.load_json,vendor.fetch))
    for key,version,category in needed:
        if category=='bundled':keys={'npm@'+version+'~components'}
        elif category=='optional':keys={key+'~components'}
        else:keys=scopes(key,version)
        for scope in keys:
            expected[key,version,category].extend(history.get(scope,{}).values())
    return expected,errors
