"""Vendor bulletins that extend the CVE product matrix to specific distributions."""
from concurrent.futures import ThreadPoolExecutor
import re

from urllib.error import HTTPError
from urllib.request import Request, urlopen
from vendor_scan_data import MSRC, document


SQL_KEYS = {'2025':'sql2025','2022':'sql','2017':'sql2017','2016':'sql2016','2014':'sql2014'}


def sql_bulletins(start,out):
    docs = document(MSRC+'updates')['value']
    months = {u['ID'] for u in docs if re.fullmatch(r'\d{4}-[A-Z][a-z]{2}',u['ID']) and u['InitialReleaseDate'][:7]>=start[:7]}
    def month(name):
        data=document(MSRC+'cvrf/'+name)
        products={}
        for p in data['ProductTree']['FullProductName']:
            m=re.fullmatch(r'Microsoft SQL Server (2025|2022|2017|2016|2014)(?: for x64-based Systems)?(?: Service Pack \d+)?(?: \((GDR|CU\s*\d+)\))?',p['Value'],re.I)
            if m:products[p['ProductID']]=(SQL_KEYS[m[1]],m[2] or 'Microsoft update')
        articles={}
        listed={}
        for v in data['Vulnerability']:
            for f in v.get('Remediations',[]):
                kb=(f.get('Description') or {}).get('Value','')
                if f.get('Type')!=2 or not re.fullmatch(r'\d{7}',kb) or not f.get('FixedBuild'):continue
                for pid in products.keys() & set(f.get('ProductID',[])):
                    key,branch=products[pid];articles[kb]=(key,branch,f['FixedBuild'])
                    listed.setdefault(kb,set()).add(v['CVE'])
        by_id={v['CVE']:v for v in data['Vulnerability']}
        findings=[]
        for kb,(key,branch,build) in articles.items():
            linked=listed[kb].copy()
            try:
                request=Request('https://support.microsoft.com/en-us/help/'+kb,headers={'Accept':'text/html','User-Agent':'CVEHarbor'})
                with urlopen(request,timeout=60) as response:
                    article=response.read().decode()
            except HTTPError as exc:
                if exc.code not in (403,404,410):raise
                print('SQL KB',kb,'article unavailable; using MSRC product-specific remediation',flush=True)
                article=''
            title=re.search(r'<title[^>]*>(.*?)</title>',article,re.I|re.S)
            if title and any(('sql server '+year) in title[1].lower() for year,ident in SQL_KEYS.items() if ident==key):
                linked.update(re.findall(r'https://msrc\.microsoft\.com/update-guide/(?:[a-z-]+/)?vulnerability/(CVE-\d{4}-\d+)',article,re.I))
            for ident in sorted(linked):
                v=by_id.get(ident)
                if not v:continue
                date=min(x['Date'] for x in v['RevisionHistory'])[:19]+'Z'
                if date>=start:findings.append((key,ident,v['Title']['Value'],date,kb,branch,build))
        return findings
    with ThreadPoolExecutor(max_workers=3) as pool:
        for findings in pool.map(month,sorted(months)):
            for key,ident,title,date,kb,branch,build in findings:
                url='https://msrc.microsoft.com/update-guide/vulnerability/'+ident
                row=out[key].setdefault(ident,dict(id=ident,title=title,published=date,summary=title,url=url,
                    status='Microsoft SQL Server security bulletin',evidence='Product advisory · verify servicing branch',
                    sources=[{'url':url,'label':'Microsoft Security Update Guide'}]))
                row.setdefault('vendorFixes',{})[build]=branch+' · KB'+kb
                link='https://support.microsoft.com/help/'+kb
                if not any(s['url']==link for s in row['sources']):row['sources'].append({'url':link,'label':'SQL Server KB'+kb})
                row['remediation']='; '.join(b+' · '+label for b,label in sorted(row['vendorFixes'].items()))


def sophos_bulletins(start,out):
    # Upstream kernel and CA notices do not name SFOS in their affected-product records.
    # Dates are the original Sophos bulletins, rather than subsequent hotfix revisions.
    notices=[
        ('CVE-2026-98432','2026-11-02','Linux kernel TCP vulnerability in Sophos Firewall','sophos-sa-20261102-linux-kernel-tcp',
         'Check the SFOS hotfix installation status. Sophos lists HF110626.1 for 23.0 GA, 23.0 EAP1 and 22.0 MR3 and requires a restart.'),
        ('sophos-sa-20261027-emudhra','2026-10-27','Compromised eMudhra intermediate CA certificates','sophos-sa-20261027-emudhra',
         'Review the certificate and firewall hotfix guidance for the installed SFOS release.')]
    for ident,date,title,slug,notes in notices:
        if date<start:continue
        url='https://www.sophos.com/en-us/security-advisories/'+slug
        out['sophos'][ident]=dict(id=ident,title=title,published=date+'T00:00:00Z',summary=notes,
            remediation=notes,url=url,status='Sophos Security Advisory',evidence='Firewall notice · verify hotfix status',
            sources=[{'url':url,'label':'Sophos Security Advisory'}])
