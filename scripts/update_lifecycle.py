#!/usr/bin/env python3
"""Public lifecycle cache generated from endoflife.date per-product JSON feeds.

Source EOL status is advisory, not a guarantee of extended support agreements.
Collection errors never result in fabricated lifecycle dates.
"""
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from collect_sql_updates import MicrosoftSqlParser
ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/"lifecycle.js"
PRODUCTS={
 "windows-server":"Windows Server",
 "windows":"Windows Client",
 "mssqlserver":"Microsoft SQL Server",
 "sharepoint":"SharePoint Server",
 "dotnet":".NET",
 "dotnet-framework":".NET Framework",
 "exchange-server":"Exchange Server",
 "system-center":"System Center",
 "powershell":"PowerShell",
 "azure-devops-server":"Azure DevOps Server",
 "sitefinity":"Sitefinity CMS",
 "wordpress":"WordPress",
 "php":"PHP",
 "ubuntu":"Ubuntu",
 "debian":"Debian",
 "rhel":"Red Hat Enterprise Linux",
 "centos":"CentOS",
 "almalinux":"AlmaLinux",
 "rocky-linux":"Rocky Linux",
 "mysql":"MySQL",
 "mariadb":"MariaDB",
 "python":"Python",
 "nodejs":"Node.js",
 "docker-engine":"Docker Engine",
 "kubernetes":"Kubernetes",
 "fortios":"FortiOS",
}

ALIASES={"dotnet-framework":"dotnetfx","exchange-server":"msexchange"}
SITEFINITY="https://www.progress.com/support/sitefinity-lifecycle-policy"
def vendor_table(url):
    req=urllib.request.Request(url,headers={"User-Agent":"CVEHarbor/1.0","Accept":"*/*"})
    with urllib.request.urlopen(req,timeout=18) as response:
        parser=MicrosoftSqlParser()
        parser.feed(response.read(2_000_000).decode())
        return [cells for _,cells in parser.rows]

def vendor_rows(slug):
    rows=[]
    if slug=="sitefinity":
        for cells in vendor_table(SITEFINITY):
            if len(cells)!=5:continue
            version=re.match(r"Sitefinity\s+(\d+\.\d+)",cells[0],re.I)
            if not version:continue
            # The publisher defines retirement as the first of the named month.
            # An earliest possible retirement is not a confirmed retirement date.
            end=None
            if re.fullmatch(r"[A-Za-z]+ \d{4}",cells[-1]):
                end=datetime.strptime(cells[-1],"%B %Y").date().isoformat()
            rows.append({"cycle":version[1],"eol":end,"url":SITEFINITY,"retirement_note":cells[-1]})
    else:
        for year in (2025,2022,2019):
            name=f"System Center {year} Operations Manager"
            url="https://learn.microsoft.com/en-us/lifecycle/products/"+name.lower().replace(" ","-")
            cells=next(c for c in vendor_table(url) if len(c)==4 and c[0]==name)
            def local_date(value):
                utc=datetime.strptime(value,"%m/%d/%Y %I:%M:%S %p").replace(tzinfo=timezone.utc)
                return utc.astimezone(ZoneInfo("America/Los_Angeles")).date().isoformat()
            rows.append({"cycle":f"{year} Operations Manager","releaseDate":local_date(cells[1]),
                         "support":local_date(cells[2]),"eol":local_date(cells[3]),"url":url})
    if not rows:raise ValueError("Publisher lifecycle table unavailable")
    return rows

def build():
    result={"checked_at":datetime.now(timezone.utc).isoformat(),"cycles":[],"errors":[],"available_products":[]}
    try:
        req=urllib.request.Request("https://endoflife.date/api/all.json",
            headers={"User-Agent":"CVEHarbor-Lifecycle/1.0","Accept":"application/json"})
        with urllib.request.urlopen(req,timeout=20) as resp:
            entries=json.loads(resp.read(100_000))
        if not isinstance(entries,list):raise ValueError("Unexpected product directory")
        result["available_products"]=[x for x in entries if isinstance(x,str)
            and 1<=len(x)<=70 and all(c.islower() or c.isdigit() or c=="-" for c in x)][:1000]
    except Exception as exc:
        result["errors"].append({"product":"product-directory","reason":str(exc)[:120]})
    for slug,title in PRODUCTS.items():
        source_slug=ALIASES.get(slug,slug)
        url="https://endoflife.date/api/"+source_slug+".json"
        try:
            if slug in ("sitefinity","system-center"):
                rows=vendor_rows(slug)
            else:
                request=urllib.request.Request(url,headers={"User-Agent":"CVEHarbor-Lifecycle/1.0","Accept":"application/json"})
                with urllib.request.urlopen(request,timeout=12) as resp:
                    rows=json.loads(resp.read(300_000))
            if not isinstance(rows,list) or not rows:raise ValueError("Unexpected product data format")
            for row in rows[:16]:
                if not isinstance(row,dict):continue
                eol=row.get("eol")
                if not isinstance(eol,(str,bool)):eol=None
                support=row.get("support")
                result["cycles"].append({"product":title.strip(),"cycle":str(row.get("cycle") or "Unknown")[:60],
                 "eol":eol if isinstance(eol,bool) else None,
                 "slug":slug,
                 "eol_date":eol if isinstance(eol,str) else None,
                 "support_date":support if isinstance(support,str) else None,
                 "latest":str(row.get("latest") or "")[:80],
                 "latest_release_date":str(row.get("latestReleaseDate") or "")[:40],
                 "release_date":str(row.get("releaseDate") or "")[:40],
                 "url":row.get("url") if slug in ("sitefinity","system-center") else "https://endoflife.date/"+source_slug,
                 **({"retirement_note":row["retirement_note"]} if row.get("retirement_note") else {})})
        except Exception as exc:
            result["errors"].append({"product":slug,"reason":str(exc)[:120]})
    result["products"]=[{"slug":slug,"product":title} for slug,title in PRODUCTS.items()]
    OUTPUT.write_text("window.CVEHARBOR_LIFECYCLE = "+json.dumps(result).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Lifecycle:",len(result["cycles"]),"cycles,",len(result["errors"]),"unavailable sources")
if __name__=="__main__":build()
