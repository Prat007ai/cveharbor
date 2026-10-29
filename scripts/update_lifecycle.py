#!/usr/bin/env python3
"""Public lifecycle cache generated from endoflife.date per-product JSON feeds.

Source EOL status is advisory, not a guarantee of extended support agreements.
Collection errors never result in fabricated lifecycle dates.
"""
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
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

def build():
    result={"checked_at":datetime.now(timezone.utc).isoformat(),"cycles":[],"errors":[]}
    for slug,title in PRODUCTS.items():
        url="https://endoflife.date/api/"+slug+".json"
        try:
            request=urllib.request.Request(url,headers={"User-Agent":"CVEHarbor-Lifecycle/1.0","Accept":"application/json"})
            with urllib.request.urlopen(request,timeout=12) as resp:
                rows=json.loads(resp.read(300_000))
            if not isinstance(rows,list):raise ValueError("Unexpected product data format")
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
                 "url":"https://endoflife.date/"+slug})
        except Exception as exc:
            result["errors"].append({"product":slug,"reason":str(exc)[:120]})
    result["products"]=[{"slug":slug,"product":title} for slug,title in PRODUCTS.items()]
    OUTPUT.write_text("window.CVEHARBOR_LIFECYCLE = "+json.dumps(result).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Lifecycle:",len(result["cycles"]),"cycles,",len(result["errors"]),"unavailable sources")
if __name__=="__main__":build()
