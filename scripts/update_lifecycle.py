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
 "php":"PHP", "python":"Python", "dotnet":" .NET", "nodejs":"Node.js",
 "windows-server":"Windows Server", "ubuntu":"Ubuntu", "debian":"Debian",
 "mysql":"MySQL", "postgresql":"PostgreSQL", "wordpress":"WordPress",
 "fortios":"FortiOS", "kubernetes":"Kubernetes"
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
            for row in rows[:3]:
                if not isinstance(row,dict):continue
                eol=row.get("eol")
                if not isinstance(eol,(str,bool)):eol=None
                support=row.get("support")
                result["cycles"].append({"product":title.strip(),"cycle":str(row.get("cycle") or "Unknown")[:60],
                 "eol":eol if isinstance(eol,bool) else None,
                 "eol_date":eol if isinstance(eol,str) else None,
                 "support_date":support if isinstance(support,str) else None,
                 "url":"https://endoflife.date/"+slug})
        except Exception as exc:
            result["errors"].append({"product":slug,"reason":str(exc)[:120]})
    OUTPUT.write_text("window.CVEHARBOR_LIFECYCLE = "+json.dumps(result).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Lifecycle:",len(result["cycles"]),"cycles,",len(result["errors"]),"unavailable sources")
if __name__=="__main__":build()
