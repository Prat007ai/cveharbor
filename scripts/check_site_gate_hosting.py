#!/usr/bin/env python3
"""Read-only hosting diagnostics for the requested temporary site gate."""
import json
import os
import shutil
import socket
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def cloudflare(path):
    token=os.environ.get("CLOUDFLARE_API_TOKEN","")
    if not token:return {"ok":False,"error":"Cloudflare deployment token unavailable"}
    request=urllib.request.Request("https://api.cloudflare.com/client/v4"+path,headers={"Authorization":"Bearer "+token,"Accept":"application/json"})
    try:
        with urllib.request.urlopen(request,timeout=25) as response:body=json.loads(response.read(500000))
        if body.get("success") is not True:return {"ok":False,"errors":[e.get("code") for e in body.get("errors",[])]}
        return {"ok":True,"result":body.get("result")}
    except urllib.error.HTTPError as exc:return {"ok":False,"http_status":exc.code}
    except Exception as exc:return {"ok":False,"error":type(exc).__name__}


def main():
    report={"checked_at":datetime.now(timezone.utc).isoformat(),"source_revision":os.environ.get("GITHUB_SHA"),"dns":{}}
    report["credential_source"]=os.environ.get("SITE_GATE_TOKEN_SOURCE","existing_deployment")
    password=os.environ.get("SITE_GATE_PASSWORD","")
    report["site_gate_password_configured"]=len(password)>=16 and "\n" not in password and "\r" not in password
    identity=cloudflare("/user/tokens/verify")
    report["credential_identity"]={k:v for k,v in identity.items() if k!="result"}
    if identity.get("ok"):
        token_id=identity.get("result",{}).get("id")
        report["credential_identity"].update({k:identity.get("result",{}).get(k) for k in ("id","status")})
        if token_id:
            metadata=cloudflare("/user/tokens/"+token_id)
            if metadata.get("ok"):report["credential_identity"]["name"]=metadata.get("result",{}).get("name")
    for name in ("cveharbor.com","www.cveharbor.com","api.cveharbor.com"):
        try:report["dns"][name]=sorted({row[4][0] for row in socket.getaddrinfo(name,443,type=socket.SOCK_STREAM)})
        except OSError as exc:report["dns"][name]={"error":type(exc).__name__}
    if shutil.which("dig"):
        result=subprocess.run(["dig","+short","NS","cveharbor.com"],capture_output=True,text=True,timeout=15)
        report["nameservers"]=result.stdout.splitlines()
    zones=cloudflare("/zones?"+urllib.parse.urlencode({"name":"cveharbor.com"}))
    report["zone_access"]={k:v for k,v in zones.items() if k!="result"}
    report["zones"]=[]
    if zones.get("ok"):
        for zone in zones.get("result") or []:
            if zone.get("name")!="cveharbor.com":continue
            item={k:zone.get(k) for k in ("id","name","status")}
            item["account_matches"]=zone.get("account",{}).get("id")==os.environ.get("CLOUDFLARE_ACCOUNT_ID")
            records=cloudflare("/zones/"+zone["id"]+"/dns_records?"+urllib.parse.urlencode({"per_page":100}))
            item["dns_access"]={k:v for k,v in records.items() if k!="result"}
            if records.get("ok"):
                item["frontend_records"]=[{k:r.get(k) for k in ("id","type","name","content","proxied")} for r in records.get("result") or [] if r.get("name") in ("cveharbor.com","www.cveharbor.com") and r.get("type") in ("A","AAAA","CNAME")]
            routes=cloudflare("/zones/"+zone["id"]+"/workers/routes")
            item["route_access"]={k:v for k,v in routes.items() if k!="result"}
            if routes.get("ok"):item["frontend_routes"]=[r for r in routes.get("result") or [] if r.get("pattern","").startswith(("cveharbor.com/","www.cveharbor.com/"))]
            report["zones"].append(item)
    output=Path("data/site-gate-hosting.json");output.parent.mkdir(parents=True,exist_ok=True)
    output.write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps(report))


if __name__=="__main__":main()
