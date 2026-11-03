#!/usr/bin/env python3
"""Deploy the frontend behind its temporary Cloudflare password gate.

Passwords are read from CI secrets and sent to Wrangler over stdin. No password
is written to source, configuration, deployment artifacts or command arguments.
"""
import base64
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
CONFIG=ROOT/"site-gate"/"wrangler.json"
DOMAIN="cveharbor.com"
GITHUB_IPS={f"185.199.{part}.153" for part in (108,109,110,111)}|{f"2606:50c0:800{part}::153" for part in range(4)}


def cloudflare(path,method="GET",data=None,allow_not_found=False):
    token=os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:raise RuntimeError("CLOUDFLARE_API_TOKEN is not configured")
    request=urllib.request.Request("https://api.cloudflare.com/client/v4"+path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"},method=method)
    try:
        with urllib.request.urlopen(request,timeout=30) as response:result=json.loads(response.read(1000000))
    except urllib.error.HTTPError as exc:
        if allow_not_found and exc.code==404:return None
        raise RuntimeError(f"Cloudflare {method} {path.split('?')[0]} returned HTTP {exc.code}; check the token's zone DNS/Worker-route permissions") from None
    if result.get("success") is not True:
        raise RuntimeError("Cloudflare rejected the request; error codes: "+str([e.get("code") for e in result.get("errors",[])]))
    return result.get("result")


def checked_configuration():
    config=json.loads(CONFIG.read_text())
    if config.get("assets",{}).get("run_worker_first") is not True:
        raise RuntimeError("Static assets must run through the gate Worker first")
    gated=config.get("vars",{}).get("SITE_GATE_ENABLED")!="false"
    password=os.environ.get("SITE_GATE_PASSWORD","")
    if gated and (len(password)<16 or "\n" in password or "\r" in password):
        raise RuntimeError("Set the SITE_GATE_PASSWORD GitHub secret to a single-line password of at least 16 characters before activating the site gate")
    if not os.environ.get("CLOUDFLARE_ACCOUNT_ID"):raise RuntimeError("CLOUDFLARE_ACCOUNT_ID is not configured")
    return config,gated,password


def routing_plan(config):
    zones=cloudflare("/zones?"+urllib.parse.urlencode({"name":DOMAIN}))
    zones=[zone for zone in zones if zone.get("name")==DOMAIN and zone.get("status")=="active"]
    if len(zones)!=1:raise RuntimeError("The cveharbor.com Cloudflare zone must be active")
    zone=zones[0]
    if zone.get("account",{}).get("id")!=os.environ["CLOUDFLARE_ACCOUNT_ID"]:
        raise RuntimeError("The frontend zone and Worker deployment must belong to the same Cloudflare account")
    routes=cloudflare(f"/zones/{zone['id']}/workers/routes")
    patterns={route["pattern"] for route in config["routes"]}
    if any(route.get("pattern") in patterns and route.get("script") not in (None,config["name"]) for route in routes):
        raise RuntimeError("A different Worker already owns a frontend route; review it before replacement")
    records=[]
    for host in (DOMAIN,"www."+DOMAIN):
        rows=cloudflare(f"/zones/{zone['id']}/dns_records?"+urllib.parse.urlencode({"name":host,"per_page":100}))
        rows=[row for row in rows if row.get("type") in ("A","AAAA","CNAME") and row.get("name")==host]
        if not rows:raise RuntimeError("No existing frontend DNS record found for "+host)
        for row in rows:
            content=str(row.get("content","")).rstrip(".").lower()
            if content not in GITHUB_IPS|{"prat007ai.github.io",DOMAIN}:
                raise RuntimeError("Unexpected frontend DNS origin for "+host+"; review it before enabling the gate")
            if row.get("proxiable") is False:raise RuntimeError("Frontend DNS record cannot be proxied: "+host)
        records.extend(rows)
    return zone["id"],records


def wrangler(arguments,password=None):
    result=subprocess.run(["npx","--yes","wrangler@4.156.0",*arguments],cwd=ROOT,
        input=json.dumps({"SITE_GATE_PASSWORD":password})+"\n" if password is not None else None,text=True,capture_output=True)
    if password is not None:
        if result.returncode:raise RuntimeError("Could not store the frontend password as an encrypted Worker secret")
        print("Frontend password stored as an encrypted Worker secret")
        return ""
    output=result.stdout+result.stderr
    for secret in (os.environ.get("SITE_GATE_PASSWORD"),os.environ.get("CLOUDFLARE_API_TOKEN")):
        if secret:output=output.replace(secret,"[redacted]")
    print(output)
    if result.returncode:raise RuntimeError("Cloudflare frontend deployment command failed")
    return output


def probe(url,gated,username,password):
    def get(path,authenticate):
        headers={"User-Agent":"CVEHarbor-Site-Gate-Verification/1.0","Cache-Control":"no-cache"}
        if authenticate:headers["Authorization"]="Basic "+base64.b64encode((username+":"+password).encode()).decode()
        request=urllib.request.Request(url+path,headers=headers)
        try:
            with urllib.request.urlopen(request,timeout=25) as response:return response.status,response.headers,response.read(1000)
        except urllib.error.HTTPError as exc:return exc.code,exc.headers,exc.read(1000)
    for path in ("/","/account/","/styles.css","/threat-data.js","/attack-scanning-current.txt","/attack-scanning-current.csv"):
        status,headers,_=get(path,False)
        if gated and (status!=401 or 'realm="CVEHarbor development"' not in headers.get("WWW-Authenticate","")):
            raise RuntimeError("Anonymous request was not protected: "+path+" HTTP "+str(status))
        if gated and "no-store" not in headers.get("Cache-Control",""):
            raise RuntimeError("Gate response allows caching: "+path)
    status,_,_=get("/",gated)
    if status!=200:raise RuntimeError("Authenticated frontend request failed: HTTP "+str(status))


def verify_backend():
    subprocess.run(["node", str(ROOT/"scripts/verify_frontend_backend.mjs")], cwd=ROOT, check=True)


def main():
    # Fail closed before secrets, DNS, or frontend changes, including scheduled publication.
    verify_backend()
    config,gated,password=checked_configuration()
    # All credential and routing checks happen before any DNS or Worker changes.
    zone_id,records=routing_plan(config)
    temp_root=Path(os.environ.get("RUNNER_TEMP",tempfile.gettempdir()))
    settings=cloudflare(f"/accounts/{os.environ['CLOUDFLARE_ACCOUNT_ID']}/workers/scripts/{config['name']}/settings",allow_not_found=True)
    if settings is None:
        staging=dict(config);staging.pop("routes",None);staging["workers_dev"]=True
        staging["main"]=str(ROOT/"site-gate/worker.mjs")
        staging["assets"]={**config["assets"],"directory":str(ROOT/"public")}
        staging_file=temp_root/"cveharbor-site-staging.json";staging_file.write_text(json.dumps(staging))
        output=wrangler(["deploy","--config",str(staging_file)])
        if gated:wrangler(["secret","bulk","--config",str(staging_file)],password)
        urls=re.findall(r"https://[a-z0-9.-]+\.workers\.dev",output)
        if not urls:raise RuntimeError("Cannot verify the protected staging hostname; frontend DNS is unchanged")
        for attempt in range(10):
            try:
                probe(urls[-1],gated,config["vars"]["SITE_GATE_USERNAME"],password);break
            except (RuntimeError,urllib.error.URLError,TimeoutError):
                if attempt==9:raise
                time.sleep(5)
    else:
        names={binding.get("name") for binding in settings.get("bindings",[])}
        if "SITE_GATE_USERNAME" not in names:
            raise RuntimeError("A different Worker already uses the frontend name; review it before replacement")
        if gated:wrangler(["secret","bulk","--config",str(CONFIG)],password)
    (temp_root/"cveharbor-site-dns-before.json").write_text(json.dumps(records,indent=2))
    # Install asset-backed routes first, then enable only the existing frontend proxies.
    wrangler(["deploy","--config",str(CONFIG)])
    for row in records:
        if not row.get("proxied"):
            cloudflare(f"/zones/{zone_id}/dns_records/{row['id']}","PATCH",{"proxied":True,"ttl":1})
    for attempt in range(20):
        try:
            probe("https://"+DOMAIN,gated,config["vars"]["SITE_GATE_USERNAME"],password);break
        except (RuntimeError,urllib.error.URLError,TimeoutError):
            if attempt==19:raise
            time.sleep(15)
    print("PASS: frontend routes and asset downloads are protected; account API and database were not changed")
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"],"a") as output:output.write("page_url=https://cveharbor.com\n")


if __name__=="__main__":main()
