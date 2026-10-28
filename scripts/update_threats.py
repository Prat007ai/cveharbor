#!/usr/bin/env python3
"""Public review-only threat indicators. Never auto-block or infer customer exposure."""
import ipaddress
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"threat-data.js"
FEEDS={
 "dshield_scanners":("https://feeds.dshield.org/feeds/topips.txt","SANS Internet Storm Center","Observed scanning and attack sources"),
 "feodo_c2":("https://feodotracker.abuse.ch/downloads/ipblocklist.txt","abuse.ch Feodo Tracker","Botnet command and control"),
}
def public_ipv4(value):
    try:
        address=ipaddress.ip_address(value)
        return str(address) if address.version==4 and address.is_global else None
    except ValueError:
        return None

def collect():
    report={"checked_at":datetime.now(timezone.utc).isoformat(),"sources":{},"indicators":[]}
    for key,(url,name,activity) in FEEDS.items():
        try:
            request=urllib.request.Request(url,headers={"User-Agent":"CVEHarbor-ThreatIntel/1.0","Accept":"text/plain"})
            with urllib.request.urlopen(request,timeout=25) as resp:
                body=resp.read(700_001)
            if len(body)>700_000:
                raise ValueError("Feed larger than safety limit")
            raw=body.decode("utf-8-sig")
            entries={}
            for line in raw.splitlines():
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                # DShield sometimes has a first header row, followed by IP and tabular counts.
                parts=re.split(r"[\s,;]+",line.strip())
                ip=public_ipv4(parts[0])
                if ip:
                    entries[ip]={"ip":ip,"source":name,"source_id":key,
                                 "activity":activity,"source_url":url,
                                 "observed_at":None,
                                 "guidance":"Review logs and local allowlists before taking action."}
            if not entries:
                raise ValueError("No valid public IPv4 indicators in source")
            report["indicators"].extend(list(entries.values())[:150])
            report["sources"][key]={"ok":True,"count":len(entries),"url":url}
        except Exception as exc:
            report["sources"][key]={"ok":False,"error":str(exc)[:160],"url":url}
    report["count"]=len(report["indicators"])
    # Never make source first-seen or the collection timestamp look like attacker last-seen evidence.
    OUT.write_text("window.CVEHARBOR_THREATS = "+json.dumps(report,separators=(",",":")).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Threat IP feeds:",{k:v.get("count",v.get("error")) for k,v in report["sources"].items()})
    return 0 if report["count"] else 1

if __name__=="__main__":
    raise SystemExit(collect())
