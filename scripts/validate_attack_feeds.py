#!/usr/bin/env python3
"""Validate public attack feeds without changing production data or using keys."""
import argparse
import hashlib
import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from update_threats import ATTACK_SOURCE_IDS, FEEDS, SOURCE_LIMIT, export_attack_current, feed_byte_limit, parse_source


def validate(folder):
    timestamp=datetime.now(timezone.utc).isoformat()
    report={"checked_at":timestamp,"source_revision":os.environ.get("GITHUB_SHA"),
            "per_source_limit":SOURCE_LIMIT,"sources":{},"indicators":[]}
    all_entries={}
    for key,(url,name,activity) in FEEDS.items():
        if key not in ATTACK_SOURCE_IDS:continue
        try:
            req=urllib.request.Request(url,headers={"User-Agent":"CVEHarbor-ThreatIntel/1.0","Accept":"text/plain"})
            limit=feed_byte_limit(key)
            with urllib.request.urlopen(req,timeout=30) as response:
                body=response.read(limit+1);modified=response.headers.get("Last-Modified")
            if len(body)>limit:raise ValueError("Feed larger than safety limit")
            entries=parse_source(key,body.decode("utf-8-sig"),datetime.now(timezone.utc))
            all_entries[key]=entries
            preview=list(entries.values())[:SOURCE_LIMIT]
            report["indicators"].extend(preview)
            report["sources"][key]={"ok":True,"count":len(entries),"published_count":len(preview),
                "truncated":len(entries)>SOURCE_LIMIT,"last_attempt":timestamp,"last_success":timestamp,
                "url":url,"body_sha256":hashlib.sha256(body).hexdigest(),"upstream_last_modified":modified}
        except Exception as exc:
            report["sources"][key]={"ok":False,"error":str(exc)[:160],"last_attempt":timestamp,"url":url}
    healthy=sum(bool(s.get("ok")) for s in report["sources"].values())
    report["mode"]="live" if healthy==len(ATTACK_SOURCE_IDS) else "partial" if healthy else "failed"
    report["attack_export"]=export_attack_current(report,all_entries,folder)
    report["unique_ip_count"]=len({x["ip"] for x in report["indicators"]})
    report["count"]=len(report["indicators"])
    (folder/"report.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"mode":report["mode"],"unique_current_export_ips":report["attack_export"]["count"],
                      "sources":{k:{field:v[field] for field in ("ok","count","error") if field in v} for k,v in report["sources"].items()}}))
    return 0 if report["mode"]=="live" else 1


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output",type=Path,default=Path("data/attack-feed-validation"))
    args=parser.parse_args()
    raise SystemExit(validate(args.output))
