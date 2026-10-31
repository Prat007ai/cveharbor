#!/usr/bin/env python3
"""Public review-only threat indicators. Never auto-block or infer customer exposure."""
import hashlib
import csv
import io
import ipaddress
import json
import os
import re
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/"threat-data.js"
FEEDS={
 "dshield_scanners":("https://feeds.dshield.org/feeds/topips.txt","SANS Internet Storm Center","Observed scanning and attack sources"),
 "blocklist_de":("https://lists.blocklist.de/lists/all.txt","blocklist.de","Reported server attacks and brute-force attempts"),
 "greensnow":("https://blocklist.greensnow.co/greensnow.txt","GreenSnow","Reported scanning and attack activity"),
 "feodo_c2":("https://feodotracker.abuse.ch/downloads/ipblocklist.txt","abuse.ch Feodo Tracker","Botnet command and control"),
 "threatfox":("https://threatfox-api.abuse.ch/api/v1/","abuse.ch ThreatFox","Malware-associated IP"),
 "spamhaus_drop":("https://www.spamhaus.org/drop/drop_v4.json","Spamhaus DROP","Reported malicious network range"),
}
def public_ipv4(value):
    try:
        address=ipaddress.ip_address(value)
        return str(address) if address.version==4 and address.is_global and not address.is_multicast and not address.is_reserved else None
    except ValueError:
        return None

SOURCE_LIMIT=500
ATTACK_SOURCE_IDS=frozenset({"dshield_scanners","blocklist_de","greensnow"})
ATTACK_EXPORT_FILES=("attack-scanning-current.txt","attack-scanning-current.csv","attack-scanning-current.json")

def feed_byte_limit(key):
    return 32_000_000 if key=="threatfox" else 8_000_000 if key in ("blocklist_de","greensnow") else 700_000

def public_network(value):
    try:
        net=ipaddress.ip_network(value,strict=True)
        return str(net) if net.version==4 and net.is_global and public_ipv4(str(net.network_address)) and public_ipv4(str(net.broadcast_address)) else None
    except ValueError:
        return None

def source_time(value):
    if not value:
        return None
    try:
        text=str(value).strip()
        if not isinstance(value,bool) and (isinstance(value,(int,float)) or re.fullmatch(r"\d{9,13}(?:\.\d+)?",text)):
            seconds=float(value)
            if seconds>100_000_000_000:seconds/=1000
            return datetime.fromtimestamp(seconds,timezone.utc)
        date=datetime.fromisoformat(text.replace("Z","+00:00").removesuffix(" UTC"))
        return date.replace(tzinfo=date.tzinfo or timezone.utc).astimezone(timezone.utc)
    except (ValueError,TypeError,OverflowError,OSError):
        return None

def parse_source(key,raw,now,diagnostics=None):
    url,name,activity=FEEDS[key]
    entries={}
    def base(address,kind="ip"):
        return {"ip":address,"kind":kind,"source":name,"source_id":key,"activity":activity,
                "source_url":url,"observed_at":None,
                "guidance":"Review source evidence, ownership and local allowlists before action."}
    if key=="threatfox":
        data=json.loads(raw)
        if data.get("query_status")=="no_result":
            return entries
        if data.get("query_status")!="ok" or not isinstance(data.get("data"),list):
            raise ValueError("ThreatFox did not return a successful IOC response")
        stats={"provider_records":len(data["data"]),"ip_port_records":0,"missing_observation":0,"expired":0,"future_observation":0}
        for row in data["data"]:
            if row.get("ioc_type")!="ip:port":
                continue
            stats["ip_port_records"]+=1
            if "observation_fields" not in stats:
                stats["observation_fields"]={k:str(v)[:64] for k,v in row.items() if "seen" in k.lower() and isinstance(v,(str,int,float,type(None)))}
            host,sep,port=str(row.get("ioc","")).rpartition(":")
            address=public_ipv4(host)
            if not sep or not address or not port.isdigit() or not 1<=int(port)<=65535:
                continue
            # Accept UTC date fields and Unix-valued observation aliases.
            first=source_time(row.get("first_seen_utc") or row.get("first_seen"))
            last=source_time(row.get("last_seen_utc") or row.get("last_seen"))
            observed=last or first
            if not observed:stats["missing_observation"]+=1;continue
            if observed<now-timedelta(days=30):stats["expired"]+=1;continue
            if observed>now+timedelta(minutes=5):stats["future_observation"]+=1;continue
            entry=entries.setdefault(address,base(address))
            confidence=row.get("confidence_level")
            evidence={"ioc_id":str(row.get("id",""))[:40],"port":int(port),
                      "malware":str(row.get("malware_printable") or row.get("malware") or "Unknown")[:100],
                      "threat_type":str(row.get("threat_type") or "Malware association")[:100],
                      "source_confidence":confidence if isinstance(confidence,(float,int)) and 0<=confidence<=100 else None,
                      "first_seen":first.isoformat() if first else None,"last_seen":last.isoformat() if last else None}
            entry.setdefault("evidence",[])
            if len(entry["evidence"])<10:entry["evidence"].append(evidence)
            if not entry.get("observed_at") or observed.isoformat()>entry["observed_at"]:
                entry["observed_at"]=observed.isoformat()
            if first and (not entry.get("first_seen") or first.isoformat()<entry["first_seen"]):entry["first_seen"]=first.isoformat()
            if last and (not entry.get("last_seen") or last.isoformat()>entry["last_seen"]):entry["last_seen"]=last.isoformat()
            entry["expires_at"]=(source_time(entry["observed_at"])+timedelta(days=30)).isoformat()
            entry["source_url"]="https://threatfox.abuse.ch/browse.php?search=ioc%3A"+address
        if diagnostics is not None:diagnostics.update(stats)
        if stats["ip_port_records"] and not entries and stats["missing_observation"]:
            raise ValueError("ThreatFox IP reports lack usable observation timestamps")
        return dict(sorted(entries.items(),key=lambda pair:pair[1]["observed_at"],reverse=True))
    if key=="spamhaus_drop":
        # Official DROP v4 export is newline-delimited JSON, with a metadata footer.
        records=[json.loads(line) for line in raw.splitlines() if line.strip()]
        if not records or any(not isinstance(row,dict) for row in records):
            raise ValueError("Invalid DROP JSON records")
        for row in records:
            if "cidr" not in row:
                if row.get("type")=="metadata":continue
                raise ValueError("Unexpected DROP record")
            network=public_network(str(row["cidr"]))
            if not network:continue
            entry=base(network,"network");entry["network"]=network
            entry["sbl_id"]=str(row.get("sblid") or "")[:50]
            entry["source_url"]="https://www.spamhaus.org/drop/"
            entry["guidance"]="This is an entire network range, not one host. Review Spamhaus evidence, current listing and local traffic before any range-wide action."
            entries[network]=entry
        if not entries:raise ValueError("No valid global IPv4 ranges in DROP")
        return entries
    if key in ("blocklist_de","greensnow") and re.search(r"<!doctype\s+html|<html\b",raw[:1000],re.I):
        raise ValueError("Expected an IP list, received an HTML page")
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):continue
        if key in ("blocklist_de","greensnow"):
            address=public_ipv4(line.split("#",1)[0].strip())
        else:
            parts=re.split(r"[\s,;]+",line.strip());address=public_ipv4(parts[0])
        if address:entries[address]=base(address)
    if not entries:raise ValueError("No valid public IPv4 indicators in source")
    return entries

HISTORY=ROOT/"data"/"threat-ip-history.json"
GROUP_NAME="Suspicious IP Block"

def object_name(address):
    return "CVEH_"+address.replace(".","_")

def ip_order(values):
    return sorted(values,key=lambda address:int(ipaddress.ip_address(address)))

def export_attack_current(report,source_entries,output_root=None):
    """Full current successful attack feeds, independent of the browser preview cap.

    This is not cumulative history and contains no malware/CIDR/retained reports.
    Observation times are never inferred from a download or collection timestamp.
    """
    folder=Path(output_root) if output_root is not None else ROOT
    folder.mkdir(parents=True,exist_ok=True)
    addresses={}
    configured=[key for key in FEEDS if key in ATTACK_SOURCE_IDS]
    successful=[key for key in configured if report.get("sources",{}).get(key,{}).get("ok")]
    for key in successful:
        for entry in source_entries.get(key,{}).values():
            address=public_ipv4(str(entry.get("ip") or ""))
            if address and entry.get("source_id")==key and entry.get("kind")!="network" and not entry.get("stale"):
                addresses.setdefault(address,set()).add(key)
    ordered=ip_order(addresses)
    content=("\n".join(ordered)+("\n" if ordered else "")).encode("utf-8")
    (folder/ATTACK_EXPORT_FILES[0]).write_bytes(content)
    csv_data=io.StringIO(newline="")
    writer=csv.writer(csv_data)
    writer.writerow(["IP address","Reporting sources"])
    for address in ordered:
        writer.writerow([address,"; ".join(FEEDS[key][1] for key in sorted(addresses[address]))])
    (folder/ATTACK_EXPORT_FILES[1]).write_text(csv_data.getvalue(),encoding="utf-8",newline="")
    meta={"generated_at":report.get("checked_at"),"count":len(ordered),"available":bool(ordered),
          "complete":bool(configured) and len(successful)==len(configured),
          "scope":"Current successful attack/scanning feeds only; review before blocking",
          "sha256":hashlib.sha256(content).hexdigest(),
          "sources":{key:{"name":FEEDS[key][1],"url":FEEDS[key][0],
                          "ok":key in successful,"count":report.get("sources",{}).get(key,{}).get("count",0),
                          "last_success":report.get("sources",{}).get(key,{}).get("last_success")}
                     for key in configured}}
    (folder/ATTACK_EXPORT_FILES[2]).write_text(json.dumps(meta,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    return meta

def export_templates(report):
    """Append-only, review-only history. Never equate collection time with last seen.

    Delta is relative to the immediately preceding successful publication, NOT
    relative to any particular firewall configuration. Operators who skip
    updates must use the cumulative file and reconcile local firewall state.
    """
    previous={}
    if HISTORY.exists():
        previous=json.loads(HISTORY.read_text(encoding="utf-8"))
    saved=previous.get("addresses") or {}
    cumulative={}
    for ip,entry in saved.items():
        address=public_ipv4(ip)
        if address and isinstance(entry,dict):
            cumulative[address]={"sources":sorted(set(entry.get("sources") or [])),
                                 "first_indexed":entry.get("first_indexed") or "",
                                 "last_indexed":entry.get("last_indexed") or ""}
    additions={}
    timestamp=report.get("checked_at") or datetime.now(timezone.utc).isoformat()
    for entry in report.get("indicators") or []:
        source=entry.get("source_id")
        address=public_ipv4(str(entry.get("ip") or ""))
        if not address or not report.get("sources",{}).get(source,{}).get("ok"):
            continue
        if address not in cumulative:
            additions[address]={"sources":[source],"first_indexed":timestamp,"last_indexed":timestamp}
            cumulative[address]=dict(additions[address])
        else:
            cumulative[address]["sources"]=sorted(set(cumulative[address]["sources"])|{source})
            cumulative[address]["last_indexed"]=timestamp
    all_ips=ip_order(cumulative)
    new_ips=ip_order(additions)
    HISTORY.parent.mkdir(parents=True,exist_ok=True)
    HISTORY.write_text(json.dumps({"generated_at":timestamp,"group_name":GROUP_NAME,
                                    "addresses":cumulative},indent=2,sort_keys=True)+"\n",encoding="utf-8")

    intro=[
        "CVEHarbor Threat IP Intelligence | "+timestamp,
        "Permanent logical group: "+GROUP_NAME,
        "Cumulative indexed IPs: "+str(len(all_ips)),
        "New since prior published snapshot: "+str(len(new_ips)),
        "REVIEW ONLY: reported indicators are NOT approved firewall blocks.",
        "Do not apply blindly. Check allowlists, cloud/VPN ownership and your logs.",
        "No rules or policies are created or enabled. No old IPs are removed.",
        "The incremental file is not a comparison against your firewall.",
        "If you skipped an update, use the cumulative file and reconcile existing objects.",
        "Collection timestamps are NOT verified source last-seen times.",
        ""
    ]
    def fortinet_file(addresses, incremental):
        lines=["# "+line if line else "" for line in intro]
        lines += ["# FortiOS. Run in the correct VDOM following change control.",
                  "# The group must exist before the incremental update is used.",
                  "# If an address object name already exists with a different subnet, STOP.",
                  "# Applying group membership can affect an existing deny policy immediately.",
                  "config firewall address"]
        for ip in addresses:
            lines += ['    edit "'+object_name(ip)+'"',
                      "        set subnet "+ip+" 255.255.255.255",
                      "    next"]
        lines+=["end","config firewall addrgrp",'    edit "'+GROUP_NAME+'"']
        if not incremental:
            lines+=['        set comment "Reviewed CVEHarbor IP indicators"']
        for ip in addresses:
            lines+=['        append member "'+object_name(ip)+'"']
        lines+=["    next","end",
                "# No firewall policy has been created. Review existing policy use."]
        return "\n".join(lines)+"\n"

    (ROOT/"fortigate-suspicious-ip-initial.txt").write_text(
        fortinet_file(all_ips,False),encoding="utf-8")
    (ROOT/"fortigate-suspicious-ip-incremental.txt").write_text(
        fortinet_file(new_ips,True),encoding="utf-8")

    # Sophos group update semantics can REPLACE HostList. Do not claim an
    # append operation without fetching/merging the actual firewall HostList.
    def request_object(ip):
        name=object_name(ip)
        return [
            '    <IPHost>',
            '      <Name>'+name+'</Name>',
            '      <IPFamily>IPv4</IPFamily>',
            '      <HostType>IP</HostType>',
            '      <IPAddress>'+ip+'</IPAddress>',
            '    </IPHost>',
        ]
    def sophos_file(addresses, initial):
        lines=intro+[
            "Sophos Firewall uses an XML API, NOT FortiGate CLI syntax.",
            "Templates below contain placeholders, not credentials.",
            "Use a trusted management host and an authenticated POST to /webconsole/APIController.",
            "Ensure the firewall XML API supports this request on your firmware.",
            "Submit the XML portion as ONE request and inspect the API response.",
            "Add / update host objects only after admin review.",
            "Never overwrite an existing group HostList without reading its current members.",
            "No firewall rule is created or activated.",
            "",
            "===== XML REQUEST START =====",
            "<Request>",
            "  <Login>",
            "    <Username>REPLACE_ADMIN_USERNAME</Username>",
            "    <Password>REPLACE_ADMIN_PASSWORD</Password>",
            "  </Login>",
            '  <Set operation="add">'
        ]
        for ip in addresses:
            lines.extend(request_object(ip))
        if initial:
            lines += ['    <IPHostGroup>',
                      '      <Name>'+GROUP_NAME+'</Name>',
                      '      <IPFamily>IPv4</IPFamily>',
                      '      <Description>Reviewed CVEHarbor indicators</Description>',
                      '      <HostList>']
            for ip in addresses:
                lines+=['        <Host>'+object_name(ip)+'</Host>']
            lines+=['      </HostList>','    </IPHostGroup>']
        lines+=["  </Set>","</Request>","===== XML REQUEST END =====",""]
        if not initial:
            lines += [
              "IMPORTANT: Host creation above does NOT add hosts to an existing group.",
              "Sophos group updates can REPLACE the complete HostList.",
              "Read the existing IPHostGroup named '"+GROUP_NAME+"' using the XML API.",
              "Merge the newly created host names with ALL existing members, deduplicate,",
              "then submit an IPHostGroup edit with that complete merged HostList.",
              "Do not issue a group edit containing only the new IPs.",
              "New host names to merge:"
            ]
            lines += [object_name(ip) for ip in addresses]
        return "\n".join(lines)+"\n"
    (ROOT/"sophos-suspicious-ip-initial.txt").write_text(sophos_file(all_ips,True),encoding="utf-8")
    (ROOT/"sophos-suspicious-ip-incremental.txt").write_text(sophos_file(new_ips,False),encoding="utf-8")

    # Maintain legacy filenames for old links, now with the cumulative group.
    (ROOT/"fortigate-threat-ip-objects.txt").write_text(
        fortinet_file(all_ips,False),encoding="utf-8")
    (ROOT/"sophos-threat-ip-api.txt").write_text(sophos_file(all_ips,True),encoding="utf-8")

def read_report():
    try:
        raw=OUT.read_text(encoding="utf-8")
        value=json.loads(raw.split("=",1)[1].strip().removesuffix(";"))
        return value if isinstance(value,dict) and isinstance(value.get("indicators"),list) else {}
    except (OSError,ValueError,IndexError):
        return {}

def collect():
    previous=read_report()
    timestamp=datetime.now(timezone.utc).isoformat()
    report={"schema_version":2,"checked_at":timestamp,"sources":{},"indicators":[],
            "per_source_limit":SOURCE_LIMIT,"added_count":0,"removed_count":0}
    attack_entries={}
    for key,(url,name,activity) in FEEDS.items():
        parsing={}
        try:
            headers={"User-Agent":"CVEHarbor-ThreatIntel/1.0","Accept":"application/json" if key in ("threatfox","spamhaus_drop") else "text/plain"}
            payload=None
            if key=="threatfox":
                auth=os.environ.get("THREATFOX_AUTH_KEY")
                if not auth:raise ValueError("THREATFOX_AUTH_KEY is not configured")
                headers["Auth-Key"]=auth;headers["Content-Type"]="application/json"
                payload=json.dumps({"query":"get_iocs","days":7}).encode()
            request=urllib.request.Request(url,data=payload,headers=headers)
            # A seven-day ThreatFox response can exceed 4 MB even though only
            # 500 parsed IP reports are published. Keep download memory bounded.
            max_bytes=feed_byte_limit(key)
            with urllib.request.urlopen(request,timeout=25) as resp:
                body=resp.read(max_bytes+1)
                modified=resp.headers.get("Last-Modified")
            if len(body)>max_bytes:raise ValueError("Feed larger than safety limit")
            entries=parse_source(key,body.decode("utf-8-sig"),datetime.now(timezone.utc),parsing)
            if key in ATTACK_SOURCE_IDS:attack_entries[key]=entries
            published=list(entries.values())[:SOURCE_LIMIT]
            old={x["ip"] for x in previous.get("indicators",[]) if x.get("source_id")==key}
            current={x["ip"] for x in published}
            saved_source=previous.get("sources",{}).get(key,{})
            changed=current!=old
            report["indicators"].extend(published)
            report["sources"][key]={"ok":True,"count":len(entries),"published_count":len(published),
                "truncated":len(entries)>SOURCE_LIMIT,"url":url,"last_attempt":timestamp,"last_success":timestamp,
                "last_changed_at":timestamp if changed else saved_source.get("last_changed_at"),
                "added_count":len(current-old),"removed_count":len(old-current),
                "body_sha256":hashlib.sha256(body).hexdigest(),"upstream_last_modified":modified,
                "parsing":parsing}
            report["added_count"]+=len(current-old)
            report["removed_count"]+=len(old-current)
        except Exception as exc:
            saved_source=previous.get("sources",{}).get(key,{})
            last_success=saved_source.get("last_success") or (previous.get("checked_at") if saved_source.get("ok") else None)
            recent=source_time(last_success)
            retained=[dict(x,stale=True) for x in previous.get("indicators",[])
                      if x.get("source_id")==key and (public_ipv4(str(x.get("ip",""))) or public_network(str(x.get("network",""))))
                      and recent and datetime.now(timezone.utc)-recent<=timedelta(hours=72)
                      and (not x.get("expires_at") or (source_time(x["expires_at"]) and source_time(x["expires_at"])>datetime.now(timezone.utc)))]
            report["indicators"].extend(retained)
            report["sources"][key]={"ok":False,"error":str(exc)[:160],"url":url,
                "last_attempt":timestamp,"last_success":last_success,"retained_count":len(retained),
                "last_changed_at":saved_source.get("last_changed_at"),"parsing":parsing}
    healthy=sum(bool(x.get("ok")) for x in report["sources"].values())
    report["mode"]="live" if healthy==len(FEEDS) else "partial" if healthy else "failed"
    report["last_successful_update"]=timestamp if healthy==len(FEEDS) else previous.get("last_successful_update")
    old_pairs={(x["ip"],x["source_id"]) for x in previous.get("indicators",[])}
    new_pairs={(x["ip"],x["source_id"]) for x in report["indicators"]}
    report["last_changed_at"]=timestamp if old_pairs!=new_pairs and healthy else previous.get("last_changed_at")
    report["unique_ip_count"]=len({x["ip"] for x in report["indicators"] if x.get("kind")!="network"})
    report["network_range_count"]=len({x["ip"] for x in report["indicators"] if x.get("kind")=="network"})
    report["stale_count"]=sum(bool(x.get("stale")) for x in report["indicators"])
    report["attack_export"]=export_attack_current(report,attack_entries)
    # Geographic attribution is approximate IP network registration data, not
    # the location of a person controlling the address. Cache to minimize API calls.
    cache_path=ROOT/"data"/"ip-geolocation-cache.json"
    try:
        cache=json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    except (ValueError,OSError):
        cache={}
    geo_attempts=0
    for entry in report["indicators"]:
        if entry.get("kind")=="network":continue
        ip=entry["ip"]
        geo=cache.get(ip) or entry.get("geo")
        if not isinstance(geo,dict) and geo_attempts<20:
            geo_attempts+=1
            try:
                req=urllib.request.Request("https://ipwho.is/"+ip,
                    headers={"User-Agent":"CVEHarbor-ThreatIntel/1.0 (https://cveharbor.com)"})
                with urllib.request.urlopen(req,timeout=5) as response:
                    result=json.loads(response.read(10000))
                country=str(result.get("country") or "")[:70]
                latitude=result.get("latitude")
                longitude=result.get("longitude")
                if (result.get("success") is True and country
                    and isinstance(latitude,(float,int)) and isinstance(longitude,(float,int))
                    and -90<=latitude<=90 and -180<=longitude<=180):
                    geo={"country":country,"country_code":str(result.get("country_code") or "")[:3],
                         "latitude":float(latitude),"longitude":float(longitude)}
                    cache[ip]=geo
            except (ValueError,OSError,TimeoutError,KeyError):
                pass
        if isinstance(geo,dict):
            entry["geo"]=geo
    cache_path.parent.mkdir(parents=True,exist_ok=True)
    cache_path.write_text(json.dumps(cache,sort_keys=True,indent=2)+"\n",encoding="utf-8")
    report["geolocation_attempts"]=geo_attempts
    report["geolocated_count"]=sum(1 for x in report["indicators"] if x.get("geo"))
    report["geo_source"]="ipwho.is IP geolocation; approximate network location, not verified origin"
    report["count"]=len(report["indicators"])
    export_templates(report)
    # Never make source first-seen or the collection timestamp look like attacker last-seen evidence.
    OUT.write_text("window.CVEHARBOR_THREATS = "+json.dumps(report,separators=(",",":")).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Threat IP feeds:",{k:v.get("count",v.get("error")) for k,v in report["sources"].items()})
    return 0 if report["mode"]=="live" else 1

if __name__=="__main__":
    raise SystemExit(collect())
