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
        return str(address) if address.version==4 and address.is_global and not address.is_multicast and not address.is_reserved else None
    except ValueError:
        return None

HISTORY=ROOT/"data"/"threat-ip-history.json"
GROUP_NAME="Suspicious IP Block"

def object_name(address):
    return "CVEH_"+address.replace(".","_")

def ip_order(values):
    return sorted(values,key=lambda address:int(ipaddress.ip_address(address)))

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
    # Geographic attribution is approximate IP network registration data, not
    # the location of a person controlling the address. Cache to minimize API calls.
    cache_path=ROOT/"data"/"ip-geolocation-cache.json"
    try:
        cache=json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    except (ValueError,OSError):
        cache={}
    for entry in report["indicators"]:
        ip=entry["ip"]
        geo=cache.get(ip)
        if not isinstance(geo,dict):
            try:
                req=urllib.request.Request("https://ipwho.is/"+ip,
                    headers={"User-Agent":"CVEHarbor-ThreatIntel/1.0 (https://cveharbor.com)"})
                with urllib.request.urlopen(req,timeout=8) as response:
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
    report["geolocated_count"]=sum(1 for x in report["indicators"] if x.get("geo"))
    report["geo_source"]="ipwho.is IP geolocation; approximate network location, not verified origin"
    report["count"]=len(report["indicators"])
    export_templates(report)
    # Never make source first-seen or the collection timestamp look like attacker last-seen evidence.
    OUT.write_text("window.CVEHARBOR_THREATS = "+json.dumps(report,separators=(",",":")).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Threat IP feeds:",{k:v.get("count",v.get("error")) for k,v in report["sources"].items()})
    return 0 if report["count"] else 1

if __name__=="__main__":
    raise SystemExit(collect())
