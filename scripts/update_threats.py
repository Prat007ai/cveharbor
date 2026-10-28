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

def export_templates(report):
    """Generate review-only firewall object imports from the same visible snapshot.

    These files intentionally do NOT create deny policies or modify existing rules.
    Failed sources are excluded and all public IPv4 values are revalidated.
    """
    verified = {}
    for entry in report.get("indicators") or []:
        source = entry.get("source_id")
        address = public_ipv4(str(entry.get("ip") or ""))
        if address and report.get("sources", {}).get(source, {}).get("ok"):
            verified.setdefault(source, set()).add(address)
    for key in verified:
        verified[key] = sorted(verified[key], key=lambda value: int(ipaddress.ip_address(value)))[:150]
    timestamp = report.get("checked_at") or "Not available"
    preamble = [
        "CVEHarbor Threat IP Intelligence",
        "Generated: " + timestamp,
        "Review only. Never apply blindly to a production firewall.",
        "Third party scanning and botnet C2 reports are DIFFERENT signal classes.",
        "Validate against local security logs and trusted scanners / cloud service allowlists.",
        "No deny policies or firewall rule modifications are included.",
        "Source IPs have no verified last seen timestamp in this dataset.",
        "",
    ]
    fortinet = [
        "# " + line if line else "" for line in preamble
    ]
    fortinet += [
        "# FortiOS: run these commands in the intended VDOM after backup and review.",
        "# Objects are grouped by report type. Add groups to a reviewed deny policy manually.",
        "# Existing object names are reused, and members are appended; review before rerunning.",
    ]
    for source, suffix in (("dshield_scanners", "SCANNING"), ("feodo_c2", "BOTNET_C2")):
        addresses = verified.get(source, [])
        if not addresses:
            fortinet.append("# " + suffix + ": no successfully collected addresses")
            continue
        fortinet.append("# " + suffix + ": " + str(len(addresses)) + " source-reported IPv4 addresses")
        fortinet.append("config firewall address")
        for address in addresses:
            fortinet += [
                '    edit "CVEH_' + address.replace(".", "_") + '"',
                "        set subnet " + address + " 255.255.255.255",
                "    next",
            ]
        fortinet.append("end")
        fortinet.extend(['config firewall addrgrp','    edit "CVEH_' + suffix + '"'])
        for address in addresses:
            fortinet.append('        append member "CVEH_' + address.replace(".", "_") + '"')
        fortinet += ["    next", "end", ""]
    fortinet.append("# No policy is created or activated. Validate objects and attach the chosen group through change control.")
    (ROOT / "fortigate-threat-ip-objects.txt").write_text("\n".join(fortinet) + "\n", encoding="utf-8")

    sophos = preamble + [
        "Sophos Firewall does not offer FortiOS-style host object CLI paste commands.",
        "The supported bulk configuration mechanism is its XML API.",
        "Enable API access ONLY for trusted administration hosts.",
        "This file contains XML request templates, NOT an executable firewall CLI script.",
        "Do not put actual credentials into a file retained on shared systems.",
        "Save ONE XML Request block at a time as an .xml file, replace the credentials,",
        "and submit using an authenticated POST from a trusted admin workstation:",
        'curl -X POST "https://FIREWALL_HOST:PORT/webconsole/APIController" -F "reqxml=@request.xml"',
        "Use your firewall's valid HTTPS certificate. Check the API response for errors.",
        "Generated IPList host objects are NOT linked to firewall deny rules.",
        "",
    ]
    for source, name in (("dshield_scanners", "CVEH_SCANNING"), ("feodo_c2", "CVEH_BOTNET_C2")):
        addresses = verified.get(source, [])
        if not addresses:
            sophos.append("No validated " + name + " IPs were collected.")
            continue
        # Sophos XML IPList supports comma-separated IPv4 values.
        sophos.extend([
            "===== BEGIN " + name + " REQUEST (" + str(len(addresses)) + " addresses) =====",
            "<Request>",
            "  <Login>",
            "    <Username>REPLACE_ADMIN_USERNAME</Username>",
            "    <Password>REPLACE_ADMIN_PASSWORD</Password>",
            "  </Login>",
            '  <Set operation="add">',
            "    <IPHost>",
            "      <Name>" + name + "</Name>",
            "      <IPFamily>IPv4</IPFamily>",
            "      <HostType>IPList</HostType>",
            "      <ListOfIPAddresses>" + ",".join(addresses) + "</ListOfIPAddresses>",
            "    </IPHost>",
            "  </Set>",
            "</Request>",
            "===== END " + name + " REQUEST =====",
            "",
        ])
    (ROOT / "sophos-threat-ip-api.txt").write_text("\n".join(sophos) + "\n", encoding="utf-8")


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
    export_templates(report)\n    # Never make source first-seen or the collection timestamp look like attacker last-seen evidence.
    OUT.write_text("window.CVEHARBOR_THREATS = "+json.dumps(report,separators=(",",":")).replace("</","<\\/")+";\n",encoding="utf-8")
    print("Threat IP feeds:",{k:v.get("count",v.get("error")) for k,v in report["sources"].items()})
    return 0 if report["count"] else 1

if __name__=="__main__":
    raise SystemExit(collect())
