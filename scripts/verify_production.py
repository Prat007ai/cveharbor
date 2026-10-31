#!/usr/bin/env python3
"""Verify that public production serves the exact assets built by this revision.

This is a no-login smoke test. Private customer workflows need separate
authenticated staging tests and cannot be declared verified by this probe.
"""
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
import hashlib
import re
import time
import sys

root=Path(__file__).resolve().parents[1]
base="https://cveharbor.com"
routes=["/", "/intelligence/", "/vulnerabilities/","/threats/","/account/","/workspace/","/customer-reports/","/customer-dashboard/","/environments/","/website-monitor/"]
required={
 "/":["homepageFeatures", "marketing-story", "asset-onboarding", "findings-table", "homepage.css?v=brochure-216"],
 "/intelligence/":["overviewTitle", "techBars", "chartInsights", "feedStatus"],
 "/vulnerabilities/":["technology-kpis","technologyManageButton","technologyCustomizer","categoryGrid","command-center.js?v=brochure-216"],
 "/threats/":["threatStatus","threatSourceFilter","threatRows","geoMapSummary","Reported suspicious IPs and network ranges"],
 "/account/":["accountSecurityDashboard","accountSecurityRecoveryStart","account-security.js"],
 "/workspace/":["accountPageRequest","accountPageVerify","accountPageRequiredEnroll"],
 "/customer-reports/":["customerReportEmail","customerReportPrint","customerReportCsv"],
 "/customer-dashboard/":["customerDashStatus"],
 "/environments/":["inventoryCustomerName"],
 "/website-monitor/":["monitorForm","monitorStatus","website-monitor-page.js","threatDashboardTitle","threatSiteSelect","threatAssessment","threatHistory"]
}

def fetch_bytes(path):
    request=Request(base+path,headers={"User-Agent":"CVEHarbor-Production-Verifier/1.0","Cache-Control":"no-cache"})
    with urlopen(request,timeout=30) as response:
        if response.status != 200: raise RuntimeError(f"{path} returned HTTP {response.status}")
        return response.read()

def fetch(path):
    return fetch_bytes(path).decode("utf-8")


def verify_local_build():
    """Check generated site and linked assets before publishing."""
    for route in routes:
        page = root / "public" / route.strip("/") / "index.html"
        if not page.is_file():
            raise RuntimeError(f"Generated route missing: {page}")
        html = page.read_text(encoding="utf-8")
        for marker in required[route]:
            if marker not in html:
                raise RuntimeError(f"Generated {route} missing {marker}")
        for asset in ("styles.css", "customer-security.js", "inventory.js", "website-monitor-page.js", "threats.js", "geo-map.js"):
            match = re.search(r'/'+re.escape(asset)+r'\?v=([a-zA-Z0-9-]+)', html)
            if match and not (root / "public" / asset).is_file():
                raise RuntimeError(f"Generated {route} references missing asset {asset}")
    for name in ("website-monitor-demo.png", "platform-explorer.png"):
        if not (root / "public" / "assets" / "homepage" / name).is_file():
            raise RuntimeError("Missing homepage preview asset: " + name)
    print("PASS: Generated routes and linked assets verified before deployment")


verify_local_build()
if "--preflight" in sys.argv:
    sys.exit(0)

for attempt in range(6):
    try:
        for route in routes:
            html=fetch(route)
            expected=(root / "public" / route.strip("/") / "index.html").read_text(encoding="utf-8")
            for marker in required[route]:
                if marker not in html: raise RuntimeError(f"{route} missing {marker}")
            assets=("styles.css","homepage.css","app.js","command-center.js","customer-security.js","inventory.js","website-monitor-page.js")
            if route=="/threats/":assets+=("threats.js","geo-map.js")
            for asset in assets:
                m=re.search(r'/'+re.escape(asset)+r'\?v=([a-zA-Z0-9-]+)',expected)
                if not m: continue
                expected_url=f"/{asset}?v={m.group(1)}"
                if expected_url not in html:
                    raise RuntimeError(f"{route} serves stale {asset} version; expected {expected_url}")
                remote=fetch(expected_url)
                local=(root/asset).read_text(encoding="utf-8")
                if hashlib.sha256(remote.encode()).digest()!=hashlib.sha256(local.encode()).digest():
                    raise RuntimeError(f"{route} serves outdated {asset} content")
        local_threats=(root/"public"/"threat-data.js").read_bytes()
        fingerprint=hashlib.sha256(local_threats).hexdigest()
        remote_threats=fetch_bytes("/threat-data.js?release="+fingerprint[:12])
        if hashlib.sha256(remote_threats).hexdigest()!=fingerprint:
            raise RuntimeError("Published threat indicators differ from this deployment's collected snapshot")
        for name in ("website-monitor-demo.png", "platform-explorer.png"):
            remote = fetch_bytes("/assets/homepage/" + name)
            local = (root / "assets" / "homepage" / name).read_bytes()
            if hashlib.sha256(remote).digest() != hashlib.sha256(local).digest():
                raise RuntimeError("Homepage preview asset differs from deployed source: " + name)
        print("PASS: Production pages and linked frontend assets match deployed source")
        break
    except Exception as error:
        if attempt==5: raise SystemExit(f"PRODUCTION VERIFICATION FAILED: {error}")
        print(f"Retry {attempt+1}: {error}",flush=True)
        time.sleep(15)
