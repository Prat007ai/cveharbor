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
routes=["/account/","/workspace/","/customer-reports/","/customer-dashboard/","/environments/"]
required={
 "/account/":["accountSecurityDashboard","accountSecurityRecoveryStart","account-security.js"],
 "/workspace/":["accountPageRequest","accountPageVerify","accountPageRequiredEnroll"],
 "/customer-reports/":["customerReportEmail","customerReportPrint","customerReportCsv"],
 "/customer-dashboard/":["customerDashStatus"],
 "/environments/":["inventoryCustomerName"]
}

def fetch(path):
    request=Request(base+path,headers={"User-Agent":"CVEHarbor-Production-Verifier/1.0","Cache-Control":"no-cache"})
    with urlopen(request,timeout=30) as response:
        if response.status != 200: raise RuntimeError(f"{path} returned HTTP {response.status}")
        return response.read().decode("utf-8")

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
        for asset in ("styles.css", "customer-security.js", "inventory.js"):
            match = re.search(r'/'+re.escape(asset)+r'\?v=([a-zA-Z0-9-]+)', html)
            if match and not (root / "public" / asset).is_file():
                raise RuntimeError(f"Generated {route} references missing asset {asset}")
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
            for asset in ("styles.css","customer-security.js","inventory.js"):
                m=re.search(r'/'+re.escape(asset)+r'\?v=([a-zA-Z0-9-]+)',expected)
                if not m: continue
                expected_url=f"/{asset}?v={m.group(1)}"
                if expected_url not in html:
                    raise RuntimeError(f"{route} serves stale {asset} version; expected {expected_url}")
                remote=fetch(expected_url)
                local=(root/asset).read_text(encoding="utf-8")
                if hashlib.sha256(remote.encode()).digest()!=hashlib.sha256(local.encode()).digest():
                    raise RuntimeError(f"{route} serves outdated {asset} content")
        print("PASS: Production pages and linked frontend assets match deployed source")
        break
    except Exception as error:
        if attempt==5: raise SystemExit(f"PRODUCTION VERIFICATION FAILED: {error}")
        print(f"Retry {attempt+1}: {error}",flush=True)
        time.sleep(15)
