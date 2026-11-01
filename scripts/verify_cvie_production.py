#!/usr/bin/env python3
"""Read-only production checks: API isolation, additive schema and scheduled feeds.

Runs in the existing deployment job with its Cloudflare credentials. It never
reads customer rows, signs in as a customer or changes production records.
"""
import argparse
import json
import os
import time
import urllib.error
import urllib.request

stage = "initialization"

DATABASE = "46710e51-7ca4-4571-b89c-921b9969de0b"
TABLES = {"cvie_products", "cvie_subscriptions", "cvie_advisories",
          "cvie_provider_budget", "cvie_sources", "cvie_disclosures",
          "cvie_disclosure_products", "cvie_disclosure_queue", "cvie_kev"}


def query(sql):
    account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
    request = urllib.request.Request(
        f"https://api.cloudflare.com/client/v4/accounts/{account}/d1/database/{DATABASE}/query",
        data=json.dumps({"sql": sql, "params": []}).encode(),
        headers={"Authorization": "Bearer " + os.environ["CLOUDFLARE_API_TOKEN"],
                 "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"Production schema verification returned HTTP {exc.code}") from None
    results = payload.get("result", [])
    if not payload.get("success") or not results or not all(r.get("success") for r in results):
        raise RuntimeError("Production database verification failed")
    return results[0]["results"]


def main():
    global stage
    parser = argparse.ArgumentParser()
    parser.add_argument("--wait-for-feeds", type=int, default=900)
    args = parser.parse_args()
    stage = "account API health"
    health = urllib.request.Request("https://api.cveharbor.com/v1/health", headers={"Accept": "application/json", "User-Agent": "CVEHarbor-Production-Verifier/1.0"})
    with urllib.request.urlopen(health, timeout=30) as response:
        if json.load(response).get("accounts") != "configured":
            raise RuntimeError("Production account API is not configured")
    stage = "private CVIE authentication"
    try:
        endpoint = urllib.request.Request("https://api.cveharbor.com/v1/cvie", headers={"Accept": "application/json", "User-Agent": "CVEHarbor-Production-Verifier/1.0"})
        urllib.request.urlopen(endpoint, timeout=30).close()
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise RuntimeError(f"Private CVIE route returned unexpected HTTP {exc.code}") from None
    else:
        raise RuntimeError("Private CVIE route did not require authentication")
    stage = "production CVIE schema"
    names = {row["name"] for row in query("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'cvie_%'")}
    if not TABLES <= names:
        raise RuntimeError("CVIE migration is incomplete: " + ", ".join(sorted(TABLES - names)))
    if not query("SELECT key FROM cvie_maintenance WHERE key='cvie-audit-v1'"):
        raise RuntimeError("The one-time CVIE audit cache refresh was not recorded")
    print("PASS: account API healthy, private CVIE route protected, core tables present and audit cache refresh recorded", flush=True)
    deadline = time.monotonic() + max(0, args.wait_for_feeds)
    stage = "scheduled source ingestion"
    while True:
        sources = query("SELECT id,status,last_success_at,error FROM cvie_sources ORDER BY id")
        totals = query("SELECT (SELECT COUNT(*) FROM cvie_kev) AS kev_records, (SELECT COUNT(*) FROM cvie_disclosures) AS disclosures, (SELECT COUNT(*) FROM cvie_disclosure_queue) AS pending_records")[0]
        print(json.dumps({"sources": sources, "public_record_counts": totals}), flush=True)
        fresh = {s["id"] for s in sources if s["status"] == "ok" and s["last_success_at"] and time.time()*1000-s["last_success_at"] < 30*60000}
        if {"cve_program", "cisa_kev"} <= fresh and totals["kev_records"] > 0 and totals["disclosures"] > 0:
            jobs=query("SELECT status,COUNT(*) AS products FROM cvie_products GROUP BY status ORDER BY status")
            health=json.dumps({"sources":sources,"public_record_counts":totals,"product_jobs":jobs,"audit_cache_refresh_recorded":True})
            print("::notice title=CVIE release verification::"+health.replace("%","%25").replace("\r","%0D").replace("\n","%0A"),flush=True)
            print("PASS: production scheduled jobs collected original CVE disclosures and CISA KEV; remaining indexing stays visible", flush=True)
            summary = os.environ.get("GITHUB_STEP_SUMMARY")
            if summary:
                with open(summary, "a") as output:
                    output.write("\nCVIE production checks passed: authenticated API isolation, nine additive tables, fresh original CVE and CISA KEV collection, and original-record ingestion.\n")
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("CVIE deployed, but live scheduled-feed verification is not yet complete; inspect the source status above")
        time.sleep(min(30, max(0, deadline-time.monotonic())))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        message = (stage + ": " + str(error)).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print("::error title=CVIE production check::" + message, flush=True)
        raise SystemExit(1) from None
