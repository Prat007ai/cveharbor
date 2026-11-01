#!/usr/bin/env python3
"""Capture public production CVIE health only; no customer reads or writes."""
import json
import time
from pathlib import Path
from verify_cvie_production import query

report={"checked_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),"ok":False,"scope":"Read-only production public feed metadata; no customer records queried"}
try:
    report["sources"]=query("SELECT id,status,last_attempt_at,last_success_at,publisher_at,coverage_start_at,error FROM cvie_sources ORDER BY id")
    report["counts"]=query("SELECT (SELECT COUNT(*) FROM cvie_kev) AS kev_records, (SELECT COUNT(*) FROM cvie_disclosures) AS disclosures, (SELECT COUNT(*) FROM cvie_disclosure_queue) AS pending_records, (SELECT COUNT(*) FROM cvie_disclosure_queue WHERE attempts>0) AS retrying_records")[0]
    report["retry_examples"]=query("SELECT cve_id,error,attempts FROM cvie_disclosure_queue WHERE attempts>0 ORDER BY attempts DESC LIMIT 5")
    report["product_job_health"]=query("SELECT status,error,COUNT(*) AS products,MAX(last_attempt_at) AS last_attempt_at,MAX(last_success_at) AS last_success_at FROM cvie_products GROUP BY status,error ORDER BY status")
    report["production_nvd_observed"]=any(row["last_success_at"] for row in report["product_job_health"])
    report["ok"]={s["id"] for s in report["sources"] if s["status"]=="ok" and s["last_success_at"] and 0<=time.time()*1000-s["last_success_at"]<(30 if s["id"]=="cisa_kev" else 15)*60000}=={"cisa_kev","cve_program"} and report["counts"]["kev_records"]>0 and report["counts"]["disclosures"]>0
    report["indexing_complete"]=report["counts"]["pending_records"]==0
except Exception as error:
    report["error"]=str(error)
Path("data/cvie-runtime-check.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps(report))
