#!/usr/bin/env python3
"""Complete authorized gate activation and save only redacted diagnostic evidence."""
import contextlib
import io
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import deploy_site_gate
import disable_public_pages_origin


def main():
    report={"checked_at":datetime.now(timezone.utc).isoformat(),"steps":[],"success":False}
    log=io.StringIO()
    try:
        with contextlib.redirect_stdout(log):
            for name,action in (
                ("deploy_protected_frontend",deploy_site_gate.main),
                ("verify_published_assets",lambda: subprocess.run(
                    ["python","scripts/verify_production.py"],check=True,capture_output=True,text=True)),
                ("disable_old_public_origin",disable_public_pages_origin.main),
            ):
                step={"name":name,"success":False};report["steps"].append(step)
                result=action()
                if isinstance(result,subprocess.CompletedProcess):print(result.stdout)
                step["success"]=True
        report["success"]=True
    except (Exception,SystemExit) as exc:
        report["error"]=type(exc).__name__+": "+str(exc)
        if isinstance(exc,subprocess.CalledProcessError):log.write((exc.stdout or "")+(exc.stderr or ""))
    report["diagnostic"]=log.getvalue()[-10000:]
    encoded=json.dumps(report,indent=2)
    for name in ("SITE_GATE_PASSWORD","CLOUDFLARE_API_TOKEN","GITHUB_TOKEN"):
        value=os.environ.get(name)
        if value:
            # Redact both raw values and their JSON-escaped representation.
            encoded=encoded.replace(json.dumps(value)[1:-1],"[redacted]").replace(value,"[redacted]")
    Path("data/site-gate-activation.json").write_text(encoded+"\n")
    print(encoded)


if __name__=="__main__":main()
