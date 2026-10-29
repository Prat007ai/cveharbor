#!/usr/bin/env python3
"""Collect public, vendor-authored release notes. Never invent patch/CU fixes.

A new release is not automatically a security update. Only vendor posts with
security language may be labelled security-related, and even those need review.
"""
import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "patch-notes.js"
REPOS = {
    "dotnet": "dotnet/runtime",
    "powershell": "PowerShell/PowerShell",
    "php": "php/php-src",
    "wordpress": "WordPress/wordpress-develop",
    "mariadb": "MariaDB/server",
    "kubernetes": "kubernetes/kubernetes",
}
MAX_NOTES = 800

def clean(value):
    return re.sub(r"\s+", " ", re.sub(r"[<>\x00-\x1f]", " ", str(value or ""))).strip()[:MAX_NOTES]

def collect():
    result = {"checked_at": datetime.now(timezone.utc).isoformat(),
              "releases": [], "errors": [], "source": "Vendor-maintained GitHub Releases"}
    for slug, repo in REPOS.items():
        try:
            req = urllib.request.Request(
                f"https://api.github.com/repos/{repo}/releases?per_page=15",
                headers={"User-Agent": "CVEHarbor-Release-Collector/1.0",
                         "Accept": "application/vnd.github+json"})
            with urllib.request.urlopen(req, timeout=12) as response:
                rows = json.loads(response.read(1_000_000))
            if not isinstance(rows, list):
                raise ValueError("Unexpected GitHub releases response")
            for row in rows:
                if not isinstance(row, dict) or row.get("draft") or row.get("prerelease"):
                    continue
                version = str(row.get("tag_name") or "").lstrip("vV")[:70]
                if not re.match(r"^\d+(?:\.\d+){1,4}(?:$|[-+])", version):
                    continue
                url = str(row.get("html_url") or "")
                if not url.startswith("https://github.com/" + repo + "/releases/tag/"):
                    continue
                notes = clean(row.get("body"))
                result["releases"].append({
                    "slug": slug, "version": version, "title": clean(row.get("name") or version)[:160],
                    "published": str(row.get("published_at") or "")[:10],
                    "notes": notes, "url": url,
                    "security_mentioned": bool(re.search(r"\b(CVE-\d{4}-\d+|security fix|security update|vulnerabilit)\b",
                                                      notes, flags=re.I)),
                    "source": "Official project GitHub release"
                })
        except Exception as exc:
            result["errors"].append({"source": repo, "reason": str(exc)[:110]})
    OUT.write_text("window.CVEHARBOR_PATCH_NOTES = " +
                   json.dumps(result, ensure_ascii=False).replace("</", "<\\/") +
                   ";\n", encoding="utf-8")
    print("Vendor release notes:", len(result["releases"]), "release entries",
          len(result["errors"]), "sources unavailable")

if __name__ == "__main__":
    collect()
