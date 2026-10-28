#!/usr/bin/env python3
"""CVEHarbor hourly public advisory sync.

Public, read-only source ingestion. Does not inspect visitors, Whitecap infrastructure,
or the operator's personal email. Does not silently convert unknown exploitation
into confirmed exploitation. Data freshness and feed failures are exposed.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "advisories.json"
SCRIPT = ROOT / "data.js"
CATEGORIES = json.loads((ROOT / "data" / "demo-advisories.json").read_text(encoding="utf-8"))["categories"]
UTC = timezone.utc
NOW = datetime.now(UTC)
SOURCES = {
    "github": "https://api.github.com/advisories",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
}
MAX_RECORDS = 900
ALLOWED = {x["name"] for x in CATEGORIES}
CVERE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)


def utc_iso() -> str:
    return NOW.isoformat(timespec="seconds").replace("+00:00", "Z")


def datepart(s: str | None) -> str:
    if not s:
        return NOW.date().isoformat()
    return str(s)[:10]


def crop(s: object, limit: int = 900) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()[:limit]


def clean_url(s: object) -> str:
    t = str(s or "").strip()
    return t if t.startswith("https://") and len(t) < 900 else ""


def get_json(url: str, source: str) -> dict | list:
    headers = {"Accept": "application/json", "User-Agent": "CVEHarbor-PublicFeed/1.0 (https://cveharbor.com)", "Cache-Control": "no-cache"}
    if source == "github":
        headers["Accept"] = "application/vnd.github+json"
        token = os.getenv("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        headers["X-GitHub-Api-Version"] = "2022-11-28"
    if source == "nvd" and os.getenv("NVD_API_KEY"):
        headers["apiKey"] = os.environ["NVD_API_KEY"]
    last = None
    for i in range(3):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=22) as resp:
                raw = resp.read(12_000_000)
                return json.loads(raw)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError) as exc:
            last = exc
            if i < 2:
                time.sleep(2 + i * 3)
    raise RuntimeError(f"{source} endpoint failed: {type(last).__name__}: {str(last)[:170]}")


def classify(*, product: str = "", ecosystem: str = "", text: str = "", cpes: list[str] | None = None) -> list[str]:
    """Conservative taxonomy match: first-party product strings and package ecosystem.

    Summary text is only used for unambiguous named products. Generic terms such
    as 'window', 'node' and 'cloud' are deliberately avoided.
    """
    p = " ".join([product, " ".join(cpes or [])]).lower()
    all_ = (p + " " + text[:220]).lower()
    tags: list[str] = []

    def add(k: str, ok: bool):
        if ok and k in ALLOWED and k not in tags:
            tags.append(k)

    def has(r: str) -> bool:
        return bool(re.search(r, all_, re.I))

    def hp(r: str) -> bool:
        return bool(re.search(r, p, re.I))

    eco = ecosystem.lower()
    add(".NET / ASP.NET", eco == "nuget" or has(r"\b(?:asp\.net|\.net framework|dotnet|blazor|entity framework|nuget|microsoft\.aspnetcore)\b"))
    add("WordPress / Plugins", has(r"\b(?:wordpress|woocommerce|wp[-_ ]?(?:plugin|core))\b") or hp(r"\bwp[-_][a-z0-9_-]+"))
    add("PHP", eco == "composer" or has(r"\b(?:php|laravel|symfony|composer|php-fpm)\b"))
    add("Python / PyPI", eco == "pip" or has(r"\b(?:python|pypi|django|flask|fastapi)\b"))
    add("Node.js / npm", eco == "npm" or has(r"\b(?:node\.js|nodejs|npm|express\.js|next\.js|react(?:\.js)?|angular|vue(?:\.js)?)\b"))
    add("Azure", has(r"\b(?:microsoft azure|azure (?:app|cloud|sql|devops|functions|kubernetes|aks|storage|identity)|azure_?devops)\b"))
    add("Microsoft 365", has(r"\b(?:microsoft 365|office 365|exchange (?:server|online)|entra id|sharepoint|teams (?:client|server)|power automate|power apps|dynamics 365|microsoft fabric)\b"))
    add("SQL Server", has(r"\b(?:sql server|mssql|sqlserver|azure sql)\b"))
    add("MySQL / MariaDB", has(r"\b(?:mysql|mariadb|percona)\b"))
    add("Drupal / CMS", has(r"\b(?:drupal|dotnetnuke|dnn cms|sitefinity|kentico|xperience cms|umbraco)\b"))
    add("Fortinet", has(r"\b(?:fortinet|fortigate|fortios|fortisiem|fortimanager|fortianalyzer)\b"))
    add("Windows", has(r"\b(?:microsoft windows|windows(?: server| kernel| operating system| 10| 11| 8(?:\.1)?| 7| nt| xp)?|win32)\b"))
    add("Linux", has(r"\b(?:linux(?: kernel| server| distribution)?|ubuntu|debian|centos|red hat enterprise linux|rhel|almalinux|rocky linux|fedora|systemd)\b"))
    add("Docker / Kubernetes", has(r"\b(?:docker|kubernetes|containerd|runc|kubelet|kube-apiserver|k8s|helm chart)\b"))
    add("VMware", has(r"\b(?:vmware|vcenter|vsphere|esxi|broadcom virtualization)\b"))
    add("Application dependencies", eco in {"pip", "npm", "nuget", "composer"} or has(r"\b(?:dependency|dependencies|supply chain|package manager|npm package|python package|nuget package|composer package)\b"))
    return tags


def migrate_legacy_categories(record: dict) -> dict:
    """Replace historic combined Windows / Linux tags with accurate platform labels.

    Stored advisories from older hourly runs may have the retired category.
    Reclassify them using product and description evidence. Never assume that
    a Linux issue affects Windows or vice versa.
    """
    old = list(record.get("categories") or [])
    if "Windows / Linux" not in old:
        return record
    updated = dict(record)
    labels = [c for c in old if c != "Windows / Linux"]
    hints = classify(
        product=f"{record.get('title') or ''} {record.get('affected') or ''}",
        text=str(record.get("summary") or ""),
    )
    for label in ("Windows", "Linux"):
        if label in hints and label not in labels:
            labels.append(label)
    updated["categories"] = labels
    return updated


def ghsa_items() -> list[dict]:
    output = []
    for advisory_type in ("reviewed", "malware"):
        for page in (1, 2):
            # GitHub global advisories list can be read without private account data.
            params = urllib.parse.urlencode({"type": advisory_type, "sort": "updated", "direction": "desc", "per_page": 100, "page": page})
            batch = get_json(SOURCES["github"] + "?" + params, "github")
            if not isinstance(batch, list):
                raise ValueError("GitHub returned an unexpected structure")
            output += batch
            if len(batch) < 100:
                break
    return output


def from_ghsa(item: dict) -> dict | None:
    ghsa = str(item.get("ghsa_id") or "")
    cve = str(item.get("cve_id") or "")
    if not GHSA.match(ghsa):
        return None
    if item.get("withdrawn_at") or item.get("state") == "withdrawn":
        return None
    vulnerabilities = item.get("vulnerabilities") or []
    cats = []
    affected = []
    fixes = []
    for x in vulnerabilities:
        pkg = x.get("package") or {}
        name, eco = str(pkg.get("name") or ""), str(pkg.get("ecosystem") or "")
        for tag in classify(product=name, ecosystem=eco, text=item.get("summary") or ""):
            if tag not in cats:
                cats.append(tag)
        rng = crop(x.get("vulnerable_version_range"), 130)
        fixed = (x.get("first_patched_version") or {}).get("identifier")
        if name:
            affected.append(f"{eco}: {name}" + (f" ({rng})" if rng else ""))
            if fixed:
                fixes.append(f"{name}: {fixed}")
    if not cats:
        cats = classify(product=item.get("summary") or "", text=item.get("description") or "")
    if not cats:
        return None
    base_sev = str(item.get("severity") or "unknown").lower()
    sev = base_sev if base_sev in {"critical", "high", "medium", "low"} else "bulletin"
    if item.get("type") == "malware":
        sev = "bulletin"
    if sev not in {"critical", "high", "medium", "bulletin"}:
        return None
    cvss = (item.get("cvss") or {}).get("score")
    sources = [{"label": "GitHub reviewed advisory", "url": f"https://github.com/advisories/{ghsa}"}]
    for ref in item.get("references") or []:
        url = clean_url(ref.get("url") if isinstance(ref, dict) else ref)
        if url and all(url != s["url"] for s in sources) and len(sources) < 4:
            sources.append({"label": "Additional advisory", "url": url})
    fid = cve if CVERE.match(cve) else ghsa
    return {
        "id": fid, "title": crop(item.get("summary") or ghsa, 175), "severity": sev,
        "categories": cats, "published": datepart(item.get("published_at")), "updated": datepart(item.get("updated_at")),
        "summary": crop(item.get("description") or item.get("summary"), 1300),
        "affected": crop("; ".join(affected), 1400) or "Affected product/version range is not stated in the structured record. Check vendor advisory.",
        "remediation": crop("; ".join(fixes), 1000) or "No fixed version was listed in this feed. Review the linked vendor advisory.",
        "action": "Match the affected package and version to your deployment before prioritizing remediation.",
        "sources": sources,
        "exploitation": "Malicious software distribution advisory; investigate exposure" if item.get("type") == "malware" else "Not confirmed by this source; check CISA KEV",
        "kind": "cve" if CVERE.match(fid) else "advisory",
        "cvss": str(cvss) if isinstance(cvss, (int, float)) else None,
        "status": "GitHub reviewed advisory" if item.get("type") != "malware" else "GitHub malware advisory",
        "first_seen_at": utc_iso(), "source_updated_at": item.get("updated_at") or "",
        "source_type": "github", "known_exploited": False,
    }


def cpe_text(vuln: dict) -> list[str]:
    result = []
    def walk(node: object):
        if isinstance(node, dict):
            if "criteria" in node:
                parts = str(node["criteria"]).split(":")
                if len(parts) >= 5:
                    result.append(f"{parts[3]} {parts[4]}")
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for x in node:
                walk(x)
    walk(vuln.get("configurations") or [])
    return list(dict.fromkeys(result))[:40]


def nvd_items() -> list[dict]:
    start = NOW - timedelta(hours=60)
    fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    collected = []
    index = 0
    for _ in range(4):
        params = urllib.parse.urlencode({"lastModStartDate": fmt(start), "lastModEndDate": fmt(NOW), "startIndex": index, "resultsPerPage": 1000})
        data = get_json(SOURCES["nvd"] + "?" + params, "nvd")
        batch = data.get("vulnerabilities") or []
        collected += batch
        index += len(batch)
        if index >= int(data.get("totalResults", 0)) or not batch:
            break
        time.sleep(1)
    return collected


def from_nvd(v: dict) -> dict | None:
    cve = v.get("cve") or {}
    fid = str(cve.get("id") or "")
    if not CVERE.match(fid) or cve.get("vulnStatus") == "Rejected":
        return None
    desc = next((x["value"] for x in cve.get("descriptions") or [] if x.get("lang") == "en"), "")
    cpes = cpe_text(cve)
    cats = classify(product=" ".join(cpes), text=desc, cpes=cpes)
    if not cats:
        return None
    metrics = cve.get("metrics") or {}
    score = None
    for metric_type in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(metric_type) or []
        if entries:
            primary = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            score = (primary.get("cvssData") or {}).get("baseScore")
            if score is not None:
                break
    if not isinstance(score, (int, float)):
        sev = "bulletin"
    elif score >= 9.0:
        sev = "critical"
    elif score >= 7.0:
        sev = "high"
    elif score >= 4.0:
        sev = "medium"
    else:
        return None
    references = [{"label": "NVD CVE record", "url": f"https://nvd.nist.gov/vuln/detail/{fid}"}]
    primary = [x for x in cve.get("references") or [] if "Vendor Advisory" in (x.get("tags") or [])]
    for x in primary[:3]:
        url = clean_url(x.get("url"))
        if url and all(url != s["url"] for s in references):
            references.append({"label": "Vendor advisory", "url": url})
    return {
        "id": fid, "title": crop(desc.split(". ")[0] or fid, 175), "severity": sev, "categories": cats,
        "published": datepart(cve.get("published")), "updated": datepart(cve.get("lastModified")),
        "summary": crop(desc, 1250),
        "affected": "Products identified in NVD configurations: " + crop("; ".join(cpes[:12]), 700) if cpes else "Confirm affected versions from the vendor advisory and NVD CPE configurations.",
        "remediation": "Review the linked vendor bulletin for patched versions and mitigations. This feed does not infer a fixed version.",
        "action": "Verify applicability against the installed product and version, then follow vendor remediation instructions.",
        "sources": references, "exploitation": "Not confirmed by this source; check CISA KEV",
        "kind": "cve", "cvss": str(score) if isinstance(score,(int,float)) else None,
        "status": "NVD indexed CVE", "first_seen_at": utc_iso(),
        "source_updated_at": cve.get("lastModified") or "", "source_type": "nvd", "known_exploited": False,
    }


def kev_items() -> list[dict]:
    data = get_json(SOURCES["cisa_kev"], "cisa_kev")
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ValueError("CISA KEV response missing vulnerabilities")
    return data["vulnerabilities"]


def from_kev(x: dict) -> dict | None:
    fid = str(x.get("cveID") or "")
    if not CVERE.match(fid):
        return None
    p = f"{x.get('vendorProject') or ''} {x.get('product') or ''}"
    cats = classify(product=p, text=str(x.get("vulnerabilityName") or ""))
    if not cats:
        return None
    return {
        "id":fid, "title":crop(x.get("vulnerabilityName"),175), "severity":"bulletin", "categories":cats,
        "published":datepart(x.get("dateAdded")), "updated":datepart(x.get("dateAdded")),
        "summary":crop(x.get("shortDescription"),1200),
        "affected":crop(p,650) + ". Consult vendor advisory for affected versions.",
        "remediation":crop(x.get("requiredAction"),700) or "Follow vendor remediation and CISA guidance.",
        "action":"Known exploited in the wild. Confirm affected installations and prioritize vendor mitigations.",
        "sources":[{"label":"CISA Known Exploited Vulnerabilities", "url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
        "exploitation":"Confirmed: listed in CISA KEV", "kind":"cve", "cvss":None,
        "status":"CISA KEV listed", "first_seen_at":utc_iso(),
        "source_updated_at":datepart(x.get("dateAdded")), "source_type":"cisa_kev", "known_exploited":True,
    }


def merge_record(old: dict, new: dict) -> dict:
    """Merge source observations without discarding first seen time or KEV flags."""
    if not old:
        return new
    # GitHub generally provides better fixed package versions. Do not replace
    # an actionable package detail with NVD's generic patch instructions.
    rank = {"github": 3, "nvd": 2, "cisa_kev": 1}
    chosen = new if rank.get(new.get("source_type"), 0) >= rank.get(old.get("source_type"), 0) else old
    merged = dict(chosen)
    merged["categories"] = sorted(set(old.get("categories") or []) | set(new.get("categories") or []))
    unique = {}
    for src in (old.get("sources") or []) + (new.get("sources") or []):
        u = clean_url(src.get("url"))
        if u:
            unique[u] = {"label": crop(src.get("label"), 80), "url": u}
    merged["sources"] = list(unique.values())[:5]
    merged["first_seen_at"] = old.get("first_seen_at") or new.get("first_seen_at") or utc_iso()
    merged["known_exploited"] = bool(old.get("known_exploited")) or bool(new.get("known_exploited"))
    if merged["known_exploited"]:
        merged["exploitation"] = "Confirmed: listed in CISA KEV"
    if old.get("cvss") and not merged.get("cvss"):
        merged["cvss"] = old["cvss"]
    merged["updated"] = max(old.get("updated") or "", new.get("updated") or "")
    return merged


def run() -> int:
    prev = json.loads(DATA.read_text(encoding="utf-8")) if DATA.exists() else {}
    previous = {}
    for item in prev.get("advisories") or []:
        if not item.get("id"):
            continue
        migrated = migrate_legacy_categories(item)
        if migrated.get("categories"):
            previous[migrated["id"]] = migrated
    merged = dict(previous)
    sources = dict(prev.get("sources") or {})
    operations = (("github", ghsa_items, from_ghsa), ("nvd", nvd_items, from_nvd), ("cisa_kev", kev_items, from_kev))
    good = 0
    for name, fetch, transform in operations:
        try:
            batch = fetch()
            converted = 0
            for item in batch:
                record = transform(item)
                if not record or not record.get("categories"):
                    continue
                rid = record["id"]
                merged[rid] = merge_record(merged.get(rid), record)
                converted += 1
            sources[name] = {"ok": True, "last_success": utc_iso(), "last_attempt": utc_iso(), "items_processed": converted, "url": SOURCES[name]}
            good += 1
            print(f"{name}: {len(batch)} fetched, {converted} categorized", flush=True)
        except Exception as e:
            old = sources.get(name, {})
            sources[name] = {**old, "ok": False, "last_attempt": utc_iso(), "error": crop(e, 200), "url": SOURCES[name]}
            print(f"WARNING: {name}: {e}", file=sys.stderr, flush=True)
    if not good:
        # A failed sync must not publish a new green successful timestamp.
        # Still exit non-zero so operator receives a workflow failure signal.
        fail = {"siteName":"CVEHarbor", "snapshotDate": datepart(prev.get("snapshotDate")), "mode":"degraded", "categories":CATEGORIES,
                "advisories": list(previous.values()), "sources":sources,
                "last_checked_at": utc_iso(), "last_successful_update": prev.get("last_successful_update")}
        publish(fail)
        return 1
    # Preserve the newest disclosures while reserving space for CISA KEV entries.
    # Do not let thousands of old KEV entries crowd out today's newly updated CVEs.
    recent = sorted(merged.values(), key=lambda x:(x.get("source_updated_at") or x.get("updated") or "", x.get("published") or ""), reverse=True)
    chosen = {r["id"]: r for r in recent[:700]}
    exploited = [r for r in recent if r.get("known_exploited")]
    for r in exploited[:200]:
        chosen.setdefault(r["id"], r)
    for r in recent:
        if len(chosen) >= MAX_RECORDS:
            break
        chosen.setdefault(r["id"], r)
    records = sorted(chosen.values(), key=lambda x:(x.get("updated") or "", x.get("published") or ""), reverse=True)
    result = {"siteName":"CVEHarbor", "snapshotDate": NOW.date().isoformat(),
              "mode":"live" if good == len(operations) else "partial", "categories":CATEGORIES, "advisories":records,
              "sources":sources, "last_checked_at":utc_iso(), "last_successful_update":utc_iso(),
              "note":"Public advisory intelligence only. Actual vulnerability exposure requires asset/version validation."}
    publish(result)
    print(f"Published {len(records)} records across {good}/{len(operations)} sources")
    return 0


def publish(data: dict):
    DATA.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, ensure_ascii=False, indent=2)
    DATA.write_text(text + "\n", encoding="utf-8")
    # Escape closing script markup for safe embedding even if vendor text is hostile.
    embed = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    SCRIPT.write_text("/* Automatically generated. Do not edit directly. */\nwindow.CVEHARBOR_DATA = " + embed + ";\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(run())
