#!/usr/bin/env python3
"""CVEHarbor hourly public advisory sync.

Public, read-only source ingestion. Does not inspect visitors, Whitecap infrastructure,
or the operator's personal email. Does not silently convert unknown exploitation
into confirmed exploitation. Data freshness and feed failures are exposed.
"""
from __future__ import annotations

import json
import csv
import io
import os
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
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
VENDOR_BASELINE = ROOT / "data" / "vendor-baseline.json"
CATEGORIES = json.loads((ROOT / "data" / "demo-advisories.json").read_text(encoding="utf-8"))["categories"]
UTC = timezone.utc
NOW = datetime.now(UTC)
SOURCES = {
    "github": "https://api.github.com/advisories",
    "php_upstream": "https://api.github.com/repos/php/php-src/security-advisories",
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "msrc_rss": "https://api.msrc.microsoft.com/update-guide/rss",
    "fortinet_rss": "https://filestore.fortinet.com/fortiguard/rss/ir.xml",
    "ubuntu_rss": "https://ubuntu.com/security/notices/rss.xml",
    "osv_recent": "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv",
    "wordfence": "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production",
}
MAX_RECORDS = 2500
HEALTH = ROOT / "data" / "feed-health.json"
ALLOWED = {x["name"] for x in CATEGORIES}
CVERE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$", re.I)


def utc_iso() -> str:
    return NOW.isoformat(timespec="seconds").replace("+00:00", "Z")


def datepart(s: str | None) -> str:
    """Only source-provided valid dates count as publication or update dates."""
    if not s:
        return ""
    candidate = str(s)[:10]
    try:
        parsed = datetime.strptime(candidate, "%Y-%m-%d")
        return candidate if parsed.strftime("%Y-%m-%d") == candidate else ""
    except ValueError:
        return ""


def crop(s: object, limit: int = 900) -> str:
    return re.sub(r"\s+", " ", str(s or "")).strip()[:limit]


def clean_url(s: object) -> str:
    t = str(s or "").strip()
    return t if t.startswith("https://") and len(t) < 900 else ""


def get_json(url: str, source: str) -> dict | list:
    headers = {"Accept": "application/json", "User-Agent": "CVEHarbor-PublicFeed/1.0 (https://cveharbor.com)", "Cache-Control": "no-cache"}
    if source in {"github", "php_upstream"}:
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
    modern_dotnet = has(r"(?:\.net core|dotnet[ ._-]?core|asp\.net[\s._-]*core|aspnetcore|microsoft\.aspnetcore|coreclr|netcoreapp|\.net (?:[5-9]|1[0-9])(?:\.[0-9]+)?\b|dotnet[- ]?(?:[5-9]|1[0-9])(?:\.[0-9]+)?\b)")
    legacy_dotnet = has(r"(?:\.net framework|asp\.net(?![\s._-]*core)|aspnet(?!core)|system\.web|web forms|winforms|entity framework 6|netfx)")
    generic_dotnet = eco == "nuget" or has(r"(?:\bdotnet\b|\.net\b|entity framework|blazor|nuget)")
    add(".NET / ASP.NET", legacy_dotnet or generic_dotnet or modern_dotnet)
    add(".NET Core", modern_dotnet)
    add("WordPress / Plugins", has(r"\b(?:wordpress|woocommerce|wp[-_ ]?(?:plugin|core))\b") or hp(r"\bwp[-_][a-z0-9_-]+"))
    add("PHP", eco == "composer" or has(r"\b(?:php|laravel|symfony|composer|php-fpm)\b"))
    add("Python / PyPI", eco == "pip" or has(r"\b(?:python|pypi|django|flask|fastapi)\b"))
    add("Node.js / npm", eco == "npm" or has(r"\b(?:node\.js|nodejs|npm|express\.js|next\.js|react(?:\.js)?|angular|vue(?:\.js)?)\b"))
    add("Azure", has(r"\b(?:microsoft azure|azure (?:app|cloud|sql|devops|functions|kubernetes|aks|storage|identity)|azure_?devops)\b"))
    add("Microsoft 365", has(r"\b(?:microsoft 365|office 365|exchange (?:server|online)|entra id|sharepoint|teams (?:client|server)|power automate|power apps|dynamics 365|microsoft fabric)\b"))
    add("SQL Server", has(r"\b(?:sql server|mssql|sqlserver|azure sql)\b"))
    add("MySQL / MariaDB", has(r"\b(?:mysql|mariadb|percona)\b"))
    add("Drupal / CMS", has(r"\b(?:drupal|dotnetnuke|dnn cms|kentico|xperience cms|umbraco)\b"))
    add("Progress Telerik", has(r"(?:progress[ _-]*telerik|telerik[ _.-]*(?:ui|web|reporting|controls|asp|kendo)|telerik\.web\.ui|radasyncupload|radpersistence(?:manager)?|raddocklayout|radimageeditor|radfileexplorer|radeditor)"))
    add("Sitefinity", has(r"(?:sitefinity|sitefinity[_-]nextjs[_-]sdk|@progress/sitefinity)"))
    add("Veeam Backup & Replication", has(r"(?:veeam[ _-]*(?:backup[ &+_\-]*replication|b[&_ ]r|agent for linux|backup server)|veeam_backup_&_replication|veeam_backup_and_replication|veeam[ _-]*vbr)"))
    add("Sophos Firewall", has(r"(?:sophos[ _-]*(?:firewall|sfos|xg\b|xgs\b)|sophos_firewall|sophos_xg_firewall|sophos_xgs_firewall)"))
    add("Exchange SE", has(r"(?:exchange[ _-]*server[ _-]*(?:subscription[ _-]*edition|se\b)|exchange[ _-]*se\b|exchange_server_subscription_edition)"))
    add("Windows 11 OS", has(r"\b(?:microsoft[ _-]*)?windows[ _-]*11(?:\b|[_-])"))
    # Product-specific matches stay conservative. Public web marketing does
    # not prove that any particular release is deployed by Whitecap.
    add("Angular", p.strip() == "angular" or (eco == "npm" and hp(r"(?:^@angular/|^angular$|^angularjs$)")) or hp(r"(?:\bangular (?:framework|core|ssr|http client)\b|angularjs)"))
    add("React / Next.js", hp(r"(?:\breact[-_](?:server[-_])?dom\b|^react$|next(?:\.js)?|nextjs|react server components|react[-_]native(?:[-_]|$))"))
    add("JavaScript / TypeScript", hp(r"(?:\btypescript\b|\bjavascript\b|\bdeno\b|\bvite\b|\bwebpack\b)"))
    add("jQuery / Bootstrap", hp(r"(?:\bjquery\b|\bbootstrap\b|^@popperjs/core$)"))
    add("Kendo UI", hp(r"(?:\bkendo(?:react|[_ .-]?ui)?\b|@progress/kendo)"))
    add("SharePoint / SharePoint Server", has(r"(?:\bsharepoint\b|sharepoint_server|sharepoint online|sharepoint workflow manager)"))
    add("Microsoft Power Platform", has(r"(?:\bpower platform\b|\bpower apps\b|\bpower automate\b|\bpower pages\b|\bmicrosoft dataverse\b|microsoft[_ .-]?powerplatform)"))
    add("Dynamics 365", has(r"(?:\bdynamics 365\b|microsoft dynamics|dynamics[_ .-]?crm)"))
    add("Microsoft Fabric / Power BI", has(r"(?:microsoft fabric|\bpower bi\b|powerbi\b|microsoft[_ .-]?fabric)"))
    add("Azure AI / AI SDK", has(r"(?:azure openai|azure ai(?: services| foundry| search| sdk)?|azure cognitive services|azure-ai-|semantic kernel|\bcopilot studio\b|microsoft ai builder)"))
    add("NoSQL / MongoDB", hp(r"(?:\bmongodb\b|mongo[_-]?db|^mongoose$|\bcouchdb\b|\bnosql\b|\bcosmos db\b|\bredis\b)"))
    add("AWS", hp(r"(?:amazon web services|\baws(?:[-_ ](?:sdk|lambda|cli|cloud|ec2|s3))?\b|\bamazon (?:ec2|s3|cloudfront|lambda)\b)"))
    add("iOS / Android", hp(r"(?:\bios\b|\bandroid\b|\bswiftui\b|\breact.native\b|\bflutter\b|\bxamarin\b|\bnet maui\b)"))
    add("Fortinet", has(r"\b(?:fortinet|fortigate|fortios|fortisiem|fortimanager|fortianalyzer)\b"))
    server_windows = has(r"\b(?:windows[\s_-]+server(?:[\s_-]+(?:[0-9]{4}|[0-9]+))?|windows_server(?:_[0-9]+)?|hyper[\s_-]?v server)\b")
    generic_windows = has(r"\b(?:microsoft[ _-]+windows(?![\s_-]+(?:server|11))|windows(?![\s_-]+(?:server|11))|win32)\b")
    add("Windows Server OS", server_windows)
    add("Windows", generic_windows)
    add("Linux", has(r"\b(?:linux(?: kernel| server| distribution)?|ubuntu|debian|centos|red hat enterprise linux|rhel|almalinux|rocky linux|fedora|systemd)\b"))
    add("HyperV", has(r"\b(?:hyper[\s_-]?v|hyperv|hypervisor(?:\s+platform)?|vmms\.exe|vmwp\.exe)\b"))
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


def recategorize_existing(record: dict) -> dict:
    """Map historical records to dedicated products without inventing affected products.

    Existing NVD records were classified before these categories existed. Match
    only explicitly identified products in title, affected versions and summary.
    """
    entry = dict(record)
    old_categories = list(entry.get("categories") or [])
    evidence = " ".join([str(entry.get(k) or "") for k in ("title", "affected", "summary")])
    hints = classify(product=evidence, text=evidence)
    categories = list(dict.fromkeys(old_categories + hints))
    if "Windows 11 OS" in hints:
        categories = [c for c in categories if c != "Windows"]
    if "Windows Server OS" in hints and "Windows" not in hints:
        categories = [c for c in categories if c != "Windows"]
    if "Sitefinity" in hints and not re.search(r"\b(?:drupal|dotnetnuke|kentico|umbraco)\b", evidence, re.I):
        categories = [c for c in categories if c != "Drupal / CMS"]
    entry["categories"] = [c for c in categories if c in ALLOWED]
    return entry


def vendor_baseline_items() -> list[dict]:
    """Older official advisories that seed new product sections, not fresh discoveries."""
    if not VENDOR_BASELINE.exists():
        return []
    data = json.loads(VENDOR_BASELINE.read_text(encoding="utf-8"))
    result = []
    for entry in data.get("advisories") or []:
        fid = str(entry.get("id") or "")
        cats = entry.get("categories") or []
        if not (CVERE.match(fid) or GHSA.match(fid)) or not cats or any(c not in ALLOWED for c in cats):
            raise ValueError(f"Invalid vendor baseline advisory {fid}")
        sources = [source for source in entry.get("sources") or []
                   if clean_url(source.get("url"))]
        if not sources:
            raise ValueError(f"Missing official reference for {fid}")
        record = dict(entry)
        record.update({
            "kind": "cve" if CVERE.match(fid) else "advisory",
            "source_type": "vendor_baseline",
            "source_updated_at": entry.get("updated") or entry.get("published") or "",
            "status": "Vendor-sourced historical baseline; not newly disclosed",
            "first_seen_at": utc_iso(),
            "known_exploited": bool(entry.get("known_exploited", False)),
            "action": "Verify the affected version and exposure, then follow the vendor remediation.",
            "sources": sources,
        })
        result.append(record)
    return result


def ghsa_items() -> list[dict]:
    """Retrieve recently published AND recently revised GitHub advisories.

    Sorting exclusively by updated date can bury disclosures in batches of
    historical records that received routine metadata changes.
    """
    output = {}
    for advisory_type in ("reviewed", "malware"):
        for order in ("published", "updated"):
            for page in (1, 2):
                params = urllib.parse.urlencode({
                    "type": advisory_type, "sort": order, "direction": "desc",
                    "per_page": 100, "page": page
                })
                batch = get_json(SOURCES["github"] + "?" + params, "github")
                if not isinstance(batch, list):
                    raise ValueError("GitHub returned an unexpected structure")
                for item in batch:
                    if isinstance(item, dict) and item.get("ghsa_id"):
                        output[item["ghsa_id"]] = item
                if len(batch) < 100:
                    break
    if not output:
        raise RuntimeError("GitHub advisory feed returned no published records")
    return list(output.values())

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
        if not isinstance(x, dict):
            continue
        pkg = x.get("package") or {}
        if not isinstance(pkg, dict):
            pkg = {"name": str(pkg)}
        name, eco = str(pkg.get("name") or ""), str(pkg.get("ecosystem") or "")
        for tag in classify(product=name, ecosystem=eco, text=item.get("summary") or ""):
            if tag not in cats:
                cats.append(tag)
        rng = crop(x.get("vulnerable_version_range"), 130)
        # REST global advisories return first_patched_version as a string.
        # Some other GitHub schemas represent it as an object with identifier.
        version = x.get("first_patched_version")
        fixed = version.get("identifier") if isinstance(version, dict) else version
        if name:
            affected.append(f"{eco}: {name}" + (f" ({rng})" if rng else ""))
            if fixed:
                fixes.append(f"{name}: {crop(fixed, 120)}")
    if not cats:
        cats = classify(product=item.get("summary") or "", text=item.get("description") or "")
    if not cats:
        return None
    base_sev = str(item.get("severity") or "unknown").lower()
    sev = base_sev if base_sev in {"critical", "high", "medium", "low"} else "bulletin"
    if item.get("type") == "malware":
        sev = "bulletin"
    if sev not in {"critical", "high", "medium", "low", "bulletin"}:
        return None
    cvss_obj = item.get("cvss") or {}
    cvss = cvss_obj.get("score") if isinstance(cvss_obj, dict) else None
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


def php_upstream_items() -> list[dict]:
    """Fetch PHP project's published repository advisories directly.

    GitHub's repository security advisory API is publicly readable for
    published advisories. This is separate from the global GHSA ranking feed.
    """
    output = {}
    for sort_by in ("published", "updated"):
        query = urllib.parse.urlencode({
            "state": "published", "sort": sort_by,
            "direction": "desc", "per_page": 100
        })
        batch = get_json(SOURCES["php_upstream"]+"?"+query, "php_upstream")
        if not isinstance(batch, list):
            raise ValueError("PHP upstream security advisory response was not an array")
        for item in batch:
            if isinstance(item, dict) and item.get("ghsa_id"):
                output[item["ghsa_id"]] = item
    if not output:
        raise RuntimeError("PHP upstream feed returned no published advisories")
    return list(output.values())


def from_php_upstream(item: dict) -> dict | None:
    if not isinstance(item, dict):
        return None
    parsed = dict(item)
    # Force the first party PHP classification even when an upstream advisory
    # title is generic (for example, 'RCE via stale global state').
    parsed["summary"] = "PHP runtime: " + str(item.get("summary") or "")
    record = from_ghsa(parsed)
    if not record:
        return None
    record["title"] = crop(item.get("summary") or record["title"], 175)
    # The upstream advisory belongs to the PHP interpreter, including
    # extensions, even when the GHSA summary omits the word 'PHP'.
    record["categories"] = list(dict.fromkeys(["PHP", *record["categories"]]))
    record["status"] = "Published security advisory from PHP upstream"
    record["source_type"] = "php_upstream"
    record["sources"] = [{
        "label":"PHP upstream security advisory",
        "url":"https://github.com/php/php-src/security/advisories/" + str(item["ghsa_id"])
    }, *record.get("sources", [])][:5]
    # Never treat a missing original publication date as a disclosure today.
    if not item.get("published_at"):
        record["published"] = ""
    return record


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
    """Sample new publications explicitly, plus recently modified records.

    A last-modified search alone can be dominated by months-old CVEs, hiding
    truly new disclosures behind pagination.
    """
    fmt = lambda dt: dt.strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    collected = {}
    queries = (
        # Prioritize actual new publications for the main dashboard.
        ("pubStartDate", "pubEndDate", NOW - timedelta(hours=48), 2),
        # Also refresh changed CVSS, references, patches, and exploitation.
        ("lastModStartDate", "lastModEndDate", NOW - timedelta(hours=12), 3),
    )
    for start_name, end_name, start_time, max_pages in queries:
        index = 0
        for _ in range(max_pages):
            params = urllib.parse.urlencode({
                start_name: fmt(start_time), end_name: fmt(NOW),
                "startIndex": index, "resultsPerPage": 1000
            })
            data = get_json(SOURCES["nvd"] + "?" + params, "nvd")
            batch = data.get("vulnerabilities") or []
            for item in batch:
                cve_id = (item.get("cve") or {}).get("id")
                if cve_id:
                    collected[cve_id] = item
            index += len(batch)
            if index >= int(data.get("totalResults", 0)) or not batch:
                break
            # Unauthenticated NVD API requests have strict rate limits.
            time.sleep(7 if not os.getenv("NVD_API_KEY") else 1)
        if index < int(data.get("totalResults", 0)):
            raise RuntimeError(f"NVD {start_name} pagination incomplete: {index} of {data.get('totalResults')} returned")
        # Avoid burst limits when moving between NVD query windows.
        if not os.getenv("NVD_API_KEY"):
            time.sleep(6)
    if not collected:
        raise RuntimeError("NVD returned no CVEs for its publication and modification windows")
    return list(collected.values())

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
        sev = "low"
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
    if len(data["vulnerabilities"]) < 100:
        raise RuntimeError("CISA KEV returned an unexpectedly small catalog")
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
        # CISA dateAdded is not the original CVE disclosure date.
        "published":"", "updated":datepart(x.get("dateAdded")),
        "summary":crop(x.get("shortDescription"),1200),
        "affected":crop(p,650) + ". Consult vendor advisory for affected versions.",
        "remediation":crop(x.get("requiredAction"),700) or "Follow vendor remediation and CISA guidance.",
        "action":"Known exploited in the wild. Confirm affected installations and prioritize vendor mitigations.",
        "sources":[{"label":"CISA Known Exploited Vulnerabilities", "url":"https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}],
        "exploitation":"Confirmed: listed in CISA KEV", "kind":"cve", "cvss":None,
        "status":"CISA KEV listed", "first_seen_at":utc_iso(),
        "source_updated_at":datepart(x.get("dateAdded")), "source_type":"cisa_kev", "known_exploited":True,
    }



def get_text(url: str, source: str, limit: int = 6_000_000) -> str:
    """Bounded download, with retries and explicit failure status."""
    last = None
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent":"CVEHarbor-PublicFeed/1.0 (https://cveharbor.com)",
                "Accept":"application/rss+xml, application/atom+xml, text/csv, application/json, */*",
            })
            with urllib.request.urlopen(req, timeout=25) as resp:
                raw = resp.read(limit + 1)
                if len(raw) > limit:
                    raise ValueError("Feed response exceeds the configured byte limit")
                return raw.decode("utf-8-sig")
        except (urllib.error.URLError, TimeoutError, UnicodeError, ValueError) as exc:
            last = exc
            if attempt < 2:
                time.sleep(2 + attempt * 2)
    raise RuntimeError(f"{source}: {type(last).__name__}: {crop(last, 180)}")


def from_vendor_rss(entry: dict) -> dict | None:
    """Only ingest vendor RSS entries with explicitly identified CVE IDs.

    Non-CVE news, generic release notices, and undated entries are ignored.
    """
    vendor = entry.get("vendor") or ""
    title = crop(entry.get("title"), 175)
    description = crop(entry.get("summary"), 1200)
    published = datepart(entry.get("published"))
    url = clean_url(entry.get("url"))
    matches = list(dict.fromkeys(re.findall(r"\\bCVE-\\d{4}-\\d{4,}\\b", title + " " + description, re.I)))
    if not matches or not url or not published:
        return None
    fid = matches[0].upper()
    label = {"msrc_rss":"Microsoft Security Update Guide",
             "fortinet_rss":"Fortinet PSIRT", "ubuntu_rss":"Ubuntu Security Notice"}.get(vendor, "Vendor security notice")
    cats = {"msrc_rss":classify(product=title, text=description),
            "fortinet_rss":["Fortinet"],"ubuntu_rss":["Linux"]}.get(vendor, [])
    if not cats:
        return None
    return {"id":fid,"title":title or fid,"severity":"bulletin",
            "categories":cats,"published":published,"updated":published,
            "summary":description or title,
            "affected":"Confirm affected products and versions in the linked official vendor notice.",
            "remediation":"Consult the official notice for fixed versions and mitigation.",
            "action":"Check whether your installed product and version are affected.",
            "sources":[{"label":label,"url":url}],
            "exploitation":"Not confirmed by this source; check CISA KEV",
            "kind":"cve","cvss":None,"status":label+" RSS notice",
            "first_seen_at":utc_iso(),"source_updated_at":published,
            "source_type":vendor,"known_exploited":False}


def rss_vendor_items(vendor: str) -> list[dict]:
    data = get_text(SOURCES[vendor], vendor)
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"Invalid XML from {vendor}: {exc}") from exc
    records = []
    for item in root.iter():
        name = item.tag.rsplit("}",1)[-1]
        if name not in {"item","entry"}:
            continue
        fields = {}
        for child in item:
            key=child.tag.rsplit("}",1)[-1]
            value=" ".join(child.itertext()).strip()
            if key=="link" and not value:
                value=child.attrib.get("href","")
            fields.setdefault(key,value)
        date = fields.get("pubDate") or fields.get("published") or fields.get("updated") or ""
        if date and not datepart(date):
            try:
                date=parsedate_to_datetime(date).date().isoformat()
            except (TypeError, ValueError, IndexError):
                date=""
        records.append({"vendor":vendor,"title":fields.get("title"),
                        "summary":fields.get("description") or fields.get("summary") or fields.get("content"),
                        "published":date,"url":fields.get("link") or fields.get("id")})
    if not records:
        raise RuntimeError(f"{vendor} returned no RSS or Atom entries")
    return records


def osv_recent_items() -> list[dict]:
    """Incremental OSV modified-ID export, not OSV's package/version query API."""
    text_data = get_text(SOURCES["osv_recent"],"osv_recent",limit=9_000_000)
    cutoff=(NOW-timedelta(days=7))
    results=[]
    for row in csv.reader(io.StringIO(text_data)):
        if len(row)<2:
            continue
        try:
            changed=datetime.fromisoformat(row[0].strip().replace("Z","+00:00"))
        except ValueError:
            continue
        if changed.tzinfo is None:
            changed=changed.replace(tzinfo=UTC)
        if changed < cutoff:
            break
        path=row[1].strip()
        parts=path.split("/")
        if len(parts)!=2 or not re.fullmatch(r"[A-Za-z0-9_.+-]+",parts[0]):
            continue
        if not (CVERE.match(parts[1]) or GHSA.match(parts[1])):
            continue
        if len(results)>=80:
            break
        url="https://storage.googleapis.com/osv-vulnerabilities/"+urllib.parse.quote(parts[0])+"/"+urllib.parse.quote(parts[1])+".json"
        try:
            item=get_json(url,"osv_recent")
            if isinstance(item,dict) and item.get("id"):
                results.append(item)
        except Exception as exc:
            print(f"WARNING: OSV record {parts[1]} failed: {exc}",file=sys.stderr,flush=True)
    return results


def from_osv(item: dict) -> dict | None:
    aliases=[item.get("id"),*(item.get("aliases") or [])]
    fid=next((x for x in aliases if isinstance(x,str) and CVERE.fullmatch(x)),None)
    if not fid:
        fid=next((x for x in aliases if isinstance(x,str) and GHSA.fullmatch(x)),None)
    if not fid or item.get("withdrawn"):
        return None
    packages=[];ecosystems=[];fixes=[]
    for affected in item.get("affected") or []:
        pkg=affected.get("package") or {}
        if pkg.get("name"):
            packages.append(str(pkg["name"]))
        if pkg.get("ecosystem"):
            ecosystems.append(str(pkg["ecosystem"]))
        for rng in affected.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixes.append(str(ev["fixed"]))
    cats=[]
    for name in packages:
        for eco in ecosystems:
            for label in classify(product=name,ecosystem=eco,text=item.get("summary") or ""):
                if label not in cats:cats.append(label)
    if not cats:
        return None
    refs=[{"label":"OSV advisory","url":"https://osv.dev/vulnerability/"+urllib.parse.quote(str(item["id"]))}]
    summary=crop(item.get("summary") or item.get("details") or fid,1100)
    return {"id":fid,"title":crop(item.get("summary") or fid,175),
            "severity":"bulletin","categories":cats,
            "published":datepart(item.get("published")),"updated":datepart(item.get("modified")),
            "summary":summary,"affected":crop(", ".join(packages),600) or "See OSV record",
            "remediation":("Fixed versions reported: "+crop(", ".join(sorted(set(fixes))),450)) if fixes else "Review linked OSV advisory for fixes.",
            "action":"Verify the affected dependency version against your software bill of materials.",
            "sources":refs,"exploitation":"Not confirmed by this source; check CISA KEV",
            "kind":"cve" if CVERE.match(fid) else "advisory","cvss":None,
            "status":"OSV indexed package advisory","first_seen_at":utc_iso(),
            "source_updated_at":item.get("modified") or "","source_type":"osv_recent","known_exploited":False}


def wordfence_items() -> list[dict]:
    key=os.getenv("WORDFENCE_API_KEY")
    if not key:
        raise RuntimeError("Requires WORDFENCE_API_KEY in GitHub Actions secrets")
    req=urllib.request.Request(SOURCES["wordfence"],headers={"Authorization":"Bearer "+key,
                                                               "User-Agent":"CVEHarbor-PublicFeed/1.0"})
    with urllib.request.urlopen(req,timeout=40) as resp:
        raw=resp.read(35_000_001)
    if len(raw)>35_000_000:raise ValueError("Wordfence feed too large for configured response limit")
    data=json.loads(raw)
    if not isinstance(data,dict):raise ValueError("Unexpected Wordfence response schema")
    return list(data.values())


def from_wordfence(item:dict) -> dict | None:
    ids=item.get("cve") or item.get("cve_id") or ""
    if isinstance(ids,list):ids=" ".join(str(x) for x in ids)
    match=re.search(r"\\bCVE-\\d{4}-\\d{4,}\\b",str(ids),re.I)
    if not match:return None
    fid=match.group(0).upper()
    title=crop(item.get("title") or fid,175)
    score=item.get("cvss") or {}
    if isinstance(score,dict):
        score=score.get("score") or score.get("cvss_score")
    try:cvss=float(score)
    except (ValueError,TypeError):cvss=None
    sev="critical" if cvss is not None and cvss>=9 else "high" if cvss is not None and cvss>=7 else "medium" if cvss is not None and cvss>=4 else "bulletin"
    products=[str(x.get("name") or "") for x in item.get("software") or [] if isinstance(x,dict)]
    return {"id":fid,"title":title,"severity":sev,"categories":["WordPress / Plugins"],
            "published":datepart(item.get("published") or item.get("published_at")),
            "updated":datepart(item.get("updated") or item.get("updated_at")),
            "summary":crop(item.get("description") or title,1150),
            "affected":crop(", ".join(products),700) or "See Wordfence advisory",
            "remediation":"Review the Wordfence advisory for patched versions.",
            "action":"Check installed WordPress plugins and themes against affected versions.",
            "sources":[{"label":"Wordfence Intelligence","url":"https://www.wordfence.com/threat-intel/vulnerabilities/"}],
            "exploitation":"Not confirmed by this source; check CISA KEV",
            "kind":"cve","cvss":str(cvss) if cvss is not None else None,
            "status":"Wordfence Intelligence advisory","first_seen_at":utc_iso(),
            "source_updated_at":item.get("updated") or "","source_type":"wordfence","known_exploited":False}


def merge_record(old: dict, new: dict) -> dict:
    """Merge source observations without discarding first seen time or KEV flags."""
    if not old:
        return new
    # GitHub generally provides better fixed package versions. Do not replace
    # an actionable package detail with NVD's generic patch instructions.
    rank = {"php_upstream": 5, "wordfence":4.5, "github": 4, "osv_recent": 3.5, "vendor_baseline": 3, "nvd": 2, "msrc_rss":2, "fortinet_rss":2, "ubuntu_rss":2, "cisa_kev": 1}
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


def choose_records(merged: dict[str,dict], baseline_ids: set[str]) -> list[dict]:
    """Prioritize original disclosure dates and retain separately revised issues."""
    # Prioritize genuinely NEW CVEs before older records with recent metadata
    # updates. Retain important vendor baselines and known exploited issues.
    published_cutoff = (NOW - timedelta(days=30)).date().isoformat()
    updated_cutoff = (NOW - timedelta(days=7)).date().isoformat()
    all_records = list(merged.values())
    def publish_order(r):
        return (r.get("published") or "", r.get("updated") or "")
    newly_disclosed = sorted(
        [r for r in all_records if (r.get("published") or "") >= published_cutoff],
        key=publish_order, reverse=True
    )
    recently_revised = sorted(
        [r for r in all_records if (r.get("published") or "") < published_cutoff
         and (r.get("updated") or "") >= updated_cutoff],
        key=lambda r:(r.get("updated") or "",r.get("published") or ""), reverse=True
    )
    historical = sorted(all_records, key=publish_order, reverse=True)
    chosen = {rid: merged[rid] for rid in baseline_ids if rid in merged}
    for group in (newly_disclosed, recently_revised):
        for record in group:
            if len(chosen) >= MAX_RECORDS:
                break
            chosen.setdefault(record["id"], record)
    for record in sorted((r for r in all_records if r.get("known_exploited")),
                         key=lambda r:r.get("updated") or "", reverse=True):
        if len(chosen) >= MAX_RECORDS:
            break
        chosen.setdefault(record["id"], record)
    for record in historical:
        if len(chosen) >= MAX_RECORDS:
            break
        chosen.setdefault(record["id"], record)
    # Public list is ordered by original disclosure, not last-modified metadata.
    records = sorted(chosen.values(), key=publish_order, reverse=True)
    return records


def run() -> int:
    prev = json.loads(DATA.read_text(encoding="utf-8")) if DATA.exists() else {}
    previous = {}
    for item in prev.get("advisories") or []:
        if not item.get("id"):
            continue
        migrated = recategorize_existing(migrate_legacy_categories(item))
        if migrated.get("categories"):
            previous[migrated["id"]] = migrated
    merged = dict(previous)
    # Seed historically verified vendor advisories as baseline records. They
    # retain original disclosure dates and are not treated as new feed events.
    baseline = vendor_baseline_items()
    baseline_ids = {record["id"] for record in baseline}
    for record in baseline:
        rid = record["id"]
        merged[rid] = merge_record(merged.get(rid), record)
    sources = dict(prev.get("sources") or {})
    operations = (("github", ghsa_items, from_ghsa),
                  ("php_upstream", php_upstream_items, from_php_upstream),
                  ("nvd", nvd_items, from_nvd),
                  ("cisa_kev", kev_items, from_kev),
                  ("msrc_rss", lambda:rss_vendor_items("msrc_rss"), from_vendor_rss),
                  ("fortinet_rss", lambda:rss_vendor_items("fortinet_rss"), from_vendor_rss),
                  ("ubuntu_rss", lambda:rss_vendor_items("ubuntu_rss"), from_vendor_rss),
                  ("osv_recent", osv_recent_items, from_osv))
    if os.getenv("WORDFENCE_API_KEY"):
        operations += (("wordfence",wordfence_items,from_wordfence),)
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
                "advisories": list(merged.values()), "sources":sources,
                "last_checked_at": utc_iso(), "last_successful_update": prev.get("last_successful_update")}
        publish(fail)
        return 1
    records = choose_records(merged, baseline_ids)
    result = {"siteName":"CVEHarbor", "snapshotDate": NOW.date().isoformat(),
              "mode":"live" if good == len(operations) else "partial",
              "coverage_limited":len(merged)>len(records),
              "candidate_records":len(merged),
              "categories":CATEGORIES, "advisories":records,
              "sources":sources, "last_checked_at":utc_iso(), "last_successful_update":utc_iso(),
              "note":"Public advisory intelligence only. Actual vulnerability exposure requires asset/version validation."}
    publish(result)
    print(f"Published {len(records)} records across {good}/{len(operations)} sources")
    return 0


def publish(data: dict):
    """Validate a snapshot and publish a small machine-readable health report."""
    DATA.parent.mkdir(parents=True, exist_ok=True)
    entries = data.get("advisories") or []
    ids = [str(x.get("id") or "") for x in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate advisory identifiers in public snapshot")
    for record in entries:
        if not (CVERE.match(str(record.get("id") or "")) or GHSA.match(str(record.get("id") or ""))):
            raise ValueError("Unrecognized public advisory identifier")
        if not record.get("categories") or any(x not in ALLOWED for x in record["categories"]):
            raise ValueError("Unrecognized or missing technology category")
        for field in ("published", "updated"):
            value = record.get(field) or ""
            if value and datepart(value) != value[:10]:
                raise ValueError("Invalid advisory " + field + " date")
    text = json.dumps(data, ensure_ascii=False, indent=2)
    DATA.write_text(text + "\n", encoding="utf-8")
    # Escape closing script markup for safe embedding even if vendor text is hostile.
    embed = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    SCRIPT.write_text("/* Automatically generated. Do not edit directly. */\nwindow.CVEHARBOR_DATA = " + embed + ";\n", encoding="utf-8")
    counts = {category["name"]:0 for category in CATEGORIES}
    for record in entries:
        for category in record["categories"]:
            counts[category] += 1
    sources = {}
    for name, source in (data.get("sources") or {}).items():
        sources[name] = {key:source.get(key) for key in ("ok","last_attempt","last_success","items_processed","error")}
    health = {"mode":data.get("mode"),"last_checked_at":data.get("last_checked_at"),
              "last_successful_update":data.get("last_successful_update"),
              "records_indexed":len(entries),"candidate_records":data.get("candidate_records"),
              "coverage_limited":bool(data.get("coverage_limited")),
              "category_counts":counts,"sources":sources,
              "note":"Snapshot status reports feed collection, not exhaustive vendor coverage or deployed-system exposure."}
    HEALTH.write_text(json.dumps(health, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(run())
