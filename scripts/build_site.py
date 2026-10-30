#!/usr/bin/env python3
"""Build CVEHarbor public assets with stable platform taxonomy and dated vendor advisories.

Do not publish source credentials or internal workflow metadata. The vendor
catalog remains visible even if an independent upstream feed temporarily fails.
"""
from pathlib import Path
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'public'
if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir()

for name in ('index.html', 'styles.css', 'app.js', 'workspace.js', 'operations.js', 'accounts.js', 'disclosure-trend.js', 'page-router.js', 'header-auth.js', 'command-center.js', 'account-page.js', 'account-security.js', 'workspace-page.js', 'workspace-dashboard.js', 'lifecycle-monitor.js', 'inventory.js', 'inventory-matching.js', 'customer-security.js', 'customer-score.js', 'malware.js', 'geo-map.js', 'malware-data.js', 'data.js', 'CNAME', 'robots.txt'):
    shutil.copy2(ROOT / name, OUT / name)
for name in ('lifecycle.js','patch-notes.js','threats.js','threat-data.js','fortigate-threat-ip-objects.txt','sophos-threat-ip-api.txt','fortigate-suspicious-ip-initial.txt','fortigate-suspicious-ip-incremental.txt','sophos-suspicious-ip-initial.txt','sophos-suspicious-ip-incremental.txt'):
    if (ROOT / name).exists():
        shutil.copy2(ROOT / name, OUT / name)
# Public snapshot health report is generated on each actual feed refresh.
if (ROOT / 'data' / 'feed-health.json').exists():
    shutil.copy2(ROOT / 'data' / 'feed-health.json', OUT / 'feed-health.json')

taxonomy = json.loads((ROOT / 'data' / 'demo-advisories.json').read_text(encoding='utf-8'))
baseline = json.loads((ROOT / 'data' / 'vendor-baseline.json').read_text(encoding='utf-8'))
categories = taxonomy['categories']
allowed = {c['name'] for c in categories}
assert len(categories) == len(allowed), 'Duplicate technology categories'

advisories = []
for entry in baseline['advisories']:
    if not entry.get('sources') or not set(entry.get('categories', [])).issubset(allowed):
        raise ValueError(f"Invalid dated vendor advisory: {entry.get('id')}")
    record = {
        **entry,
        'kind': 'cve' if str(entry.get('id','')).startswith('CVE-') else 'advisory',
        'source_type': 'vendor_baseline',
        'status': 'Historical vendor advisory (not a new disclosure)',
        'known_exploited': bool(entry.get('known_exploited', False)),
        'first_seen_at': None,
        'action': 'Verify your deployed version and follow the linked official vendor advisory.',
    }
    advisories.append(record)

catalog = {
    'siteName': 'CVEHarbor',
    'categories': categories,
    'advisories': advisories,
    'catalogStatus': 'Dated vendor advisories, shown independently of hourly feed health',
}
content = json.dumps(catalog, ensure_ascii=False, separators=(',', ':')).replace('</', '<\\/')
(OUT / 'catalog.js').write_text('window.CVEHARBOR_CATALOG = ' + content + ';\n', encoding='utf-8')
(OUT / '.nojekyll').touch()
print('Built public site:', [x.name for x in OUT.iterdir()])
print(f"Categories: {len(categories)}; official historical vendor advisories: {len(advisories)}")

# Dedicated account and workspace pages retain the same domain and API session.
for section in ('account','workspace','customer-dashboard','customer-reports'):
    page=OUT / section
    page.mkdir(exist_ok=True)
    shutil.copy2(ROOT / section / 'index.html',page / 'index.html')

# Publish canonical GitHub Pages section URLs. The shared DOM temporarily
# remains available to existing scripts and modal handlers; CSS scopes each
# route's visible content. Remove the shared DOM only after script modularization.
SECTION_PAGES = {
    'vulnerabilities': 'Vulnerability Search and Advisories',
    'alerts': 'My Technology Watchlist and Security Alerts',
    'threats': 'Threat IP Intelligence',
    'malware': 'Malware and Ransomware Intelligence',
    'lifecycle': 'End of Support and Patch Watch',
    'environments': 'My Customer Environments',
    'admin-tools': 'Security Administration Toolkit',
    'remediation': 'Vulnerability Remediation Tracker',
}
source_html = (ROOT / 'index.html').read_text(encoding='utf-8')
home_html = source_html.replace('<body>', '<body data-page="home">', 1)
home_html = home_html.replace('href="#advisories">Skip to advisories', 'href="#dashboard">Skip to overview', 1)
(OUT / 'index.html').write_text(home_html, encoding='utf-8')
for section, heading in SECTION_PAGES.items():
    folder = OUT / section
    folder.mkdir(exist_ok=True)
    page = source_html.replace('<body>', f'<body data-page="{section}">', 1)
    first_section = {
        'vulnerabilities': 'technology', 'alerts': 'securityWorkspace',
        'threats': 'threat-intelligence', 'malware': 'malware-intelligence',
        'lifecycle': 'lifecycleMonitor', 'environments': 'inventoryWorkspace',
        'admin-tools': 'operationsCentre', 'remediation': 'remediationTracker',
    }[section]
    page = page.replace('href="#advisories">Skip to advisories',
                        f'href="#{first_section}">Skip to main section', 1)
    # All locally hosted scripts and images use root-relative paths on nested
    # routes so they do not resolve to /malware/data.js, etc.
    import re
    page = re.sub(r'(src=")(?!https?://|/)([^"]+)"',
                  lambda match: match.group(1) + '/' + match.group(2) + '"', page)
    page = page.replace('<title>CVEHarbor | Vulnerability Intelligence</title>',
                        f'<title>{heading} | CVEHarbor</title>', 1)
    page = page.replace('<meta name="description" content="CVEHarbor: Independent, source-backed vulnerability intelligence across application frameworks, CMS, cloud, databases and IT infrastructure.">',
                        f'<meta name="description" content="CVEHarbor {heading}. Source-backed security intelligence and tools.">', 1)
    (folder / 'index.html').write_text(page, encoding='utf-8')
print('Dedicated public section pages:', ', '.join(SECTION_PAGES))
