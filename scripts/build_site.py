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

for name in ('index.html', 'styles.css', 'app.js', 'data.js', 'CNAME', 'robots.txt'):
    shutil.copy2(ROOT / name, OUT / name)
for name in ('threats.js','threat-data.js','fortigate-threat-ip-objects.txt','sophos-threat-ip-api.txt','fortigate-suspicious-ip-initial.txt','fortigate-suspicious-ip-incremental.txt','sophos-suspicious-ip-initial.txt','sophos-suspicious-ip-incremental.txt'):
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
