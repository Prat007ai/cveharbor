"""Build only local synthetic assets in an isolated temporary tree. No feed fetches."""
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'staging/.build/public'
ORIGIN = 'https://cveharbor-site-staging.cveharbor-staging.workers.dev'

def build():
    with tempfile.TemporaryDirectory(prefix='cvie-staging-assets-') as directory:
        tree = Path(directory)
        tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
        generated = {'data.js', 'malware-data.js', 'threat-data.js', 'lifecycle.js', 'patch-notes.js'}
        for name in tracked:
            if not name or name.startswith(('data/', 'public/', 'staging/', '.github/', 'account-backend/', 'docs/')) or name in generated:
                continue
            if name.startswith(('attack-scanning-', 'fortigate-', 'sophos-')):
                continue
            source = ROOT / name
            if source.is_file():
                target = tree / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        data = tree / 'data'
        data.mkdir()
        # These are checked-in static taxonomy/identity definitions, not collected intelligence.
        taxonomy = json.loads((ROOT / 'data/demo-advisories.json').read_text())
        (data / 'demo-advisories.json').write_text(json.dumps(taxonomy))
        shutil.copy2(ROOT / 'data/lifecycle-products.json', data / 'lifecycle-products.json')
        snapshot = {'siteName': 'CVEHarbor STAGING', 'snapshotDate': '2026-11-02', 'mode': 'synthetic_staging',
                    'coverage_limited': True, 'candidate_records': 0, 'categories': taxonomy['categories'], 'advisories': [], 'sources': {}}
        (data / 'advisories.json').write_text(json.dumps(snapshot))
        (data / 'vendor-baseline.json').write_text(json.dumps({'advisories': []}))
        for name, variable, content in [
            ('data.js', 'CVEHARBOR_DATA', snapshot),
            ('malware-data.js', 'CVEHARBOR_MALWARE', {'samples': [], 'advisories': [], 'sources': {}}),
            ('threat-data.js', 'CVEHARBOR_THREATS', {'sources': {}, 'ips': [], 'scanners': [], 'schema_version': 2}),
        ]:
            (tree / name).write_text('window.' + variable + ' = ' + json.dumps(content) + ';\n')
        subprocess.run(['python', 'scripts/build_site.py'], cwd=tree, check=True, capture_output=True)
        public = tree / 'public'
        (public / 'CNAME').unlink(missing_ok=True)
        (public / 'robots.txt').write_text('User-agent: *\nDisallow: /\n')
        for target in public.rglob('*'):
            if target.is_file() and target.suffix in {'.js', '.html', '.json', '.css', '.txt', '.svg'}:
                text = target.read_text()
                text = re.sub(r'https://(?:api\.|confirm\.|www\.)?cveharbor\.com', ORIGIN, text)
                if target.suffix == '.html':
                    text = text.replace('<head>', '<head><meta name="robots" content="noindex,nofollow">', 1)
                    text = re.sub(r'(<body\b[^>]*>)', r'\1<div role="status" style="padding:8px;background:#573b00;color:white">CVEHarbor STAGING — synthetic data; captured email only; native schedules disabled</div>', text, count=1)
                target.write_text(text)
        if OUT.exists():
            shutil.rmtree(OUT)
        OUT.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(public, OUT)
        for target in OUT.rglob('*'):
            if target.is_file() and target.suffix in {'.js', '.html', '.json'}:
                assert not re.search(r'https://(?:api\.|confirm\.|www\.)?cveharbor\.com', target.read_text()), target
        print('Synthetic staging assets built; production output was not touched.')

if __name__ == '__main__':
    build()

