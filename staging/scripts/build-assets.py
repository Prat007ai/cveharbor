"""Build only local synthetic assets in an isolated temporary tree. No feed fetches."""
from pathlib import Path
import json
import os
import re
import shutil
import subprocess
import tempfile
import hashlib
import base64

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(os.environ.get('STAGING_ASSET_OUTPUT', ROOT / 'staging/.build/public')).resolve()
assert OUT in [ROOT/'staging/.build/public', ROOT/'staging/.build/customer-remediation-candidate/public']
SOURCE=Path(os.environ.get('STAGING_ASSET_SOURCE',ROOT)).resolve()
ORIGIN=os.environ.get('STAGING_ASSET_ORIGIN','https://cveharborstage.com')
assert ORIGIN=='https://cveharborstage.com'
assert SOURCE in [ROOT, ROOT/'release/.build/production-frontend']
QR_CDN = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js'
QR_LOCAL = '/assets/vendor/qrcodejs-1.0.0.min.js'
QR_INTEGRITY = 'CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA=='

def account_auth_for_staging(text):
    # Correct the pinned frontend only in the isolated staging asset tree.
    # /v1/me returns 401 + authenticated:false, without an error message.
    old = "if(!/Sign in required/.test(error.message))message('Account service unavailable. You can still browse the public website.');"
    new = "if(error.status!==401)message('Account service unavailable. You can still browse the public website.');"
    if "await window.CVEHarborAccountRead('/me')" in text and "if(error.status!==401)" in text:
        return text
    assert text.count(old) == 1, 'Review changed account-page.js authentication handler'
    return text.replace(old, new, 1)

def build():
    with tempfile.TemporaryDirectory(prefix='cvie-staging-assets-') as directory:
        tree = Path(directory)
        tracked = (subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0') if SOURCE==ROOT else [str(p.relative_to(SOURCE)) for p in SOURCE.rglob('*') if p.is_file()])
        generated = {'data.js', 'malware-data.js', 'threat-data.js', 'lifecycle.js', 'patch-notes.js'}
        for name in tracked:
            if not name or name.startswith(('data/', 'public/', 'staging/', '.github/', 'account-backend/', 'docs/')) or name in generated:
                continue
            if name.startswith(('attack-scanning-', 'fortigate-', 'sophos-')):
                continue
            source = SOURCE / name
            if source.is_file():
                target = tree / name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
        data = tree / 'data'
        data.mkdir()
        # These are checked-in static taxonomy/identity definitions, not collected intelligence.
        taxonomy = json.loads((SOURCE / 'data/demo-advisories.json').read_text())
        (data / 'demo-advisories.json').write_text(json.dumps(taxonomy))
        shutil.copy2(SOURCE / 'data/lifecycle-products.json', data / 'lifecycle-products.json')
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
        # Same audited bytes/SRI as the existing CDN reference; never download
        # a dependency during the build or at runtime. Keep the MIT notice.
        qr = (ROOT / 'staging/vendor/qrcodejs/qrcode.min.js').read_bytes().rstrip(b'\n')
        assert base64.b64encode(hashlib.sha512(qr).digest()).decode() == QR_INTEGRITY
        local_qr = public / QR_LOCAL.lstrip('/')
        local_qr.parent.mkdir(parents=True, exist_ok=True)
        local_qr.write_bytes(qr)
        shutil.copy2(ROOT / 'staging/vendor/qrcodejs/LICENSE', local_qr.with_suffix('.LICENSE.txt'))
        (public / 'CNAME').unlink(missing_ok=True)
        (public / 'robots.txt').write_text('User-agent: *\nDisallow: /\n')
        for target in public.rglob('*'):
            if target.is_file() and target.suffix in {'.js', '.html', '.json', '.css', '.txt', '.svg'}:
                text = target.read_text()
                if target.name == 'account-page.js':
                    text = account_auth_for_staging(text)
                text = re.sub(r'https://(?:api\.|confirm\.|www\.)?cveharbor\.com', ORIGIN, text)
                if target.suffix == '.html':
                    text = text.replace(QR_CDN, QR_LOCAL)
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

