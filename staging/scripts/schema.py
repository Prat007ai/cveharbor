"""Validate the full schema locally and emit a checksummed staging bootstrap plan.

Does not connect to Cloudflare or apply a remote migration.
"""
from pathlib import Path
import hashlib
import json
import sqlite3

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / 'account-backend'
OUT = ROOT / 'staging/.build/schema'

def prepare():
    files = [BACKEND / 'schema.sql']
    files += [BACKEND / name for name in [
        'totp-schema.sql', 'alert-schema.sql', 'inventory-schema.sql', 'remediation-schema.sql',
        'lifecycle-schema.sql', 'finding-status-schema.sql', 'finding-ticket-schema.sql',
        'finding-ticket-history-schema.sql', 'customer-score-schema.sql', 'package-inventory-schema.sql',
        'software-upgrade-history-schema.sql', 'plugin-monitor-schema.sql', 'plugin-release-schema.sql', 'plugin-source-schema.sql',
    ]]
    files += sorted((BACKEND / 'migrations').glob('*.sql'))
    connection = sqlite3.connect(':memory:')
    connection.execute('PRAGMA foreign_keys=ON')
    manifest = []
    bootstrap = []
    for f in files:
        sql = f.read_text()
        connection.executescript(sql)
        assert not connection.execute('PRAGMA foreign_key_check').fetchall(), f
        manifest.append({'file': str(f.relative_to(ROOT)), 'sha256': hashlib.sha256(sql.encode()).hexdigest(),
                         'phase': 'bootstrap' if f.name[:4] not in ('0028', '0029') else f.name[:4]})
        if manifest[-1]['phase'] == 'bootstrap':
            bootstrap.append('-- ' + str(f.relative_to(ROOT)) + '\n' + sql)
    assert connection.execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / 'bootstrap-through-0027.sql').write_text('\n'.join(bootstrap))
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    tables = connection.execute("SELECT count(*) FROM sqlite_schema WHERE type='table'").fetchone()[0]
    print(f'Full local schema validated: {tables} tables; 0028/0029 remain separate remote steps.')
    connection.close()

if __name__ == '__main__':
    prepare()
