"""Restore a checkpoint-29 D1 export LOCALLY only; never contact Cloudflare.

Reports contain fingerprints/counts, not exported rows, SQL or private paths.
The export cannot prove its source account or Time Travel recoverability.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REFERENCE_SHA256 = 'd2a9af7136414eabe7dc5c74814addbdbb113e43d7edc0c85d8fbaadc1e9248e'
TOKENS = re.compile(r"--[^\n]*|/\*[\s\S]*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|`(?:``|[^`])*`|\[[^\]]*\]|[A-Za-z_][A-Za-z_0-9]*|\s+|.")

def ddl_tokens(sql):
    # Permit export formatting/identifier quoting, not changed expressions,
    # CHECK/UNIQUE/FK clauses, partial indexes or string literals.
    out = []
    for token in TOKENS.findall(sql):
        if token.isspace() or token.startswith(('--', '/*')):
            continue
        if token.startswith("'"):
            out.append(('literal', token))
        elif token.startswith(('"', '`', '[')):
            quote = token[0]
            out.append(('identifier', token[1:-1].replace(quote * 2, quote).lower()))
        elif re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', token):
            out.append(('identifier', token.lower()))
        else:
            out.append(('symbol', token))
    return out

def digest(data):
    return hashlib.sha256(data).hexdigest()

def validate_export(source):
    reference_bytes = (ROOT / 'staging/schema-diagnostic.v1.json').read_bytes()
    if digest(reference_bytes) != REFERENCE_SHA256:
        raise ValueError('reference_checksum')
    reference = json.loads(reference_bytes)
    original = (ROOT / reference['source_sql']).read_bytes()
    if digest(original) != reference['source_sql_sha256']:
        raise ValueError('original_source_checksum')
    if source.stat().st_size > 100000000:
        raise ValueError('export_size_limit')
    payload = source.read_bytes()
    report = {'local_only': True, 'status': 'failed', 'export_sha256': digest(payload),
              'export_bytes': len(payload), 'expected_original_checkpoint': 29,
              'expected_schema_sha256': reference['checkpoints'][29]['schema_sha256'],
              'source_identity_requires_admin_verification': True,
              'time_travel_not_tested': True}
    with tempfile.TemporaryDirectory(prefix='cveharbor-local-export-') as temp:
        expected = sqlite3.connect(':memory:')
        expected.executescript(original.decode('utf-8'))
        restored = sqlite3.connect(str(Path(temp) / 'restored.sqlite'))
        restored.enable_load_extension(False)
        def authorize(action, one, two, database, _trigger):
            if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_PRAGMA and one.lower() not in ('foreign_keys', 'defer_foreign_keys'):
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and str(two).lower() in ('load_extension', 'writefile', 'readfile'):
                return sqlite3.SQLITE_DENY
            if database not in (None, 'main'):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK
        restored.set_authorizer(authorize)
        ticks = 0
        def bounded():
            nonlocal ticks
            ticks += 1
            return int(ticks > 2000)
        restored.set_progress_handler(bounded, 10000)
        try:
            restored.executescript(payload.decode('utf-8-sig'))
            restored.set_authorizer(None)
            restored.execute('PRAGMA foreign_keys=ON')
            objects = list(restored.execute(reference['schema_sql']))
            wanted = list(expected.execute(reference['schema_sql']))
            if [r[:3] for r in objects] != [r[:3] for r in wanted] or any(ddl_tokens(a[3]) != ddl_tokens(b[3]) for a, b in zip(objects, wanted)):
                raise ValueError('schema_definition_mismatch')
            counts = []
            for kind, name, _table, _sql in wanted:
                ident = '"' + name.replace('"', '""') + '"'
                if kind == 'table':
                    counts.append([name, restored.execute('SELECT count(*) FROM ' + ident).fetchone()[0]])
                    for pragma in ['table_xinfo', 'foreign_key_list', 'index_list']:
                        query = 'PRAGMA ' + pragma + '(' + ident + ')'
                        actual_rows, expected_rows = list(restored.execute(query)), list(expected.execute(query))
                        if pragma == 'index_list':
                            # Index creation order is immaterial in a SQL export;
                            # retain name, uniqueness, origin and partial flag.
                            actual_rows = sorted(row[1:] for row in actual_rows)
                            expected_rows = sorted(row[1:] for row in expected_rows)
                        if actual_rows != expected_rows:
                            raise ValueError('table_metadata_mismatch')
                elif kind == 'index':
                    query = 'PRAGMA index_xinfo(' + ident + ')'
                    if list(restored.execute(query)) != list(expected.execute(query)):
                        raise ValueError('index_metadata_mismatch')
            if counts != reference['checkpoints'][29]['counts']:
                raise ValueError('unexpected_application_rows')
            if list(restored.execute('PRAGMA foreign_key_check')):
                raise ValueError('foreign_key_violation')
            if list(restored.execute('PRAGMA integrity_check')) != [('ok',)]:
                raise ValueError('integrity_failure')
            if digest(source.read_bytes()) != report['export_sha256']:
                raise ValueError('export_changed_during_validation')
            report.update(status='passed', tables=18, explicit_indexes=10, application_rows=0,
                          local_restore_passed=True, foreign_keys_passed=True, integrity_check='ok',
                          definitions_and_constraints_match=True)
        finally:
            restored.close()
            expected.close()
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', dest='source', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.report.resolve().is_relative_to(ROOT) or args.report.exists():
        raise SystemExit('Use a new private report path outside the repository.')
    try:
        report = validate_export(args.source)
    except Exception:
        raise SystemExit('Local export validation failed. Keep adoption blocked; inspect privately. No export contents were logged.')
    with args.report.open('x') as target:
        args.report.chmod(0o600)
        json.dump(report, target, indent=2)
        target.write('\n')
    print('PASS: local checkpoint-29 restore, definitions, counts, foreign keys and integrity. Live identity and recovery retention still require administrator verification.')

if __name__ == '__main__':
    main()
