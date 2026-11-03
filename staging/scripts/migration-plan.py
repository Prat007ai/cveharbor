"""Credential-free migration checkpoints. No network or remote SQL execution."""
import hashlib
import json
import sqlite3
from pathlib import Path
import subprocess
import os
import tempfile
ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'staging/.build/schema'

def write_atomic(destination, text):
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=destination.parent, delete=False) as temporary:
            name = temporary.name
            temporary.write(text)
        os.replace(name, destination)
    finally:
        if name and os.path.exists(name):
            os.unlink(name)

SCHEMA_SQL = "SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' AND name NOT GLOB '_cf_*' AND name NOT GLOB 'd1_*' ORDER BY type,name"

def d1_limits(db):
    # Conservative published D1 limits, plus workerd's five-term compound cap.
    for name, value in [('LENGTH', 2000000), ('SQL_LENGTH', 100000), ('COLUMN', 100),
                        ('EXPR_DEPTH', 100), ('COMPOUND_SELECT', 5), ('VDBE_OP', 250000),
                        ('FUNCTION_ARG', 32), ('ATTACHED', 0), ('LIKE_PATTERN_LENGTH', 50),
                        ('VARIABLE_NUMBER', 100), ('TRIGGER_DEPTH', 10)]:
        db.setlimit(getattr(sqlite3, 'SQLITE_LIMIT_' + name), value)

def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':'))

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def identifier(name):
    return '"' + name.replace('"', '""') + '"'

def statements(sql):
    # SQLite, rather than splitting on ';', recognizes trigger bodies and quoted literals.
    pending = ''
    for char in sql:
        pending += char
        if char == ';' and sqlite3.complete_statement(pending):
            yield pending
            pending = ''
    if pending.strip() and not all(not line.strip() or line.lstrip().startswith('--') for line in pending.splitlines()):
        raise ValueError('Unterminated SQL')

def row_sql(name, columns):
    values = []
    for col in columns:
        value = identifier(col)
        # The only time-dependent built-in seed. Preserve its type/range invariant.
        if name == 'cvie_maintenance' and col == 'completed_at':
            value = "CASE WHEN typeof(completed_at)='integer' AND completed_at>0 AND completed_at<=CAST(strftime('%s','now') AS INTEGER)*1000+300000 THEN '<migration-time>' ELSE 'INVALID' END"
        if (name == 'staging_schema_history' and col == 'applied_at') or (name == 'operations_control' and col == 'changed_at'):
            value = "CASE WHEN typeof(" + identifier(col) + ")='text' AND datetime(" + identifier(col) + ") IS NOT NULL AND datetime(" + identifier(col) + ")<=datetime('now','+5 minutes') THEN '<migration-time>' ELSE 'INVALID' END"
        values.append('quote(' + value + ')')
    return 'SELECT ' + "||'|'||".join(values) + ' AS value FROM ' + identifier(name) + ' ORDER BY value COLLATE BINARY'

def build():
    subprocess.run(['node','staging/scripts/schema.mjs'],cwd=ROOT,check=True,capture_output=True)
    approved_bytes=(ROOT/'staging/migrations.v1.json').read_bytes()
    approved=json.loads(approved_bytes)
    validated=json.loads((OUT/'validated-plan.json').read_text())
    manifest=[{'file':e['path'],'sha256':e['sha256'],'phase':'manifest'} for e in approved['entries']]
    guards=';\n'.join(validated['guards'])+';\n'
    manifest.append({'file':'staging/.build/schema/recovery-guards.sql','sha256':digest(guards),'phase':'recovery-guards'})
    write_atomic(OUT/'recovery-guards.sql', guards)
    db = sqlite3.connect(':memory:')
    d1_limits(db)
    db.execute('PRAGMA foreign_keys=ON')
    plan = {'format': 1, 'manifest_version': approved['version'], 'approved_manifest_sha256': hashlib.sha256(approved_bytes).hexdigest(),
            'schema_sql': SCHEMA_SQL, 'files': [], 'checkpoints': [], 'schemas': {}}
    def checkpoint():
        objects = [list(row) for row in db.execute(SCHEMA_SQL)]
        sh = digest(encoded(objects))
        tables = []
        counts = []
        data = []
        for _, name, _, _ in objects:
            if not any(o[0] == 'table' and o[1] == name for o in objects):
                continue
            if any(t['name'] == name for t in tables):
                continue
            columns = [r[1] for r in db.execute('PRAGMA table_info(' + identifier(name) + ')')]
            query = row_sql(name, columns)
            tables.append({'name': name, 'row_sql': query})
        tables.sort(key=lambda t: t['name'])
        for t in tables:
            rows = [r[0] for r in db.execute(t['row_sql'])]
            counts.append([t['name'], len(rows)])
            data.extend([[t['name'], row] for row in rows])
        plan['schemas'][sh] = {'objects': objects, 'tables': tables}
        plan['checkpoints'].append({'schema_sha256': sh, 'counts': counts, 'rows_sha256': digest(encoded(data))})
    checkpoint()
    for entry in manifest:
        sql = (ROOT / entry['file']).read_text()
        if digest(sql) != entry['sha256']:
            raise ValueError('Input changed')
        batch = list(statements(sql))
        if entry['phase']=='manifest':
            batch.append("INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES('"+entry['file']+"','"+entry['sha256']+"',1);")
        start = len(plan['checkpoints']) - 1
        for statement in batch:
            db.execute(statement)
            if db.execute('PRAGMA foreign_key_check').fetchall():
                raise ValueError('Foreign key violation')
            checkpoint()
        plan['files'].append({**entry, 'start': start, 'end': len(plan['checkpoints']) - 1, 'statements': batch})
    if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok' or len(plan['checkpoints'][-1]['counts']) != validated['table_count']-1:
        raise ValueError('Invalid final schema')
    payload = encoded(plan) + '\n'
    write_atomic(OUT / 'execution-plan.json', payload)
    print('Migration execution plan SHA-256: ' + digest(payload))
    print('Statements: ' + str(len(plan['checkpoints']) - 1) + '; source files: ' + str(len(plan['files'])))
    db.close()
    return plan, digest(payload)

if __name__ == '__main__':
    build()

