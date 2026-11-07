"""Offline, fail-closed D1 dump conversion. No network or credential access.

Only oversized single-row literal INSERTs change. Complete values are assembled
in an import-only table before the original INSERT, preserving target triggers,
constraints and statement order. No target row is inserted in pieces.
"""
import argparse
import collections
import hashlib
import json
import re
import sqlite3
import struct
import sys
from pathlib import Path

STATEMENT_LIMIT = 100_000
IMPORT_LIMIT = 200_000_000  # tighter rehearsal upload bound, provider limit 5 GB
VALUE_LIMIT = 2_000_000
CHUNK_BYTES = 16_000
SCRATCH = '__pr270_import_value_8c21b7'
IDENT = r'(?:"(?:[^"]|"")*"|`[^`]*`|\[[^]]*\]|[A-Za-z_]\w*)'
INSERT = re.compile(r'\A(\s*INSERT\s+INTO\s+' + IDENT + r'\s*(?:\([^)]*\)\s*)?VALUES\s*)\((.*)\)\s*;\s*\Z', re.I | re.S)
LITERAL = re.compile(r"(?:NULL|[-+]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?|'(?:[^']|'')*'|[xX]'(?:[0-9a-fA-F]{2})*')\Z", re.I)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def statements(text):
    """Keep original bytes/whitespace; SQLite recognizes trigger END boundaries."""
    if '\x00' in text:
        raise ValueError('NUL in SQL source')
    start = i = 0
    quote = None
    comment = None
    while i < len(text):
        c = text[i]
        nxt = text[i:i+2]
        if comment == 'line':
            if c == '\n': comment = None
        elif comment == 'block':
            if nxt == '*/': comment = None; i += 1
        elif quote:
            if c == quote:
                if quote != ']' and i+1 < len(text) and text[i+1] == quote: i += 1
                else: quote = None
        elif nxt == '--': comment = 'line'; i += 1
        elif nxt == '/*': comment = 'block'; i += 1
        elif c in "'\"`[": quote = ']' if c == '[' else c
        elif c == ';' and sqlite3.complete_statement(text[start:i+1]):
            yield text[start:i+1]
            start = i+1
        i += 1
    tail = text[start:]
    if re.sub(r'--[^\n]*(?:\n|$)|/\*.*?\*/', '', tail, flags=re.S).strip():
        raise ValueError('Incomplete SQL statement')
    if quote or comment == 'block': raise ValueError('Unclosed SQL token')
    if tail: yield tail


def preflight(data):
    if len(data) > IMPORT_LIMIT: raise ValueError('Import request/file size limit')
    parts = list(statements(data.decode('utf-8')))
    sizes = [len(s.encode('utf-8')) for s in parts]
    if any(n > STATEMENT_LIMIT for n in sizes):
        raise ValueError('Oversized SQL statement before upload')
    return {'bytes': len(data), 'statements': len(parts), 'max_statement_bytes': max(sizes, default=0), 'sha256': sha(data)}


def fields(body):
    result = []; start = i = 0; quoted = False
    while i < len(body):
        if body[i] == "'":
            if quoted and i+1 < len(body) and body[i+1] == "'": i += 1
            else: quoted = not quoted
        elif body[i] == ',' and not quoted:
            result.append(body[start:i].strip()); start = i+1
        i += 1
    result.append(body[start:].strip())
    if quoted or not all(LITERAL.fullmatch(v) for v in result):
        raise ValueError('Oversized INSERT must contain one row of literal values')
    return result


def chunks(literal):
    if literal[:2].lower() == "x'":
        raw = bytes.fromhex(literal[2:-1])
        if len(raw) > VALUE_LIMIT: raise ValueError('BLOB exceeds D1 value limit')
        return ['X\'' + raw[i:i+CHUNK_BYTES//2].hex() + "'" for i in range(0, len(raw), CHUNK_BYTES//2)], 'blob'
    if not literal.startswith("'"): raise ValueError('Unsupported oversized literal')
    value = literal[1:-1].replace("''", "'")
    if len(value.encode()) > VALUE_LIMIT: raise ValueError('TEXT exceeds D1 value limit')
    result = []; part = []; size = 0
    for c in value:
        escaped = c.replace("'", "''"); length = len(escaped.encode())
        if size+length > CHUNK_BYTES:
            result.append("'" + ''.join(part) + "'"); part = []; size = 0
        part.append(escaped); size += length
    if part: result.append("'" + ''.join(part) + "'")
    return result, 'text'


def transform(data):
    if len(data) > IMPORT_LIMIT: raise ValueError('Input file bound')
    text = data.decode('utf-8')
    if SCRATCH.casefold() in text.casefold(): raise ValueError('Scratch identifier collision')
    output = []; changes = []; created = False; serial = 0; added = 0
    for number, sql in enumerate(statements(text), 1):
        if len(sql.encode()) <= STATEMENT_LIMIT:
            output.append(sql); continue
        match = INSERT.fullmatch(sql)
        if not match: raise ValueError('Unsupported oversized SQL; original retained')
        values = fields(match[2]); before = len(sql.encode()); fragments = 0
        if not created:
            output.append(f'\nCREATE TABLE "{SCRATCH}"(id INTEGER PRIMARY KEY,v);\n')
            created = True; added += 1
        for index, value in enumerate(values):
            if len(value.encode()) <= CHUNK_BYTES: continue
            pieces, kind = chunks(value); serial += 1
            output.append(f'INSERT INTO "{SCRATCH}"(id,v) VALUES({serial},{pieces[0]});\n')
            for piece in pieces[1:]:
                # || yields TEXT; explicit BLOB cast preserves binary storage class.
                expr = f'v||{piece}'
                if kind == 'blob': expr = f'CAST({expr} AS BLOB)'
                output.append(f'UPDATE "{SCRATCH}" SET v={expr} WHERE id={serial};\n')
            values[index] = f'(SELECT v FROM "{SCRATCH}" WHERE id={serial})'
            fragments += len(pieces); added += len(pieces)
        replacement = match[1] + '(' + ','.join(values) + ');'
        if not fragments or len(replacement.encode()) > STATEMENT_LIMIT:
            raise ValueError('Cannot represent oversized INSERT within limit')
        output.append(replacement)
        changes.append({'statement': number, 'original_sha256': sha(sql.encode()), 'original_bytes': before,
                        'replacement_sha256': sha(replacement.encode()), 'replacement_bytes': len(replacement.encode()), 'fragment_writes': fragments})
    if created:
        output.append(f'\nDROP TABLE "{SCRATCH}";\n'); added += 1
    converted = ''.join(output).encode()
    check = preflight(converted)
    return converted, {'version': 1, 'original_sha256': sha(data), 'converted': check, 'changes': changes,
                       'scratch_table': SCRATCH if created else None, 'scratch_values': serial,
                       'added_statements': added, 'method': 'complete literal assembly before original target INSERT; unchanged order'}


def snapshot(db):
    schema = db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name").fetchall()
    result = {}; coverage = collections.Counter()
    for (table,) in db.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"):
        quoted = '"'+table.replace('"', '""')+'"'
        columns = db.execute(f'PRAGMA table_xinfo({quoted})').fetchall()
        names = ['"'+c[1].replace('"', '""')+'"' for c in columns if c[6] != 1]
        if not any(c[1].lower() == '_rowid_' for c in columns):
            try:
                db.execute(f'SELECT _rowid_ FROM {quoted} LIMIT 0')
                names.insert(0, '_rowid_')
            except sqlite3.OperationalError:
                pass  # WITHOUT ROWID table
        # typeof + hex preserves NULL, bytes, Unicode/NUL and numeric storage classes.
        query = 'SELECT ' + ','.join('typeof('+n+'),'+n for n in names) + ' FROM '+quoted
        encoded = []
        for row in db.execute(query):
            fields_out = []
            for i in range(0,len(row),2):
                kind, value = row[i:i+2]; coverage[kind] += 1
                if kind == 'blob': value = value.hex()
                elif kind == 'real': value = struct.pack('>d',value).hex()
                elif kind == 'text':
                    coverage['unicode'] += any(ord(c)>127 for c in value)
                    coverage['quotes'] += "'" in value or '"' in value
                    coverage['newlines'] += '\n' in value or '\r' in value
                    value = value.encode('utf-8').hex()
                fields_out.append([kind,value])
            encoded.append(json.dumps(fields_out,separators=(',',':')).encode())
        encoded.sort()
        result[table] = {'columns': columns, 'rows': len(encoded), 'typed_content_sha256': sha(b'\n'.join(encoded))}
    return {'schema': schema, 'tables': result, 'coverage': dict(coverage)}


def validate(original, converted):
    preflight(converted)
    results = []
    for data in (original, converted):
        db = sqlite3.connect(':memory:')
        try:
            db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, VALUE_LIMIT)
            db.set_authorizer(lambda action, arg1, arg2, *_:
                sqlite3.SQLITE_DENY if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH)
                or (action == sqlite3.SQLITE_FUNCTION and arg2 == 'load_extension')
                else sqlite3.SQLITE_OK)
            # Keep D1's foreign-key enforcement enabled. Its import is one implicit
            # transaction; dump PRAGMAs retain their original relative positions.
            db.execute('PRAGMA foreign_keys=ON'); db.execute('BEGIN')
            for sql in statements(data.decode('utf-8')): db.execute(sql)
            db.commit()
            if db.execute('PRAGMA foreign_key_check').fetchall(): raise ValueError('Foreign key violations')
            if db.execute('PRAGMA integrity_check').fetchall() != [('ok',)]: raise ValueError('Integrity failed')
            results.append(snapshot(db))
        finally: db.close()
    if results[0] != results[1]: raise ValueError('Full typed content or schema mismatch')
    if SCRATCH in results[1]['tables']: raise ValueError('Scratch table remained')
    result = results[0]
    return {'schema_equal': True, 'counts_equal': True, 'types_and_full_content_equal': True,
            'foreign_keys_enabled': True, 'foreign_key_check': 'pass', 'integrity_check': 'ok',
            'tables': len(result['tables']), 'rows': sum(t['rows'] for t in result['tables'].values()),
            'schema_sha256': sha(json.dumps(result['schema'],separators=(',',':')).encode()),
            'typed_content_sha256': sha(json.dumps(result['tables'],sort_keys=True,separators=(',',':')).encode()),
            'coverage': result['coverage'], 'sqlite_version': sqlite3.sqlite_version,
            'remote_atomicity_claimed': False}


def main():
    if sys.argv[1:] == ['--preflight-stdin']:
        print(json.dumps(preflight(sys.stdin.buffer.read(IMPORT_LIMIT+1))))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path); parser.add_argument('output', type=Path)
    parser.add_argument('--expected-sha256', required=True)
    args = parser.parse_args()
    if args.source.resolve() == args.output.resolve(): raise ValueError('Never overwrite original')
    data = args.source.read_bytes()
    if sha(data) != args.expected_sha256: raise ValueError('Original checksum mismatch')
    converted, report = transform(data)
    report['validation'] = validate(data, converted)
    if sha(args.source.read_bytes()) != report['original_sha256']: raise ValueError('Original changed')
    report_path = args.output.with_suffix('.manifest.json')
    if args.output.exists() or report_path.exists(): raise ValueError('Output already exists')
    with args.output.open('xb') as f: f.write(converted)
    with report_path.open('x',encoding='utf-8') as f: json.dump(report,f,indent=2)
    print(json.dumps(report))


if __name__ == '__main__':
    main()
