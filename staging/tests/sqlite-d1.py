"""Local-only SQL engine for D1 contract tests; counters are synthetic, not billing estimates."""
import json
import sqlite3
import sys

db = sqlite3.connect(':memory:', isolation_level=None)
db.row_factory = sqlite3.Row
db.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 5)
db.execute('PRAGMA foreign_keys=ON')
def split_sql(sql):
    pending = ''
    out = []
    for char in sql:
        pending += char
        if char == ';' and sqlite3.complete_statement(pending):
            out.append({'sql': pending})
            pending = ''
    if pending.strip():
        out.append({'sql': pending})
    return out

for line in sys.stdin:
    message = json.loads(line)
    result = []
    try:
        items = message['batch'] if 'batch' in message else split_sql(message['sql'])
        transactional = 'batch' in message or len(items) > 1
        if transactional:
            db.execute('BEGIN')
        for item in items:
            before = db.total_changes
            cursor = db.execute(item['sql'])
            rows = [dict(r) for r in cursor.fetchall()]
            result.append({'success': True, 'results': rows, 'meta': {'rows_read': len(rows), 'rows_written': db.total_changes-before,
                'duration': 0, 'size_after': db.execute('PRAGMA page_count').fetchone()[0]*db.execute('PRAGMA page_size').fetchone()[0]}})
        if transactional:
            db.execute('COMMIT')
        print(json.dumps({'success': True, 'result': result}), flush=True)
    except Exception:
        if db.in_transaction:
            db.execute('ROLLBACK')
        print(json.dumps({'success': False, 'errors': [{'code': 7500, 'message': 'synthetic-secret-must-not-escape'}], 'result': []}), flush=True)
