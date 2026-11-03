"""Local-only SQL engine for D1 contract tests; counters are synthetic, not billing estimates."""
import json
import sqlite3
import sys

db = sqlite3.connect(':memory:', isolation_level=None)
db.row_factory = sqlite3.Row
db.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 5)
db.execute('PRAGMA foreign_keys=ON')
for line in sys.stdin:
    message = json.loads(line)
    result = []
    try:
        if 'batch' in message:
            db.execute('BEGIN')
        for item in message.get('batch', [message]):
            before = db.total_changes
            cursor = db.execute(item['sql'])
            rows = [dict(r) for r in cursor.fetchall()]
            result.append({'success': True, 'results': rows, 'meta': {'rows_read': len(rows), 'rows_written': db.total_changes-before,
                'duration': 0, 'size_after': db.execute('PRAGMA page_count').fetchone()[0]*db.execute('PRAGMA page_size').fetchone()[0]}})
        if 'batch' in message:
            db.execute('COMMIT')
        print(json.dumps({'success': True, 'result': result}), flush=True)
    except Exception:
        if db.in_transaction:
            db.execute('ROLLBACK')
        print(json.dumps({'success': False, 'errors': [{'code': 7500, 'message': 'synthetic-secret-must-not-escape'}], 'result': []}), flush=True)
