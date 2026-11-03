"""Local D1-limit/read-only harness. No credentials, sockets or remote operations."""
import json
import sqlite3
import sys

db = sqlite3.connect(':memory:', isolation_level=None)
db.row_factory = sqlite3.Row
db.setlimit(sqlite3.SQLITE_LIMIT_COMPOUND_SELECT, 5)
db.execute('PRAGMA foreign_keys=ON')
locked = False

def readonly(action, one, two, _database, _trigger):
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_PRAGMA and one in ('table_info', 'index_list', 'index_info', 'quick_check', 'foreign_key_check', 'page_count', 'page_size'):
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY

for line in sys.stdin:
    message = json.loads(line)
    try:
        if 'setup' in message:
            if locked:
                raise ValueError('Setup only once')
            db.executescript(message['setup'])
            db.set_authorizer(readonly)
            locked = True
            print(json.dumps({'success': True, 'result': []}), flush=True)
            continue
        if not locked:
            raise ValueError('Read-only setup required')
        cursor = db.execute(message['sql'])
        rows = [dict(r) for r in cursor.fetchall()]
        size = db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]
        print(json.dumps({'success': True, 'result': [{'success': True, 'results': rows,
            'meta': {'rows_read': len(rows), 'rows_written': 0, 'size_after': size, 'duration': 0}}]}), flush=True)
    except Exception:
        print(json.dumps({'success': False, 'errors': [{'code': 7500, 'message': 'synthetic-error-must-not-escape'}], 'result': []}), flush=True)
