"""Remove only an empty local development monitoring schema. Never a production tool."""
import argparse
import sqlite3
from pathlib import Path
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('database',type=Path)
parser.add_argument('--confirm-empty-development',action='store_true',required=True)
args=parser.parse_args()
if not args.database.is_file():raise SystemExit('Specify an existing local development SQLite file')
connection=sqlite3.connect(args.database)
tables=[row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'lifecycle_monitor_%' OR name='lifecycle_watch_settings')")]
if any(connection.execute('SELECT COUNT(*) FROM "'+table+'"').fetchone()[0] for table in tables):raise SystemExit('Refusing rollback: monitoring tables contain data. Disable runtime flags and retain history instead.')
connection.execute('PRAGMA foreign_keys=OFF')
with connection:
    for table in tables:connection.execute('DROP TABLE "'+table+'"')
connection.close()
print('Empty development monitoring schema removed; existing lifecycle watches/preferences remain.')
