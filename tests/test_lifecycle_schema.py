import unittest,sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class LifecycleSchemaTest(unittest.TestCase):
 def test_migration_is_additive_and_keeps_optin_off(self):
  db=sqlite3.connect(':memory:')
  db.execute('PRAGMA foreign_keys=ON')
  db.executescript((ROOT/'account-backend/schema.sql').read_text())
  db.executescript((ROOT/'account-backend/lifecycle-schema.sql').read_text())
  db.execute('INSERT INTO users(id,email) VALUES(?,?)',('test-user','user@example.org'))
  db.execute('INSERT INTO lifecycle_watches(user_id,id,product,slug,cycle,created_at) VALUES(?,?,?,?,?,?)',('test-user','watch1','SQL Server','mssqlserver','2022',1))
  self.assertEqual(db.execute('SELECT COUNT(*) FROM lifecycle_preferences').fetchone()[0],0)
  db.execute('DELETE FROM users WHERE id=?',('test-user',))
  self.assertEqual(db.execute('SELECT COUNT(*) FROM lifecycle_watches').fetchone()[0],0)
  db.close()
