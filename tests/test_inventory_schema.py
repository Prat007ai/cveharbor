import unittest
import sqlite3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

class InventorySchemaTests(unittest.TestCase):
    def test_additive_migration_and_cascade(self):
        con=sqlite3.connect(':memory:')
        con.execute('PRAGMA foreign_keys=ON')
        con.executescript((ROOT/'account-backend/schema.sql').read_text())
        con.executescript((ROOT/'account-backend/inventory-schema.sql').read_text())
        con.execute('INSERT INTO users(id,email) VALUES(?,?)',('u1','one@example.org'))
        con.execute('INSERT INTO users(id,email) VALUES(?,?)',('u2','two@example.org'))
        con.execute('INSERT INTO inventory_customers(id,user_id,name) VALUES(?,?,?)',('c1','u1','Customer A'))
        con.execute('INSERT INTO inventory_environments(id,user_id,customer_id,name,kind) VALUES(?,?,?,?,?)',('e1','u1','c1','Production','Production'))
        con.execute('INSERT INTO inventory_assets(id,user_id,environment_id,name,asset_type,technology,version) VALUES(?,?,?,?,?,?,?)',('a1','u1','e1','Web Server','Server','PHP','8.4'))
        self.assertEqual(con.execute('SELECT version FROM inventory_assets').fetchone()[0],'8.4')
        con.execute('DELETE FROM inventory_customers WHERE id=? AND user_id=?',('c1','u1'))
        self.assertEqual(con.execute('SELECT COUNT(*) FROM inventory_assets').fetchone()[0],0)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM inventory_environments').fetchone()[0],0)
        self.assertEqual(con.execute('SELECT COUNT(*) FROM users').fetchone()[0],2)
        con.close()
