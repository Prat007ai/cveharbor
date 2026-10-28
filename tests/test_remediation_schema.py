"""Validate the production D1 assignment migration against SQLite semantics."""
import sqlite3
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = (ROOT / "account-backend" / "schema.sql").read_text()
MIGRATION = (ROOT / "account-backend" / "remediation-schema.sql").read_text()


class RemediationMigrationTest(unittest.TestCase):
    def test_fresh_schema_and_existing_database_migration(self):
        connection = sqlite3.connect(":memory:")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(SCHEMA)
        connection.executescript(MIGRATION)  # idempotent, existing installation
        connection.execute("INSERT INTO users(id,email) VALUES(?,?)", ("u1", "admin@example.org"))
        connection.execute(
            "INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES(?,?,?,?,?,?,?)",
            ("u1", "CVE-2026-12345", "Open", "", "", "", "2026-10-28"))
        connection.execute(
            "INSERT INTO remediation_assignments(user_id,cve_id,assignee_email,assigned_by,state,claimed_at) VALUES(?,?,?,?,?,?)",
            ("u1", "CVE-2026-12345", "engineer@example.org", "admin@example.org", "sent", 123))
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO remediation_assignments(user_id,cve_id,assignee_email,assigned_by,state,claimed_at) VALUES(?,?,?,?,?,?)",
                ("u1", "CVE-2026-99999", "engineer@example.org", "admin@example.org", "sent", 124))
        connection.execute("DELETE FROM remediations WHERE user_id=? AND cve_id=?", ("u1", "CVE-2026-12345"))
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM remediation_assignments").fetchone()[0], 0)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)
        connection.close()


if __name__ == "__main__":
    unittest.main()
