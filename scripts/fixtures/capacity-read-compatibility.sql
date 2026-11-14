-- Existing production table definitions needed by read-only workspace probes.
-- Isolated fictional load-test database only; no workflow writers are enabled.

CREATE TABLE IF NOT EXISTS remediation_finding_write_context (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL,cve_id TEXT NOT NULL,expected_record TEXT,expected_manual TEXT,
 expected_finding TEXT NOT NULL,expected_asset TEXT NOT NULL,
 PRIMARY KEY(user_id,asset_id,cve_id)
);

CREATE TABLE IF NOT EXISTS remediation_retired_records (
 user_id TEXT NOT NULL,record_id TEXT NOT NULL,canonical_id TEXT NOT NULL,
 PRIMARY KEY(user_id,record_id),
 FOREIGN KEY(user_id,canonical_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
