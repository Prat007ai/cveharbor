-- Cloudflare D1 migration for CVEHarbor remediation assignments.
-- Apply to the EXISTING cveharbor-accounts database after a D1 backup.
-- The existing remediations table is already present. Do not recreate it.
CREATE TABLE IF NOT EXISTS remediation_assignments (
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  assignee_email TEXT NOT NULL,
  assigned_by TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('sending','sent','failed')),
  claimed_at INTEGER NOT NULL,
  last_sent_at INTEGER,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,cve_id),
  FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_assignment_assignee ON remediation_assignments(assignee_email,state);
