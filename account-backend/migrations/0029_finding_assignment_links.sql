-- Link an existing standalone assignment without changing invitation IDs or tokens.
CREATE TABLE IF NOT EXISTS remediation_link_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,record_id TEXT NOT NULL,
 asset_id TEXT NOT NULL,cve_id TEXT NOT NULL,retired_record_id TEXT NOT NULL DEFAULT '',
 previous_status TEXT NOT NULL,selected_status TEXT NOT NULL,snapshot_json TEXT NOT NULL,
 linked_by TEXT NOT NULL,linked_at TEXT NOT NULL,
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_link_audit ON remediation_link_audit(user_id,record_id,id);
CREATE TABLE IF NOT EXISTS remediation_retired_records (
 user_id TEXT NOT NULL,record_id TEXT NOT NULL,canonical_id TEXT NOT NULL,
 PRIMARY KEY(user_id,record_id),
 FOREIGN KEY(user_id,canonical_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
-- Reject an assignment writer that was already in flight against a retired placeholder.
CREATE TRIGGER IF NOT EXISTS prevent_retired_remediation_insert BEFORE INSERT ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_retired_records WHERE user_id=NEW.user_id AND record_id=NEW.cve_id)
BEGIN SELECT RAISE(ABORT,'This record was linked to an existing assignment; refresh before saving'); END;
-- A concurrent inline finding edit must not be overwritten while the user reviews a link.
CREATE TRIGGER IF NOT EXISTS validate_link_snapshot BEFORE INSERT ON remediation_link_audit
WHEN json_extract(NEW.snapshot_json,'$.finding.updated_at') IS NOT (SELECT updated_at FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
OR json_extract(NEW.snapshot_json,'$.finding.status') IS NOT (SELECT status FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
OR json_extract(NEW.snapshot_json,'$.finding.notes') IS NOT (SELECT notes FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
BEGIN SELECT RAISE(ABORT,'The finding changed; review the link again'); END;
