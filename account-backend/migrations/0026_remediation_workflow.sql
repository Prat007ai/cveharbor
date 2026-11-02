-- Additive: no backfill, invented timestamps or changes to existing remediation records.
CREATE TABLE IF NOT EXISTS remediation_record_metadata (
 user_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 assigned_severity TEXT NOT NULL DEFAULT '' CHECK(assigned_severity IN ('','critical','high','medium','low','info')),
 assessed_by TEXT NOT NULL DEFAULT '',
 assessed_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(user_id,cve_id),
 FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS remediation_assignment_metadata (
 assignment_id TEXT PRIMARY KEY REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
 assigned_severity TEXT NOT NULL DEFAULT '' CHECK(assigned_severity IN ('','critical','high','medium','low','info'))
);
CREATE TABLE IF NOT EXISTS remediation_status_changes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 previous_status TEXT NOT NULL,
 new_status TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 1000),
 changed_by TEXT NOT NULL,
 changed_at TEXT NOT NULL,
 FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_status_changes_scope ON remediation_status_changes(user_id,cve_id,id DESC);
-- Transaction-scoped write context, inserted and removed in the same D1 batch.
CREATE TABLE IF NOT EXISTS remediation_change_context (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 actor_email TEXT NOT NULL,
 changed_at TEXT NOT NULL,
 expected_updated TEXT NOT NULL,
 PRIMARY KEY(user_id,cve_id)
);
CREATE TRIGGER IF NOT EXISTS remediation_status_reason_required BEFORE UPDATE OF status ON remediations
WHEN OLD.status!=NEW.status
BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM remediation_change_context c WHERE c.user_id=OLD.user_id AND c.cve_id=OLD.cve_id AND length(trim(c.reason)) BETWEEN 1 AND 1000 AND length(c.actor_email)>0) THEN RAISE(ABORT,'Remediation status change reason required') END;
END;
CREATE TRIGGER IF NOT EXISTS remediation_update_conflict BEFORE UPDATE ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_change_context c WHERE c.user_id=OLD.user_id AND c.cve_id=OLD.cve_id AND c.expected_updated!=OLD.updated_at)
BEGIN SELECT RAISE(ABORT,'Remediation record changed; reload before saving'); END;
CREATE TRIGGER IF NOT EXISTS remediation_status_changed AFTER UPDATE OF status ON remediations
WHEN OLD.status!=NEW.status
BEGIN
 INSERT INTO remediation_status_changes(user_id,cve_id,previous_status,new_status,reason,changed_by,changed_at)
 SELECT NEW.user_id,NEW.cve_id,OLD.status,NEW.status,c.reason,c.actor_email,c.changed_at FROM remediation_change_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id;
END;
CREATE TRIGGER IF NOT EXISTS remediation_insert_conflict BEFORE INSERT ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_change_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id AND c.expected_updated!='')
 AND NOT EXISTS(SELECT 1 FROM remediations r WHERE r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id)
BEGIN SELECT RAISE(ABORT,'Remediation record changed; reload before saving'); END;
