-- Optional FYI observers; never receive or share the assignee's bearer token.
CREATE TABLE IF NOT EXISTS remediation_assignment_fyi (
 assignment_id TEXT NOT NULL REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
 recipient_email TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(assignment_id,recipient_email)
);
CREATE TABLE IF NOT EXISTS remediation_assignment_notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id TEXT NOT NULL,
 recipient_email TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('assigned','acknowledged')),
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','unconfirmed','cancelled')),
 created_at INTEGER NOT NULL,
 not_before INTEGER NOT NULL DEFAULT 0,
 claimed_at INTEGER,
 claim_token TEXT NOT NULL DEFAULT '',
 completed_at INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0,
 provider_id TEXT NOT NULL DEFAULT '',
 remediation_status TEXT NOT NULL DEFAULT '',
 UNIQUE(assignment_id,recipient_email,kind),
 FOREIGN KEY(assignment_id,recipient_email) REFERENCES remediation_assignment_fyi(assignment_id,recipient_email) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assignment_notification_queue ON remediation_assignment_notifications(state,not_before,id);
CREATE TRIGGER IF NOT EXISTS assignment_fyi_sent AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='sent' AND OLD.delivery_status!='sent' AND NEW.revoked_at IS NULL
BEGIN
 INSERT OR IGNORE INTO remediation_assignment_notifications(assignment_id,recipient_email,kind,created_at,remediation_status)
 SELECT NEW.id,f.recipient_email,'assigned',NEW.sent_at,r.status FROM remediation_assignment_fyi f JOIN remediations r ON r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id WHERE f.assignment_id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS assignment_fyi_acknowledged AFTER UPDATE OF acknowledged_at ON remediation_assignment_requests
WHEN OLD.acknowledged_at IS NULL AND NEW.acknowledged_at IS NOT NULL AND NEW.revoked_at IS NULL
BEGIN
 INSERT OR IGNORE INTO remediation_assignment_notifications(assignment_id,recipient_email,kind,created_at,remediation_status)
 SELECT NEW.id,f.recipient_email,'acknowledged',NEW.acknowledged_at,r.status FROM remediation_assignment_fyi f JOIN remediations r ON r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id WHERE f.assignment_id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS assignment_fyi_revoked AFTER UPDATE OF revoked_at ON remediation_assignment_requests
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
 UPDATE remediation_assignment_notifications SET state='cancelled',completed_at=NEW.revoked_at WHERE assignment_id=NEW.id AND state IN ('queued','unconfirmed');
END;
