-- New status changes only; no historical updates are replayed as email.
CREATE VIEW IF NOT EXISTS remediation_status_participants AS
 SELECT user_id,cve_id,lower(recipient_email) recipient_email FROM remediation_assignment_requests WHERE delivery_status='sent' AND revoked_at IS NULL
 UNION SELECT user_id,cve_id,lower(requester_email) FROM remediation_assignment_requests WHERE delivery_status='sent' AND revoked_at IS NULL
 UNION SELECT a.user_id,a.cve_id,lower(f.recipient_email) FROM remediation_assignment_requests a JOIN remediation_assignment_fyi f ON f.assignment_id=a.id WHERE a.delivery_status='sent' AND a.revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS remediation_status_notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 change_id INTEGER NOT NULL REFERENCES remediation_status_changes(id) ON DELETE CASCADE,
 recipient_email TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','unconfirmed','cancelled')),
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),not_before INTEGER NOT NULL DEFAULT 0,
 claimed_at INTEGER,claim_token TEXT NOT NULL DEFAULT '',completed_at INTEGER,provider_id TEXT NOT NULL DEFAULT '',
 UNIQUE(change_id,recipient_email)
);
CREATE INDEX IF NOT EXISTS idx_status_notification_queue ON remediation_status_notifications(state,not_before,id);
-- Preserve progress/reminder behavior. Replace the incomplete requester/FYI-only
-- status notifications with a deduplicated set of every assignment participant.
DROP TRIGGER IF EXISTS review_status_progress;
CREATE TRIGGER review_status_progress AFTER INSERT ON remediation_status_changes
WHEN NEW.previous_status!=NEW.new_status
BEGIN
 UPDATE remediation_review_access SET last_progress_at=CAST(strftime('%s',NEW.changed_at) AS INTEGER),progress_version=progress_version+1
 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=unixepoch() WHERE kind='reminder' AND state='queued'
 AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 INSERT OR IGNORE INTO remediation_status_notifications(change_id,recipient_email)
 SELECT NEW.id,recipient_email FROM remediation_status_participants WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id;
END;
