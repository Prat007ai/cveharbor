-- Additive. New assignments opt into reviewer access; existing invitations are not backfilled.
CREATE TABLE IF NOT EXISTS remediation_review_access (
 assignment_id TEXT PRIMARY KEY REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL,
 interval_seconds INTEGER CHECK(interval_seconds IN (86400,172800)),
 last_progress_at INTEGER NOT NULL,
 progress_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_review_progress_due ON remediation_review_access(last_progress_at,expires_at);
CREATE TABLE IF NOT EXISTS remediation_review_challenges (
 id TEXT PRIMARY KEY,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_review_challenge_scope ON remediation_review_challenges(assignment_id,created_at);
CREATE TABLE IF NOT EXISTS remediation_review_sessions (
 token_hash TEXT PRIMARY KEY,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_session_scope ON remediation_review_sessions(assignment_id,expires_at);
CREATE TABLE IF NOT EXISTS remediation_review_activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 author_email TEXT NOT NULL,
 previous_status TEXT NOT NULL,
 new_status TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT '' CHECK(length(reason)<=1000),
 comment TEXT NOT NULL DEFAULT '' CHECK(length(comment)<=2000),
 created_at INTEGER NOT NULL,
 FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_review_activity_scope ON remediation_review_activity(user_id,cve_id,id DESC);
CREATE INDEX IF NOT EXISTS idx_review_activity_assignment ON remediation_review_activity(assignment_id,id DESC);
CREATE TABLE IF NOT EXISTS remediation_review_notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_key TEXT NOT NULL,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('progress','reminder')),
 cycle_version INTEGER,
 recipient_email TEXT NOT NULL,
 actor_email TEXT NOT NULL DEFAULT '',
 status_snapshot TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','unconfirmed','cancelled')),
 not_before INTEGER NOT NULL DEFAULT 0,
 claimed_at INTEGER,
 claim_token TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0,
 completed_at INTEGER,
 provider_id TEXT NOT NULL DEFAULT '',
 UNIQUE(event_key,recipient_email)
);
CREATE INDEX IF NOT EXISTS idx_review_notification_queue ON remediation_review_notifications(state,not_before,id);
CREATE TRIGGER IF NOT EXISTS review_assignment_sent AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='sent' AND OLD.delivery_status!='sent'
BEGIN UPDATE remediation_review_access SET last_progress_at=NEW.sent_at WHERE assignment_id=NEW.id; END;
-- Any recorded status change is progress. Unchanged saves, acknowledgement and page views do not count.
CREATE TRIGGER IF NOT EXISTS review_status_progress AFTER INSERT ON remediation_status_changes
BEGIN
 UPDATE remediation_review_access SET last_progress_at=CAST(strftime('%s',NEW.changed_at) AS INTEGER),progress_version=progress_version+1
 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=unixepoch() WHERE kind='reminder' AND state='queued'
 AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'status:'||NEW.id,a.id,'progress',a.requester_email,NEW.changed_by,NEW.new_status,CAST(strftime('%s',NEW.changed_at) AS INTEGER)
 FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id
 WHERE a.user_id=NEW.user_id AND a.cve_id=NEW.cve_id AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>unixepoch() AND a.requester_email!=NEW.changed_by;
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'status:'||NEW.id,a.id,'progress',f.recipient_email,NEW.changed_by,NEW.new_status,CAST(strftime('%s',NEW.changed_at) AS INTEGER)
 FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id JOIN remediation_assignment_fyi f ON f.assignment_id=a.id
 WHERE a.user_id=NEW.user_id AND a.cve_id=NEW.cve_id AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>unixepoch() AND f.recipient_email!=NEW.changed_by;
END;
-- A comment accompanying a status change is already covered by the status trigger.
CREATE TRIGGER IF NOT EXISTS review_comment_progress AFTER INSERT ON remediation_review_activity
WHEN NEW.previous_status=NEW.new_status
BEGIN
 UPDATE remediation_review_access SET last_progress_at=NEW.created_at,progress_version=progress_version+1
 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=unixepoch() WHERE kind='reminder' AND state='queued'
 AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'comment:'||NEW.id,a.id,'progress',a.requester_email,NEW.author_email,NEW.new_status,NEW.created_at
 FROM remediation_assignment_requests a WHERE a.id=NEW.assignment_id AND a.requester_email!=NEW.author_email;
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'comment:'||NEW.id,NEW.assignment_id,'progress',f.recipient_email,NEW.author_email,NEW.new_status,NEW.created_at
 FROM remediation_assignment_fyi f WHERE f.assignment_id=NEW.assignment_id AND f.recipient_email!=NEW.author_email;
END;
CREATE TRIGGER IF NOT EXISTS review_assignment_revoked AFTER UPDATE OF revoked_at ON remediation_assignment_requests
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
 DELETE FROM remediation_review_sessions WHERE assignment_id=NEW.id;
 DELETE FROM remediation_review_challenges WHERE assignment_id=NEW.id;
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=NEW.revoked_at WHERE assignment_id=NEW.id AND state='queued';
END;
-- Transaction-scoped context: activity is created only by an update that actually succeeds.
CREATE TABLE IF NOT EXISTS remediation_review_write_context (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 assignment_id TEXT NOT NULL,
 author_email TEXT NOT NULL,
 reason TEXT NOT NULL,
 comment TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,cve_id)
);
CREATE TRIGGER IF NOT EXISTS review_record_updated AFTER UPDATE OF updated_at ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_review_write_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id)
BEGIN
 INSERT INTO remediation_review_activity(assignment_id,user_id,cve_id,author_email,previous_status,new_status,reason,comment,created_at)
 SELECT c.assignment_id,NEW.user_id,NEW.cve_id,c.author_email,OLD.status,NEW.status,c.reason,c.comment,c.created_at FROM remediation_review_write_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id;
END;
