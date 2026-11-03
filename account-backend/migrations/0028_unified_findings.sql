-- Additive links. Legacy CVE-only records and invitations retain their original keys.
CREATE TABLE IF NOT EXISTS remediation_finding_links (
 user_id TEXT NOT NULL, record_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,record_id), UNIQUE(user_id,asset_id,cve_id),
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE TRIGGER IF NOT EXISTS finding_link_owned BEFORE INSERT ON remediation_finding_links
BEGIN SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM inventory_assets a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE a.id=NEW.asset_id AND a.user_id=NEW.user_id) THEN RAISE(ABORT,'Asset ownership mismatch') END; END;
-- A finding-status row is a projection for existing dashboards and reporting.
CREATE TRIGGER IF NOT EXISTS linked_remediation_status AFTER UPDATE OF status ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.user_id=NEW.user_id AND l.record_id=NEW.cve_id)
BEGIN
 INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status,notes,updated_at)
 SELECT l.user_id,l.asset_id,l.cve_id,CASE NEW.status WHEN 'Open' THEN 'Needs Review' WHEN 'Investigating' THEN 'Fix in Progress' WHEN 'Remediated' THEN 'Fixed/Patched' ELSE NEW.status END,'',NEW.updated_at
 FROM remediation_finding_links l WHERE l.user_id=NEW.user_id AND l.record_id=NEW.cve_id
 ON CONFLICT(user_id,asset_id,cve_id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS delete_asset_remediation BEFORE DELETE ON inventory_assets
BEGIN DELETE FROM remediations WHERE user_id=OLD.user_id AND cve_id IN (SELECT record_id FROM remediation_finding_links WHERE user_id=OLD.user_id AND asset_id=OLD.id); END;
CREATE TABLE IF NOT EXISTS remediation_owner_comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,record_id TEXT NOT NULL,
 author_email TEXT NOT NULL,comment TEXT NOT NULL CHECK(length(trim(comment)) BETWEEN 10 AND 2000),created_at INTEGER NOT NULL,
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_owner_comments_scope ON remediation_owner_comments(user_id,record_id,id DESC);
CREATE TRIGGER IF NOT EXISTS owner_comment_progress AFTER INSERT ON remediation_owner_comments
BEGIN
 UPDATE remediation_review_access SET last_progress_at=NEW.created_at,progress_version=progress_version+1 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.record_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=NEW.created_at WHERE kind='reminder' AND state='queued' AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.record_id);
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'owner-comment:'||NEW.id,a.id,'progress',f.recipient_email,NEW.author_email,r.status,NEW.created_at
 FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id JOIN remediation_assignment_fyi f ON f.assignment_id=a.id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id
 WHERE a.user_id=NEW.user_id AND a.cve_id=NEW.record_id AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>NEW.created_at AND f.recipient_email!=NEW.author_email;

END;
