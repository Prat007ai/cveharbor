-- Additive, repeatable; preserve legacy assignment records and remediation statuses.
CREATE TABLE IF NOT EXISTS remediation_assignment_requests (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  recipient_email TEXT NOT NULL,
  requester_email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),
  delivery_status TEXT NOT NULL CHECK(delivery_status IN ('sending','sent','failed')),
  public_advisory_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  sent_at INTEGER,
  acknowledged_at INTEGER,
  revoked_at INTEGER,
  provider_id TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assignment_request_scope ON remediation_assignment_requests(user_id,cve_id,seq DESC);
CREATE INDEX IF NOT EXISTS idx_assignment_request_recipient ON remediation_assignment_requests(user_id,cve_id,recipient_email,seq DESC);
CREATE TABLE IF NOT EXISTS remediation_assignment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  assignment_id TEXT NOT NULL REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK(event IN ('created','sent','delivery_failed','acknowledged','revoked')),
  occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assignment_event_request ON remediation_assignment_events(assignment_id,id);
CREATE TRIGGER IF NOT EXISTS assignment_request_created AFTER INSERT ON remediation_assignment_requests
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'created',NEW.created_at); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_sent AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='sent' AND OLD.delivery_status!='sent'
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'sent',NEW.sent_at); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_failed AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='failed' AND OLD.delivery_status!='failed'
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'delivery_failed',unixepoch()); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_acknowledged AFTER UPDATE OF acknowledged_at ON remediation_assignment_requests
WHEN OLD.acknowledged_at IS NULL AND NEW.acknowledged_at IS NOT NULL
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'acknowledged',NEW.acknowledged_at); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_revoked AFTER UPDATE OF revoked_at ON remediation_assignment_requests
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'revoked',NEW.revoked_at); END;
