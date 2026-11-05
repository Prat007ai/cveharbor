-- INACTIVE PROPOSAL. Not in either automatic migration directory.
-- No backfill, re-keying, ownership changes, or changes to baseline step 209.
PRAGMA foreign_keys=ON;
CREATE TABLE remediation_customer_scopes (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 record_id TEXT NOT NULL, cve_id TEXT NOT NULL,
 customer_id TEXT NOT NULL REFERENCES inventory_customers(id) DEFERRABLE INITIALLY DEFERRED,
 environment_id TEXT REFERENCES inventory_environments(id) DEFERRABLE INITIALLY DEFERRED,
 associated_by TEXT NOT NULL, associated_at TEXT NOT NULL,
 PRIMARY KEY(user_id,record_id),
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX remediation_customer_context_unique ON remediation_customer_scopes(user_id,customer_id,ifnull(environment_id,''),cve_id);
CREATE TRIGGER remediation_customer_owned BEFORE INSERT ON remediation_customer_scopes BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM inventory_customers c WHERE c.id=NEW.customer_id AND c.user_id=NEW.user_id)
 OR (NEW.environment_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM inventory_environments e WHERE e.id=NEW.environment_id AND e.user_id=NEW.user_id AND e.customer_id=NEW.customer_id))
 OR EXISTS(SELECT 1 FROM remediation_finding_links WHERE user_id=NEW.user_id AND record_id=NEW.record_id)
 OR EXISTS(SELECT 1 FROM remediation_retired_records WHERE user_id=NEW.user_id AND record_id=NEW.record_id)
 OR EXISTS(SELECT 1 FROM remediation_customer_scopes s WHERE s.user_id=NEW.user_id AND (s.record_id=NEW.record_id OR (s.customer_id=NEW.customer_id AND ifnull(s.environment_id,'')=ifnull(NEW.environment_id,'') AND s.cve_id=NEW.cve_id)))
 OR NEW.cve_id!=upper(NEW.cve_id) OR substr(NEW.record_id,1,length(NEW.cve_id))!=NEW.cve_id
 THEN RAISE(ABORT,'Customer remediation context mismatch') END;
END;
CREATE TRIGGER remediation_customer_scope_immutable BEFORE UPDATE ON remediation_customer_scopes BEGIN SELECT RAISE(ABORT,'Customer remediation scope is immutable'); END;
CREATE TRIGGER remediation_customer_scope_retained BEFORE DELETE ON remediation_customer_scopes
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN SELECT RAISE(ABORT,'Customer remediation association must be retained'); END;
CREATE TRIGGER remediation_customer_history BEFORE DELETE ON remediations
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id) AND EXISTS(SELECT 1 FROM remediation_customer_scopes WHERE user_id=OLD.user_id AND record_id=OLD.cve_id)
BEGIN SELECT RAISE(ABORT,'Customer remediation history must be retained'); END;
CREATE TRIGGER remediation_customer_asset_exclusive BEFORE INSERT ON remediation_finding_links
WHEN EXISTS(SELECT 1 FROM remediation_customer_scopes WHERE user_id=NEW.user_id AND record_id=NEW.record_id)
BEGIN SELECT RAISE(ABORT,'Customer remediation cannot be silently reassigned'); END;
CREATE TRIGGER remediation_customer_environment_stable BEFORE UPDATE OF customer_id,user_id ON inventory_environments
WHEN EXISTS(SELECT 1 FROM remediation_customer_scopes WHERE environment_id=OLD.id) AND (NEW.customer_id!=OLD.customer_id OR NEW.user_id!=OLD.user_id)
BEGIN SELECT RAISE(ABORT,'Customer remediation environment must be retained'); END;
CREATE TRIGGER remediation_customer_owner_stable BEFORE UPDATE OF user_id ON inventory_customers
WHEN NEW.user_id!=OLD.user_id AND EXISTS(SELECT 1 FROM remediation_customer_scopes WHERE customer_id=OLD.id)
BEGIN SELECT RAISE(ABORT,'Customer remediation owner must be retained'); END;
CREATE TABLE remediation_customer_ticket_history (
 user_id TEXT NOT NULL,record_id TEXT NOT NULL,ticket_number TEXT NOT NULL CHECK(length(trim(ticket_number)) BETWEEN 1 AND 64),created_at TEXT NOT NULL,
 PRIMARY KEY(user_id,record_id,ticket_number),
 FOREIGN KEY(user_id,record_id) REFERENCES remediation_customer_scopes(user_id,record_id) ON DELETE CASCADE
);
CREATE TRIGGER remediation_customer_ticket_immutable BEFORE UPDATE ON remediation_customer_ticket_history BEGIN SELECT RAISE(ABORT,'Ticket history is append only'); END;
CREATE TRIGGER remediation_customer_ticket_retained BEFORE DELETE ON remediation_customer_ticket_history
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id) BEGIN SELECT RAISE(ABORT,'Ticket history must be retained'); END;
