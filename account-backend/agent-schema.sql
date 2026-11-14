-- Additive Windows agent inventory. Agent observations never delete manual assets.
CREATE TABLE IF NOT EXISTS inventory_agent_enrollments (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 customer_id TEXT NOT NULL REFERENCES inventory_customers(id),
 environment_id TEXT NOT NULL REFERENCES inventory_environments(id), org_id TEXT NOT NULL DEFAULT '',
 expires_at INTEGER NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), consumed_at INTEGER,
 device_id TEXT REFERENCES inventory_agents(id), device_revision INTEGER
);
CREATE TABLE IF NOT EXISTS inventory_agents (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 customer_id TEXT NOT NULL REFERENCES inventory_customers(id),
 environment_id TEXT NOT NULL REFERENCES inventory_environments(id), org_id TEXT NOT NULL DEFAULT '',
 token_hash TEXT NOT NULL UNIQUE, state TEXT NOT NULL DEFAULT 'review' CHECK(state IN ('review','active','suspended','revoked')),
 hostname TEXT NOT NULL, agent_version TEXT NOT NULL, created_at INTEGER NOT NULL, last_seen INTEGER,
 last_sync INTEGER, last_sequence INTEGER NOT NULL DEFAULT 0, last_hash TEXT NOT NULL DEFAULT '',
 requested INTEGER NOT NULL DEFAULT 1, completed_request INTEGER NOT NULL DEFAULT 0,
 daily INTEGER NOT NULL DEFAULT 1 CHECK(daily IN (0,1)), roles TEXT NOT NULL DEFAULT '["Other"]',
 primary_ip TEXT NOT NULL DEFAULT '', primary_adapter TEXT NOT NULL DEFAULT '',
 accepted TEXT, pending TEXT, pending_hash TEXT NOT NULL DEFAULT '',
 invalid_since INTEGER NOT NULL DEFAULT 0, invalid_count INTEGER NOT NULL DEFAULT 0,
 revision INTEGER NOT NULL DEFAULT 0, reviewed_large_change INTEGER NOT NULL DEFAULT 0 CHECK(reviewed_large_change IN (0,1))
);
CREATE INDEX IF NOT EXISTS inventory_agents_scope ON inventory_agents(user_id,customer_id,environment_id);
CREATE TABLE IF NOT EXISTS inventory_agent_assets (
 asset_id TEXT PRIMARY KEY REFERENCES inventory_assets(id), device_id TEXT NOT NULL REFERENCES inventory_agents(id),
 product_key TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)), UNIQUE(device_id,product_key)
);
CREATE INDEX IF NOT EXISTS inventory_agent_assets_device ON inventory_agent_assets(device_id,active);
CREATE TABLE IF NOT EXISTS inventory_agent_history (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL REFERENCES inventory_agents(id),
 received_at INTEGER NOT NULL, sequence INTEGER NOT NULL, snapshot TEXT NOT NULL, changes TEXT NOT NULL,
 UNIQUE(device_id,sequence)
);
CREATE TABLE IF NOT EXISTS inventory_agent_contacts (
 user_id TEXT NOT NULL REFERENCES users(id), customer_id TEXT NOT NULL REFERENCES inventory_customers(id),
 email TEXT NOT NULL, PRIMARY KEY(user_id,customer_id,email)
);
CREATE TABLE IF NOT EXISTS inventory_agent_incidents (
 id TEXT PRIMARY KEY, device_id TEXT NOT NULL REFERENCES inventory_agents(id), reason TEXT NOT NULL,
 opened_at INTEGER NOT NULL, resolved_at INTEGER, resolved_by TEXT, resolution TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS inventory_agent_open_incident ON inventory_agent_incidents(device_id) WHERE resolved_at IS NULL;
CREATE TABLE IF NOT EXISTS inventory_agent_mail (
 incident_id TEXT NOT NULL REFERENCES inventory_agent_incidents(id), recipient TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','failed','unconfirmed','cancelled')),
 attempts INTEGER NOT NULL DEFAULT 0, not_before INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER,
 provider_id TEXT, PRIMARY KEY(incident_id,recipient)
);
CREATE TABLE IF NOT EXISTS inventory_agent_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT REFERENCES inventory_agents(id), actor TEXT NOT NULL,
 action TEXT NOT NULL, at INTEGER NOT NULL, authorized INTEGER NOT NULL CHECK(authorized=1)
);

CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_enrollments_insert BEFORE INSERT ON inventory_agent_enrollments WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_enrollments_update BEFORE UPDATE ON inventory_agent_enrollments WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_enrollments_delete BEFORE DELETE ON inventory_agent_enrollments WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agents_insert BEFORE INSERT ON inventory_agents WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agents_update BEFORE UPDATE ON inventory_agents WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agents_delete BEFORE DELETE ON inventory_agents WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_assets_insert BEFORE INSERT ON inventory_agent_assets WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_assets_update BEFORE UPDATE ON inventory_agent_assets WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_assets_delete BEFORE DELETE ON inventory_agent_assets WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_history_insert BEFORE INSERT ON inventory_agent_history WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_history_update BEFORE UPDATE ON inventory_agent_history WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_history_delete BEFORE DELETE ON inventory_agent_history WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_contacts_insert BEFORE INSERT ON inventory_agent_contacts WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_contacts_update BEFORE UPDATE ON inventory_agent_contacts WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_contacts_delete BEFORE DELETE ON inventory_agent_contacts WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_incidents_insert BEFORE INSERT ON inventory_agent_incidents WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_incidents_update BEFORE UPDATE ON inventory_agent_incidents WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_incidents_delete BEFORE DELETE ON inventory_agent_incidents WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_mail_insert BEFORE INSERT ON inventory_agent_mail WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_mail_update BEFORE UPDATE ON inventory_agent_mail WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_mail_delete BEFORE DELETE ON inventory_agent_mail WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_audit_insert BEFORE INSERT ON inventory_agent_audit WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_audit_update BEFORE UPDATE ON inventory_agent_audit WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_agent_audit_delete BEFORE DELETE ON inventory_agent_audit WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
