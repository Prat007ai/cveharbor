-- Additive private server network inventory; no changes to existing records.
CREATE TABLE inventory_server_network (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
 server_key TEXT NOT NULL CHECK(length(server_key) BETWEEN 1 AND 120),
 snapshot TEXT NOT NULL CHECK(json_valid(snapshot) AND length(snapshot)<=14000),
 primary_adapter TEXT NOT NULL DEFAULT '',
 primary_ip TEXT NOT NULL DEFAULT '',
 revision TEXT NOT NULL,
 PRIMARY KEY(user_id,environment_id,server_key)
);
CREATE TRIGGER recovery_hold_inventory_server_network_insert BEFORE INSERT ON "inventory_server_network" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_inventory_server_network_update BEFORE UPDATE ON "inventory_server_network" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_inventory_server_network_delete BEFORE DELETE ON "inventory_server_network" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
