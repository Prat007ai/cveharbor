-- Additive capacity indexes and revision tracking. No existing rows are changed.
CREATE TABLE IF NOT EXISTS inventory_capacity_schema(version INTEGER PRIMARY KEY CHECK(version=1));
CREATE TABLE IF NOT EXISTS inventory_capacity_revisions(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, revision INTEGER NOT NULL DEFAULT 0, software_count INTEGER NOT NULL DEFAULT 0 CHECK(software_count>=0));
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_capacity_schema_insert BEFORE INSERT ON "inventory_capacity_schema" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_capacity_schema_update BEFORE UPDATE ON "inventory_capacity_schema" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_capacity_schema_delete BEFORE DELETE ON "inventory_capacity_schema" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_capacity_revisions_insert BEFORE INSERT ON "inventory_capacity_revisions" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_capacity_revisions_update BEFORE UPDATE ON "inventory_capacity_revisions" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_inventory_capacity_revisions_delete BEFORE DELETE ON "inventory_capacity_revisions" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
INSERT OR IGNORE INTO inventory_capacity_revisions(user_id,revision,software_count) SELECT user_id,0,COUNT(*) FROM inventory_assets GROUP BY user_id;
CREATE TRIGGER IF NOT EXISTS capacity_asset_limit BEFORE INSERT ON inventory_assets
WHEN COALESCE((SELECT software_count FROM inventory_capacity_revisions WHERE user_id=NEW.user_id),0)>=50000
BEGIN SELECT RAISE(ABORT,'Inventory limit reached'); END;
CREATE INDEX IF NOT EXISTS idx_capacity_inventory_customers ON inventory_customers(user_id,id);
CREATE TRIGGER IF NOT EXISTS capacity_inventory_customers_insert AFTER INSERT ON inventory_customers
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_customers_update AFTER UPDATE ON inventory_customers
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_customers_delete AFTER DELETE ON inventory_customers
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_inventory_environments ON inventory_environments(user_id,id);
CREATE TRIGGER IF NOT EXISTS capacity_inventory_environments_insert AFTER INSERT ON inventory_environments
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_environments_update AFTER UPDATE ON inventory_environments
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_environments_delete AFTER DELETE ON inventory_environments
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_inventory_assets ON inventory_assets(user_id,id);
CREATE TRIGGER IF NOT EXISTS capacity_inventory_assets_insert AFTER INSERT ON inventory_assets
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision,software_count) VALUES(NEW.user_id,1,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1,software_count=software_count+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_assets_update AFTER UPDATE ON inventory_assets
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_assets_delete AFTER DELETE ON inventory_assets
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 UPDATE inventory_capacity_revisions SET revision=revision+1,software_count=software_count-1 WHERE user_id=OLD.user_id;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_customer_finding_statuses ON customer_finding_statuses(user_id,asset_id,cve_id);
CREATE TRIGGER IF NOT EXISTS capacity_customer_finding_statuses_insert AFTER INSERT ON customer_finding_statuses
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_customer_finding_statuses_update AFTER UPDATE ON customer_finding_statuses
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_customer_finding_statuses_delete AFTER DELETE ON customer_finding_statuses
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_customer_finding_ticket_history ON customer_finding_ticket_history(user_id,asset_id,cve_id,ticket_number);
CREATE TRIGGER IF NOT EXISTS capacity_customer_finding_ticket_history_insert AFTER INSERT ON customer_finding_ticket_history
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_customer_finding_ticket_history_update AFTER UPDATE ON customer_finding_ticket_history
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_customer_finding_ticket_history_delete AFTER DELETE ON customer_finding_ticket_history
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_plugin_source_mappings ON plugin_source_mappings(user_id,asset_id);
CREATE TRIGGER IF NOT EXISTS capacity_plugin_source_mappings_insert AFTER INSERT ON plugin_source_mappings
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_source_mappings_update AFTER UPDATE ON plugin_source_mappings
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_source_mappings_delete AFTER DELETE ON plugin_source_mappings
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_plugin_installation_status ON plugin_installation_status(user_id,asset_id);
CREATE TRIGGER IF NOT EXISTS capacity_plugin_installation_status_insert AFTER INSERT ON plugin_installation_status
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_installation_status_update AFTER UPDATE ON plugin_installation_status
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_installation_status_delete AFTER DELETE ON plugin_installation_status
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_plugin_monitor_checks ON plugin_monitor_checks(user_id,asset_id);
CREATE TRIGGER IF NOT EXISTS capacity_plugin_monitor_checks_insert AFTER INSERT ON plugin_monitor_checks
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_monitor_checks_update AFTER UPDATE ON plugin_monitor_checks
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_monitor_checks_delete AFTER DELETE ON plugin_monitor_checks
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_plugin_release_checks ON plugin_release_checks(user_id,asset_id);
CREATE TRIGGER IF NOT EXISTS capacity_plugin_release_checks_insert AFTER INSERT ON plugin_release_checks
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_release_checks_update AFTER UPDATE ON plugin_release_checks
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_plugin_release_checks_delete AFTER DELETE ON plugin_release_checks
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_inventory_server_network ON inventory_server_network(user_id,environment_id,server_key);
CREATE TRIGGER IF NOT EXISTS capacity_inventory_server_network_insert AFTER INSERT ON inventory_server_network
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_server_network_update AFTER UPDATE ON inventory_server_network
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_server_network_delete AFTER DELETE ON inventory_server_network
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_inventory_packages ON inventory_packages(user_id,id);
CREATE TRIGGER IF NOT EXISTS capacity_inventory_packages_insert AFTER INSERT ON inventory_packages
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_packages_update AFTER UPDATE ON inventory_packages
WHEN EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(NEW.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE TRIGGER IF NOT EXISTS capacity_inventory_packages_delete AFTER DELETE ON inventory_packages
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id)
BEGIN
 INSERT INTO inventory_capacity_revisions(user_id,revision) VALUES(OLD.user_id,1)
 ON CONFLICT(user_id) DO UPDATE SET revision=revision+1;
END;
CREATE INDEX IF NOT EXISTS idx_capacity_asset_environment ON inventory_assets(user_id,environment_id,id);
CREATE INDEX IF NOT EXISTS idx_capacity_environment_customer ON inventory_environments(user_id,customer_id,id);
CREATE INDEX IF NOT EXISTS idx_capacity_package_environment ON inventory_packages(user_id,environment_id,id);
INSERT OR IGNORE INTO inventory_capacity_schema(version) VALUES(1);
