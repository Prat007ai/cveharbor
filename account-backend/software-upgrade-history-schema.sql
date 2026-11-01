-- Additive setup. Run manually in the CVEHarbor accounts D1 database.
-- No existing versions, findings, statuses or customer records are changed.
-- Capture starts when this trigger is installed; no past dates are inferred.
CREATE TABLE IF NOT EXISTS inventory_software_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
  asset_name TEXT NOT NULL,
  previous_technology TEXT NOT NULL,
  technology TEXT NOT NULL,
  previous_version TEXT NOT NULL,
  version TEXT NOT NULL,
  recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_inventory_software_history_scope
  ON inventory_software_history(user_id,customer_id,environment_id,id DESC);
CREATE TRIGGER IF NOT EXISTS inventory_software_version_changed
AFTER UPDATE OF version,technology ON inventory_assets
WHEN OLD.version IS NOT NEW.version OR OLD.technology IS NOT NEW.technology
BEGIN
  INSERT INTO inventory_software_history
    (user_id,customer_id,environment_id,asset_id,asset_name,previous_technology,technology,previous_version,version)
  SELECT NEW.user_id,e.customer_id,NEW.environment_id,NEW.id,NEW.name,
    OLD.technology,NEW.technology,OLD.version,NEW.version
  FROM inventory_environments e
  WHERE e.id=NEW.environment_id AND e.user_id=NEW.user_id;
END;
