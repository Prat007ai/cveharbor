-- Additive private plugin scan cache and history; no existing records modified.
CREATE TABLE IF NOT EXISTS plugin_monitor_checks (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 installed_version TEXT NOT NULL,
 plugin_slug TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('checked','unverified','unavailable')),
 reason TEXT NOT NULL DEFAULT '',
 findings_json TEXT NOT NULL DEFAULT '[]',
 checked_at INTEGER NOT NULL,
 next_check_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,asset_id)
);
CREATE INDEX IF NOT EXISTS idx_plugin_monitor_due ON plugin_monitor_checks(next_check_at);
CREATE TABLE IF NOT EXISTS plugin_monitor_history (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 checked_at INTEGER NOT NULL,
 status TEXT NOT NULL,
 finding_count INTEGER NOT NULL,
 reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_plugin_monitor_history_asset ON plugin_monitor_history(user_id,asset_id,checked_at);
