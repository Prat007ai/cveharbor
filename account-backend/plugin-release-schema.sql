CREATE TABLE IF NOT EXISTS plugin_release_checks (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 installed_version TEXT NOT NULL,
 slug TEXT NOT NULL,
 release_status TEXT NOT NULL,
 latest_version TEXT NOT NULL DEFAULT '',
 update_status TEXT NOT NULL DEFAULT 'Unknown',
 release_source TEXT NOT NULL DEFAULT '',
 last_updated TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 checked_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,asset_id)
);
CREATE INDEX IF NOT EXISTS idx_plugin_release_checks_user ON plugin_release_checks(user_id);
