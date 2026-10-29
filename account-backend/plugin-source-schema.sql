-- Additive, account-private plugin source mapping. Existing inventory remains unchanged.
CREATE TABLE IF NOT EXISTS plugin_source_mappings (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 vendor_url TEXT NOT NULL DEFAULT '',
 release_url TEXT NOT NULL DEFAULT '',
 advisory_url TEXT NOT NULL DEFAULT '',
 plugin_slug TEXT NOT NULL DEFAULT '',
 verification TEXT NOT NULL DEFAULT 'Needs Review',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,asset_id)
);
CREATE INDEX IF NOT EXISTS idx_plugin_source_mappings_user ON plugin_source_mappings(user_id);

CREATE TABLE IF NOT EXISTS plugin_installation_status (user_id TEXT NOT NULL, asset_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('Active','Inactive','Network active','Inactive, listing closed')), PRIMARY KEY(user_id,asset_id));
