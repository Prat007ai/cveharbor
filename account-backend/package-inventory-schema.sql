-- Additive account-scoped package inventory for Linux environments.
CREATE TABLE IF NOT EXISTS inventory_packages (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
 asset_name TEXT NOT NULL,
 distribution TEXT NOT NULL,
 release TEXT NOT NULL,
 architecture TEXT NOT NULL,
 package_name TEXT NOT NULL,
 source_package TEXT NOT NULL,
 installed_version TEXT NOT NULL,
 collected_at TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id,environment_id,asset_name,architecture,package_name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_packages_env ON inventory_packages(user_id,environment_id);
