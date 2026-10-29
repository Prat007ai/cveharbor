-- Additive migration for private customer environments and installed technologies.
-- Existing account and remediation records are untouched.
CREATE TABLE IF NOT EXISTS inventory_customers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_customers_user ON inventory_customers(user_id);
CREATE TABLE IF NOT EXISTS inventory_environments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'Production',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,customer_id,name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_environments_user ON inventory_environments(user_id,customer_id);
CREATE TABLE IF NOT EXISTS inventory_assets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  technology TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_user ON inventory_assets(user_id,environment_id);
