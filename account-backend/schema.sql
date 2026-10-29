PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS login_challenges(id TEXT PRIMARY KEY,email TEXT NOT NULL,token_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER,created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_challenges_email ON login_challenges(email,created_at);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,token_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS user_stack(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,technology TEXT NOT NULL,product_version TEXT NOT NULL DEFAULT '',PRIMARY KEY(user_id,technology));
CREATE TABLE IF NOT EXISTS remediations(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,cve_id TEXT NOT NULL,status TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',due TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL,PRIMARY KEY(user_id,cve_id));
CREATE TABLE IF NOT EXISTS alert_preferences(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,enabled INTEGER NOT NULL DEFAULT 0,severity TEXT NOT NULL DEFAULT 'critical',frequency TEXT NOT NULL DEFAULT 'daily',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS auth_rate_limits(key TEXT PRIMARY KEY,window_start INTEGER NOT NULL,count INTEGER NOT NULL);

-- CVEHarbor scheduled email digest migration.
-- Apply once to the existing cveharbor-accounts D1 database before enabling alert delivery.
-- New opt-in is required; previously saved "future" alert preferences do not silently enable email.
CREATE TABLE IF NOT EXISTS alert_optins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  consented_at INTEGER NOT NULL,
  unsubscribe_token TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS alert_delivery_items (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  advisory_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  delivered_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_items_user ON alert_delivery_items(user_id);
CREATE TABLE IF NOT EXISTS alert_digest_runs (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  slot TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sending','sent','empty','failed')),
  claimed_at INTEGER NOT NULL,
  completed_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 1,
  item_count INTEGER NOT NULL DEFAULT 0,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,slot)
);
CREATE INDEX IF NOT EXISTS idx_alert_runs_user_date ON alert_digest_runs(user_id,completed_at);

-- Cloudflare D1 migration for CVEHarbor remediation assignments.
-- Apply to the EXISTING cveharbor-accounts database after a D1 backup.
-- The existing remediations table is already present. Do not recreate it.
CREATE TABLE IF NOT EXISTS remediation_assignments (
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  assignee_email TEXT NOT NULL,
  assigned_by TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('sending','sent','failed')),
  claimed_at INTEGER NOT NULL,
  last_sent_at INTEGER,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,cve_id),
  FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_assignment_assignee ON remediation_assignments(assignee_email,state);
CREATE TABLE IF NOT EXISTS remediation_assignment_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);

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

-- Additive D1 tables for user-controlled lifecycle monitoring.
-- No subscriber is opted in merely by applying this migration.
CREATE TABLE IF NOT EXISTS lifecycle_watches (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 id TEXT NOT NULL,
 product TEXT NOT NULL,
 slug TEXT NOT NULL DEFAULT '',
 cycle TEXT NOT NULL DEFAULT '',
 custom_eol_date TEXT NOT NULL DEFAULT '',
 custom_source_url TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,id)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_watches_user ON lifecycle_watches(user_id);
CREATE TABLE IF NOT EXISTS lifecycle_preferences (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 email_enabled INTEGER NOT NULL DEFAULT 0,
 lead_days INTEGER NOT NULL DEFAULT 90,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_delivery (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 event_key TEXT NOT NULL,
 sent_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,event_key)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_delivery_user ON lifecycle_delivery(user_id);
