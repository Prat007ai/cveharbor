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
