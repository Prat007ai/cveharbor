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
