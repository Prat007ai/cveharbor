-- Additive, account-private CVIE jobs and source-backed advisories. No inventory is changed.
CREATE TABLE IF NOT EXISTS cvie_products (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name_key TEXT NOT NULL,
  name TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT '',
  cpe TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued',
  candidates_json TEXT NOT NULL DEFAULT '[]',
  cursor_json TEXT NOT NULL DEFAULT '{}',
  scan_started_at INTEGER,
  last_attempt_at INTEGER,
  last_success_at INTEGER,
  recent_complete_at INTEGER,
  history_complete_at INTEGER,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  UNIQUE(user_id,name_key)
);
CREATE INDEX IF NOT EXISTS cvie_due ON cvie_products(next_attempt_at,lease_until);
CREATE TABLE IF NOT EXISTS cvie_subscriptions (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL REFERENCES cvie_products(id) ON DELETE CASCADE,
  origin TEXT NOT NULL CHECK(origin IN ('catalogue','inventory','stack')),
  PRIMARY KEY(user_id,product_id,origin)
);
CREATE TABLE IF NOT EXISTS cvie_advisories (
  product_id TEXT NOT NULL REFERENCES cvie_products(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  published TEXT NOT NULL,
  record_json TEXT NOT NULL,
  generation TEXT NOT NULL,
  PRIMARY KEY(product_id,cve_id)
);
CREATE INDEX IF NOT EXISTS cvie_advisory_date ON cvie_advisories(published,product_id,cve_id);
-- A durable global NVD request slot also coordinates separate Workers isolates.
CREATE TABLE IF NOT EXISTS cvie_provider_budget (
  provider TEXT PRIMARY KEY,
  next_request_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO cvie_provider_budget(provider) VALUES('nvd');
