CREATE TABLE IF NOT EXISTS customer_security_score_snapshots (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
 environment_id TEXT NOT NULL DEFAULT '',
 method_version TEXT NOT NULL,
 score INTEGER,
 confidence TEXT NOT NULL,
 coverage INTEGER NOT NULL,
 breakdown_json TEXT NOT NULL,
 metrics_json TEXT NOT NULL,
 recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_customer_score_history ON customer_security_score_snapshots(user_id,customer_id,environment_id,recorded_at);
