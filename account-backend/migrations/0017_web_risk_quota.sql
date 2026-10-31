CREATE TABLE IF NOT EXISTS web_risk_usage (
 month TEXT PRIMARY KEY,
 reserved INTEGER NOT NULL DEFAULT 0,
 warning_sent_at INTEGER,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS web_risk_account_usage (
 month TEXT NOT NULL,
 user_id TEXT NOT NULL,
 requests INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(month,user_id)
);
CREATE INDEX IF NOT EXISTS idx_web_risk_account_user ON web_risk_account_usage(user_id,month);
