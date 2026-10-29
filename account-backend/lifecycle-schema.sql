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
