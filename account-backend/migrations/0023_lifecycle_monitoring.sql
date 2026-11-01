-- PROPOSAL ONLY. Apply to a development database first. Production approval required.
-- Reuses lifecycle_watches/preferences; never imports or opts in legacy watches.
CREATE TABLE IF NOT EXISTS lifecycle_monitor_sources (
 id TEXT PRIMARY KEY, adapter TEXT NOT NULL, url TEXT NOT NULL,
 last_attempt_at INTEGER, last_success_at INTEGER, next_due_at INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0, lease_token TEXT NOT NULL DEFAULT '',
 failures INTEGER NOT NULL DEFAULT 0, error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS lifecycle_monitor_sources_due ON lifecycle_monitor_sources(next_due_at,lease_until);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_products (
 id TEXT PRIMARY KEY, source_id TEXT REFERENCES lifecycle_monitor_sources(id),
 slug TEXT NOT NULL, name TEXT NOT NULL, vendor TEXT NOT NULL, branch TEXT NOT NULL,
 edition TEXT NOT NULL DEFAULT '', official_url TEXT NOT NULL,
 verification_error TEXT NOT NULL DEFAULT '',
 UNIQUE(slug,branch,edition)
);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_accounts (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN(0,1))
);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_preferences (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 alert_types TEXT NOT NULL,delivery_mode TEXT NOT NULL DEFAULT 'daily'
 CHECK(delivery_mode IN('daily','immediate_security'))
);
CREATE TABLE IF NOT EXISTS lifecycle_watch_settings (
 user_id TEXT NOT NULL, watch_id TEXT NOT NULL, product_id TEXT NOT NULL REFERENCES lifecycle_monitor_products(id),
 status TEXT NOT NULL DEFAULT 'enabled' CHECK(status IN('enabled','paused','disabled')),
 alert_types TEXT NOT NULL, notice_days TEXT NOT NULL DEFAULT '[90,30,7]',
 delivery_mode TEXT NOT NULL DEFAULT 'daily' CHECK(delivery_mode IN('daily','immediate_security')),
 extended_entitled INTEGER NOT NULL DEFAULT 0 CHECK(extended_entitled IN(0,1)),
 consented_at INTEGER, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,watch_id), FOREIGN KEY(user_id,watch_id) REFERENCES lifecycle_watches(user_id,id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS lifecycle_watch_settings_product ON lifecycle_watch_settings(product_id,status,user_id);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_state (
 product_id TEXT PRIMARY KEY REFERENCES lifecycle_monitor_products(id),
 semantic_hash TEXT NOT NULL, record_json TEXT NOT NULL, verified_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_events (
 id TEXT PRIMARY KEY, product_id TEXT NOT NULL REFERENCES lifecycle_monitor_products(id),
 kind TEXT NOT NULL, event_key TEXT NOT NULL UNIQUE, record_json TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS lifecycle_monitor_events_product ON lifecycle_monitor_events(product_id,created_at);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_messages (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 recipient TEXT NOT NULL, slot TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending'
 CHECK(state IN('pending','submitting','submitted','delivered','failed','suppressed','submission_unknown')),
 provider_id TEXT NOT NULL DEFAULT '', request_id TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0, next_attempt_at INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0, attempt_token TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL, submitted_at INTEGER, delivered_at INTEGER, last_event_at INTEGER NOT NULL DEFAULT 0,
 detail TEXT NOT NULL DEFAULT '', UNIQUE(user_id,recipient,slot)
);
CREATE UNIQUE INDEX IF NOT EXISTS lifecycle_monitor_provider_id ON lifecycle_monitor_messages(provider_id) WHERE provider_id<>'';
CREATE INDEX IF NOT EXISTS lifecycle_monitor_messages_due ON lifecycle_monitor_messages(state,next_attempt_at,lease_until);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_notifications (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 watch_id TEXT NOT NULL, event_id TEXT NOT NULL REFERENCES lifecycle_monitor_events(id),
 recipient TEXT NOT NULL, installed_version TEXT NOT NULL DEFAULT '', due_at INTEGER NOT NULL,
 message_id TEXT REFERENCES lifecycle_monitor_messages(id),
 state TEXT NOT NULL DEFAULT 'pending' CHECK(state IN('pending','queued','suppressed')),
 unsubscribe_token TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL,
 UNIQUE(user_id,event_id,recipient)
);
CREATE INDEX IF NOT EXISTS lifecycle_monitor_notifications_due ON lifecycle_monitor_notifications(state,due_at,user_id);
CREATE INDEX IF NOT EXISTS lifecycle_monitor_notifications_owner ON lifecycle_monitor_notifications(user_id,created_at);
CREATE INDEX IF NOT EXISTS lifecycle_monitor_notifications_watch ON lifecycle_monitor_notifications(user_id,watch_id,created_at);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_delivery_events (
 id TEXT PRIMARY KEY, message_id TEXT NOT NULL REFERENCES lifecycle_monitor_messages(id),
 event TEXT NOT NULL, happened_at INTEGER NOT NULL, received_at INTEGER NOT NULL,
 detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_suppressions (
 recipient_hash TEXT PRIMARY KEY, reason TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_audit (
 id TEXT PRIMARY KEY,user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 watch_id TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS lifecycle_monitor_audit_owner ON lifecycle_monitor_audit(user_id,created_at);
CREATE TABLE IF NOT EXISTS lifecycle_monitor_runs (
 slot TEXT PRIMARY KEY, started_at INTEGER NOT NULL, completed_at INTEGER,
 checked INTEGER NOT NULL DEFAULT 0, failed INTEGER NOT NULL DEFAULT 0,
 new_events INTEGER NOT NULL DEFAULT 0, submitted INTEGER NOT NULL DEFAULT 0,
 rows_read INTEGER NOT NULL DEFAULT 0, rows_written INTEGER NOT NULL DEFAULT 0, reminder_day TEXT NOT NULL DEFAULT '',
 error TEXT NOT NULL DEFAULT ''
);
