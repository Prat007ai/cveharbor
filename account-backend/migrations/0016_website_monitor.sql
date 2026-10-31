-- Website monitoring foundation: per-account scope with individual consent.
CREATE TABLE IF NOT EXISTS website_monitors (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL, url TEXT NOT NULL, label TEXT NOT NULL,
 profile TEXT NOT NULL DEFAULT 'basic', enabled INTEGER NOT NULL DEFAULT 1,
 last_checked_at INTEGER, last_status INTEGER, last_error TEXT, created_at INTEGER NOT NULL,
 UNIQUE(user_id,url)
);
CREATE INDEX IF NOT EXISTS idx_website_monitors_due ON website_monitors(enabled,last_checked_at);
CREATE INDEX IF NOT EXISTS idx_website_monitors_user ON website_monitors(user_id);
CREATE TABLE IF NOT EXISTS website_monitor_checks (
 id TEXT PRIMARY KEY, monitor_id TEXT NOT NULL, user_id TEXT NOT NULL,
 checked_at INTEGER NOT NULL, http_status INTEGER, content_type TEXT,
 security_headers TEXT, changed INTEGER NOT NULL DEFAULT 0, error TEXT
);
CREATE INDEX IF NOT EXISTS idx_website_checks_owner ON website_monitor_checks(user_id,monitor_id,checked_at DESC);
