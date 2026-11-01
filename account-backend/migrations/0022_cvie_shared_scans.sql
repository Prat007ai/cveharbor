-- Public provider history is stored once per verified source scope.
-- Private product aliases and assets remain in their existing account tables.
CREATE TABLE IF NOT EXISTS cvie_shared_scopes (
 id TEXT PRIMARY KEY,
 signature TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 vendor TEXT NOT NULL,
 cpe TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN('queued','scanning','retrying','ready')),
 cursor_json TEXT NOT NULL DEFAULT '{}',
 scan_started_at INTEGER,
 last_attempt_at INTEGER,
 last_success_at INTEGER,
 recent_complete_at INTEGER,
 history_complete_at INTEGER,
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '',
 seed_state TEXT NOT NULL DEFAULT 'complete' CHECK(seed_state IN('pending','complete')),
 seed_token TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS cvie_shared_due ON cvie_shared_scopes(next_attempt_at,lease_until);
CREATE TABLE IF NOT EXISTS cvie_shared_advisories (
 scope_id TEXT NOT NULL REFERENCES cvie_shared_scopes(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 published TEXT NOT NULL,
 record_json TEXT NOT NULL,
 generation TEXT NOT NULL,
 PRIMARY KEY(scope_id,cve_id)
);
CREATE INDEX IF NOT EXISTS cvie_shared_product_date ON cvie_shared_advisories(scope_id,published);
-- These bridges and migration cursors are PRIVATE, never part of public cache data.
CREATE TABLE IF NOT EXISTS cvie_product_scopes (
 product_id TEXT PRIMARY KEY REFERENCES cvie_products(id) ON DELETE CASCADE,
 scope_id TEXT REFERENCES cvie_shared_scopes(id),
 candidate_scope_id TEXT,
 source_name TEXT NOT NULL,
 source_vendor TEXT NOT NULL,
 source_cpe TEXT NOT NULL,
 version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cvie_scope_members ON cvie_product_scopes(scope_id,product_id);
CREATE INDEX IF NOT EXISTS cvie_unverified_scopes ON cvie_product_scopes(scope_id,candidate_scope_id);
CREATE TABLE IF NOT EXISTS cvie_shared_seeds (
 scope_id TEXT PRIMARY KEY REFERENCES cvie_shared_scopes(id) ON DELETE CASCADE,
 product_id TEXT REFERENCES cvie_products(id) ON DELETE SET NULL,
 token TEXT NOT NULL,
 source_name TEXT NOT NULL,
 source_vendor TEXT NOT NULL,
 source_cpe TEXT NOT NULL,
 donor_generation TEXT NOT NULL DEFAULT '',
 generation TEXT NOT NULL,
 after_cve TEXT NOT NULL DEFAULT '',
 resume_status TEXT NOT NULL,
 invalid_records INTEGER NOT NULL DEFAULT 0
);
