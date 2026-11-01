-- Public authoritative evidence cache; customer associations remain account scoped.
CREATE TABLE IF NOT EXISTS cvie_sources (
 id TEXT PRIMARY KEY,
 status TEXT NOT NULL DEFAULT 'pending',
 last_attempt_at INTEGER,
 last_success_at INTEGER,
 publisher_at INTEGER,
 checkpoint INTEGER,
 coverage_start_at INTEGER,
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '',
 source_url TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO cvie_sources(id) VALUES('cve_program'),('cisa_kev');
CREATE TABLE IF NOT EXISTS cvie_disclosures (
 cve_id TEXT PRIMARY KEY,
 state TEXT NOT NULL,
 published TEXT,
 updated_at TEXT NOT NULL,
 record_json TEXT NOT NULL,
 checked_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS cvie_disclosure_products (
 cve_id TEXT NOT NULL REFERENCES cvie_disclosures(cve_id) ON DELETE CASCADE,
 family_key TEXT NOT NULL,
 applicability TEXT NOT NULL,
 affected_json TEXT NOT NULL,
 PRIMARY KEY(cve_id,family_key)
);
CREATE INDEX IF NOT EXISTS cvie_disclosure_family ON cvie_disclosure_products(family_key,cve_id);
CREATE TABLE IF NOT EXISTS cvie_disclosure_queue (
 cve_id TEXT PRIMARY KEY,
 revision TEXT NOT NULL,
 priority INTEGER NOT NULL DEFAULT 1,
 next_attempt_at INTEGER NOT NULL DEFAULT 0,
 lease_until INTEGER NOT NULL DEFAULT 0,
 attempts INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS cvie_disclosure_due ON cvie_disclosure_queue(priority,next_attempt_at,lease_until);
CREATE TABLE IF NOT EXISTS cvie_kev (
 cve_id TEXT PRIMARY KEY,
 date_added TEXT NOT NULL,
 vendor TEXT NOT NULL,
 product TEXT NOT NULL,
 record_json TEXT NOT NULL,
 checked_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS cvie_product_date ON cvie_advisories(product_id,published);
