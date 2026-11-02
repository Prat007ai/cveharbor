-- Additive only. Check migration numbering against main before applying.
CREATE TABLE IF NOT EXISTS cvie_source_snapshots (
 source_id TEXT PRIMARY KEY REFERENCES cvie_sources(id) ON DELETE CASCADE,
 content_hash TEXT NOT NULL
);
-- These support state queries and queue diagnostics, never writes from GETs.
-- Only global rejections need this secondary lookup. Published records already
-- have a CVE primary key; do not index every ingested disclosure a second time.
CREATE INDEX IF NOT EXISTS cvie_disclosure_state ON cvie_disclosures(cve_id) WHERE state='REJECTED';
CREATE TABLE IF NOT EXISTS cvie_queue_observations (
 cve_id TEXT PRIMARY KEY REFERENCES cvie_disclosure_queue(cve_id) ON DELETE CASCADE,
 enqueued_at INTEGER NOT NULL,
 first_attempt_at INTEGER
);
-- Existing queue age is unknown; do not manufacture an enqueue timestamp.
CREATE TRIGGER IF NOT EXISTS cvie_queue_observed_insert AFTER INSERT ON cvie_disclosure_queue
 BEGIN INSERT OR IGNORE INTO cvie_queue_observations(cve_id,enqueued_at)
 VALUES(NEW.cve_id,unixepoch()*1000); END;
CREATE TRIGGER IF NOT EXISTS cvie_queue_observed_attempt AFTER UPDATE OF lease_until ON cvie_disclosure_queue
 WHEN NEW.lease_until>OLD.lease_until
 BEGIN UPDATE cvie_queue_observations SET first_attempt_at=unixepoch()*1000
 WHERE cve_id=NEW.cve_id AND first_attempt_at IS NULL; END;
