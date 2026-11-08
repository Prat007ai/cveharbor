-- Shared public source associations only. Account preferences stay in their existing table.
CREATE TABLE cvie_topic_matches (
  cve_id TEXT NOT NULL REFERENCES cvie_disclosures(cve_id) ON DELETE CASCADE,
  topic TEXT NOT NULL,
  published TEXT NOT NULL,
  products_json TEXT NOT NULL,
  PRIMARY KEY(cve_id, topic)
);
CREATE INDEX cvie_topic_recent ON cvie_topic_matches(topic, published DESC, cve_id DESC);
CREATE TABLE cvie_topic_pending(cve_id TEXT PRIMARY KEY, revision TEXT NOT NULL);
CREATE TABLE cvie_topic_backfill(id INTEGER PRIMARY KEY CHECK(id=1), after_id TEXT NOT NULL, complete INTEGER NOT NULL);
INSERT INTO cvie_topic_backfill VALUES(1,'',0);
CREATE TRIGGER cvie_topic_new AFTER INSERT ON cvie_disclosures BEGIN
  INSERT OR REPLACE INTO cvie_topic_pending VALUES(NEW.cve_id,hex(randomblob(16)));
END;
CREATE TRIGGER cvie_topic_changed AFTER UPDATE OF record_json, state, published ON cvie_disclosures
WHEN NEW.record_json IS NOT OLD.record_json OR NEW.state IS NOT OLD.state OR NEW.published IS NOT OLD.published BEGIN
  INSERT OR REPLACE INTO cvie_topic_pending VALUES(NEW.cve_id,hex(randomblob(16)));
END;
