-- One-time derived-cache maintenance after the corrected Worker is deployed.
-- Retain existing evidence and all customer inventory/status/ticket records.
CREATE TABLE IF NOT EXISTS cvie_maintenance (
 key TEXT PRIMARY KEY,
 completed_at INTEGER NOT NULL
);

-- Stop in-flight record owners before rebuilding derived applicability.
UPDATE cvie_disclosure_queue SET lease_until=0
WHERE NOT EXISTS(SELECT 1 FROM cvie_maintenance WHERE key='cvie-audit-v1');

-- Force canonical records through the new normalizer, including unchanged
-- publisher revisions. Fencing invalidates any older in-flight record response.
INSERT INTO cvie_disclosure_queue(cve_id,revision,priority)
 SELECT cve_id,updated_at,1 FROM cvie_disclosures
 WHERE NOT EXISTS(SELECT 1 FROM cvie_maintenance WHERE key='cvie-audit-v1')
 ON CONFLICT(cve_id) DO UPDATE SET revision=MAX(revision,excluded.revision),
  priority=MIN(priority,excluded.priority),next_attempt_at=0,lease_until=0,attempts=0,error='';

UPDATE cvie_disclosure_products SET applicability=CASE
 WHEN json_array_length(affected_json)>0 AND NOT EXISTS(
  SELECT 1 FROM json_each(affected_json) a
  WHERE COALESCE(json_extract(a.value,'$.defaultStatus'),'unknown')<>'unaffected'
   OR EXISTS(SELECT 1 FROM json_each(json_extract(a.value,'$.versions')) v
    WHERE COALESCE(json_extract(v.value,'$.status'),'unknown')<>'unaffected')
 ) THEN 'unaffected' ELSE 'affected' END
WHERE NOT EXISTS(SELECT 1 FROM cvie_maintenance WHERE key='cvie-audit-v1');

-- Restart resolved product checks under the corrected NVD normalizer. Their
-- last verified advisories stay available until the replacement scan finishes.
-- Unresolved identities stay unresolved; this migration never guesses a CPE.
UPDATE cvie_products SET status='queued',cursor_json='{}',next_attempt_at=0,
 lease_until=0,error=''
WHERE cpe<>'' AND status<>'needs_identity'
 AND NOT EXISTS(SELECT 1 FROM cvie_maintenance WHERE key='cvie-audit-v1');

INSERT OR IGNORE INTO cvie_maintenance(key,completed_at)
 VALUES('cvie-audit-v1',CAST(strftime('%s','now') AS INTEGER)*1000);
