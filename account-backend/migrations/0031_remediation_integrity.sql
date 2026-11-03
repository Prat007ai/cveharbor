-- Phase 1: additive guards only. No backfill, record deletion, status conversion,
-- automatic linking, token changes, or notification replay. Apply after 0028–0030.
CREATE TABLE IF NOT EXISTS remediation_finding_write_context (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL,cve_id TEXT NOT NULL,expected_record TEXT,expected_manual TEXT,
 expected_finding TEXT NOT NULL,expected_asset TEXT NOT NULL,
 PRIMARY KEY(user_id,asset_id,cve_id)
);
CREATE TRIGGER IF NOT EXISTS validate_finding_write BEFORE INSERT ON remediation_finding_write_context
BEGIN
 SELECT CASE WHEN NEW.expected_record IS NOT (SELECT record_id FROM remediation_finding_links WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
 OR NEW.expected_manual IS NOT (SELECT r.updated_at FROM remediations r WHERE r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id AND NOT EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.user_id=r.user_id AND l.record_id=r.cve_id))
 OR json_extract(NEW.expected_finding,'$.status') IS NOT (SELECT status FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
 OR json_extract(NEW.expected_finding,'$.notes') IS NOT (SELECT notes FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
 OR json_extract(NEW.expected_finding,'$.updated_at') IS NOT (SELECT updated_at FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
 THEN RAISE(ABORT,'Finding changed; reload before saving') END;
 SELECT CASE WHEN NOT EXISTS(
 SELECT 1 FROM inventory_assets a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id
 WHERE a.id=NEW.asset_id AND a.user_id=NEW.user_id
 AND a.environment_id=json_extract(NEW.expected_asset,'$.environment_id') AND c.id=json_extract(NEW.expected_asset,'$.customer_id')
 AND a.name=json_extract(NEW.expected_asset,'$.asset_name') AND a.technology=json_extract(NEW.expected_asset,'$.technology') AND a.version=json_extract(NEW.expected_asset,'$.version')
 AND e.name=json_extract(NEW.expected_asset,'$.environment_name') AND c.name=json_extract(NEW.expected_asset,'$.customer_name'))
 THEN RAISE(ABORT,'Finding scope changed; review the customer asset again') END;
END;
-- A link is one stable asset/CVE in one account. It is not a CVE-only merge.
CREATE TRIGGER IF NOT EXISTS finding_link_identity BEFORE INSERT ON remediation_finding_links
BEGIN
 SELECT CASE WHEN NEW.cve_id!=upper(NEW.cve_id) OR NEW.asset_id!=lower(NEW.asset_id)
 OR NEW.record_id NOT IN (NEW.cve_id,NEW.cve_id||'~'||upper(NEW.asset_id))
 OR EXISTS(SELECT 1 FROM remediation_retired_records WHERE user_id=NEW.user_id AND record_id=NEW.record_id)
 THEN RAISE(ABORT,'Record integrity: invalid finding identity') END;
END;
CREATE TRIGGER IF NOT EXISTS finding_link_immutable BEFORE UPDATE ON remediation_finding_links
WHEN OLD.user_id!=NEW.user_id OR OLD.record_id!=NEW.record_id OR OLD.asset_id!=NEW.asset_id OR OLD.cve_id!=NEW.cve_id
BEGIN SELECT RAISE(ABORT,'Record integrity: finding links cannot be reassigned'); END;
-- Retired placeholders remain stored, but only their canonical record is active.
CREATE TRIGGER IF NOT EXISTS retired_remediation_read_only BEFORE UPDATE ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_retired_records WHERE user_id=OLD.user_id AND record_id=OLD.cve_id)
BEGIN SELECT RAISE(ABORT,'Record integrity: retired record is read only'); END;
CREATE TRIGGER IF NOT EXISTS preserve_remediation_history BEFORE DELETE ON remediations
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id) AND (
 EXISTS(SELECT 1 FROM remediation_finding_links WHERE user_id=OLD.user_id AND record_id=OLD.cve_id)
 OR EXISTS(SELECT 1 FROM remediation_retired_records WHERE user_id=OLD.user_id AND (record_id=OLD.cve_id OR canonical_id=OLD.cve_id))
 OR EXISTS(SELECT 1 FROM remediation_assignment_requests WHERE user_id=OLD.user_id AND cve_id=OLD.cve_id)
 OR EXISTS(SELECT 1 FROM remediation_assignments WHERE user_id=OLD.user_id AND cve_id=OLD.cve_id)
 OR EXISTS(SELECT 1 FROM remediation_status_changes WHERE user_id=OLD.user_id AND cve_id=OLD.cve_id)
 OR EXISTS(SELECT 1 FROM remediation_owner_comments WHERE user_id=OLD.user_id AND record_id=OLD.cve_id)
 OR EXISTS(SELECT 1 FROM remediation_record_metadata WHERE user_id=OLD.user_id AND cve_id=OLD.cve_id)
 OR EXISTS(SELECT 1 FROM remediation_link_audit WHERE user_id=OLD.user_id AND record_id=OLD.cve_id))
BEGIN SELECT RAISE(ABORT,'Record integrity: retained history prevents deletion'); END;
CREATE TRIGGER IF NOT EXISTS preserve_asset_finding_history BEFORE DELETE ON inventory_assets
WHEN EXISTS(SELECT 1 FROM users WHERE id=OLD.user_id) AND (
 EXISTS(SELECT 1 FROM remediation_finding_links WHERE user_id=OLD.user_id AND asset_id=OLD.id)
 OR EXISTS(SELECT 1 FROM customer_finding_statuses WHERE user_id=OLD.user_id AND asset_id=OLD.id)
 OR EXISTS(SELECT 1 FROM customer_finding_ticket_history WHERE user_id=OLD.user_id AND asset_id=OLD.id)
 OR EXISTS(SELECT 1 FROM customer_finding_tickets WHERE user_id=OLD.user_id AND asset_id=OLD.id))
BEGIN SELECT RAISE(ABORT,'Record integrity: retained history prevents asset deletion'); END;
-- A direct/legacy writer must not create a conflicting dashboard status.
CREATE TRIGGER IF NOT EXISTS linked_finding_status_insert BEFORE INSERT ON customer_finding_statuses
WHEN EXISTS(SELECT 1 FROM remediation_finding_links l JOIN remediations r ON r.user_id=l.user_id AND r.cve_id=l.record_id WHERE l.user_id=NEW.user_id AND l.asset_id=NEW.asset_id AND l.cve_id=NEW.cve_id AND NEW.status!=CASE r.status WHEN 'Open' THEN 'Needs Review' WHEN 'Investigating' THEN 'Fix in Progress' WHEN 'Remediated' THEN 'Fixed/Patched' ELSE r.status END)
BEGIN SELECT RAISE(ABORT,'Record integrity: update the shared remediation status'); END;
CREATE TRIGGER IF NOT EXISTS linked_finding_status_update BEFORE UPDATE OF status ON customer_finding_statuses
WHEN EXISTS(SELECT 1 FROM remediation_finding_links l JOIN remediations r ON r.user_id=l.user_id AND r.cve_id=l.record_id WHERE l.user_id=NEW.user_id AND l.asset_id=NEW.asset_id AND l.cve_id=NEW.cve_id AND NEW.status!=CASE r.status WHEN 'Open' THEN 'Needs Review' WHEN 'Investigating' THEN 'Fix in Progress' WHEN 'Remediated' THEN 'Fixed/Patched' ELSE r.status END)
BEGIN SELECT RAISE(ABORT,'Record integrity: update the shared remediation status'); END;
