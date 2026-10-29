-- Additive DevOps ticket references by account, asset and CVE.
-- Preserve existing inventory, fix status and remediation records.
CREATE TABLE IF NOT EXISTS customer_finding_tickets (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 ticket_number TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,asset_id,cve_id)
);
CREATE INDEX IF NOT EXISTS idx_customer_finding_tickets_user ON customer_finding_tickets(user_id,asset_id);
