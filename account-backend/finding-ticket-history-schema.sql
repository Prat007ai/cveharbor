-- Add only. Preserve legacy customer_finding_tickets and its existing values.
CREATE TABLE IF NOT EXISTS customer_finding_ticket_history (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 ticket_number TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,asset_id,cve_id,ticket_number)
);
CREATE INDEX IF NOT EXISTS idx_customer_finding_ticket_history_asset ON customer_finding_ticket_history(user_id,asset_id,cve_id);
INSERT OR IGNORE INTO customer_finding_ticket_history(user_id,asset_id,cve_id,ticket_number,created_at)
SELECT user_id,asset_id,cve_id,ticket_number,updated_at
FROM customer_finding_tickets
WHERE TRIM(ticket_number) != '';
