-- Additive migration for account-private, asset-scoped CVE review statuses.
-- Apply only after a D1 backup. Existing records and migrations are untouched.
CREATE TABLE IF NOT EXISTS customer_finding_statuses (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('Needs Review','Fix in Progress','Fixed/Patched','Not Applicable','Accepted Risk')),
  notes TEXT NOT NULL DEFAULT '',
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id,asset_id,cve_id)
);
CREATE INDEX IF NOT EXISTS idx_customer_finding_statuses_asset ON customer_finding_statuses(user_id,asset_id);
