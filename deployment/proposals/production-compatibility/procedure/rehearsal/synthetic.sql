PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,email TEXT NOT NULL UNIQUE,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS login_challenges(id TEXT PRIMARY KEY,email TEXT NOT NULL,token_hash TEXT NOT NULL,expires_at INTEGER NOT NULL,used_at INTEGER,created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_challenges_email ON login_challenges(email,created_at);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,token_hash TEXT NOT NULL UNIQUE,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS user_stack(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,technology TEXT NOT NULL,product_version TEXT NOT NULL DEFAULT '',PRIMARY KEY(user_id,technology));
CREATE TABLE IF NOT EXISTS remediations(user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,cve_id TEXT NOT NULL,status TEXT NOT NULL,owner TEXT NOT NULL DEFAULT '',due TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',updated_at TEXT NOT NULL,PRIMARY KEY(user_id,cve_id));
CREATE TABLE IF NOT EXISTS alert_preferences(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,enabled INTEGER NOT NULL DEFAULT 0,severity TEXT NOT NULL DEFAULT 'critical',frequency TEXT NOT NULL DEFAULT 'daily',updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS auth_rate_limits(key TEXT PRIMARY KEY,window_start INTEGER NOT NULL,count INTEGER NOT NULL);

-- CVEHarbor scheduled email digest migration.
-- Apply once to the existing cveharbor-accounts D1 database before enabling alert delivery.
-- New opt-in is required; previously saved "future" alert preferences do not silently enable email.
CREATE TABLE IF NOT EXISTS alert_optins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  consented_at INTEGER NOT NULL,
  unsubscribe_token TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS alert_delivery_items (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  advisory_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  delivered_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_items_user ON alert_delivery_items(user_id);
CREATE TABLE IF NOT EXISTS alert_digest_runs (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  slot TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sending','sent','empty','failed')),
  claimed_at INTEGER NOT NULL,
  completed_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 1,
  item_count INTEGER NOT NULL DEFAULT 0,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,slot)
);
CREATE INDEX IF NOT EXISTS idx_alert_runs_user_date ON alert_digest_runs(user_id,completed_at);

-- Cloudflare D1 migration for CVEHarbor remediation assignments.
-- Apply to the EXISTING cveharbor-accounts database after a D1 backup.
-- The existing remediations table is already present. Do not recreate it.
CREATE TABLE IF NOT EXISTS remediation_assignments (
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  assignee_email TEXT NOT NULL,
  assigned_by TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('sending','sent','failed')),
  claimed_at INTEGER NOT NULL,
  last_sent_at INTEGER,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,cve_id),
  FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_assignment_assignee ON remediation_assignments(assignee_email,state);
CREATE TABLE IF NOT EXISTS remediation_assignment_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);

-- Additive migration for private customer environments and installed technologies.
-- Existing account and remediation records are untouched.
CREATE TABLE IF NOT EXISTS inventory_customers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_customers_user ON inventory_customers(user_id);
CREATE TABLE IF NOT EXISTS inventory_environments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'Production',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,customer_id,name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_environments_user ON inventory_environments(user_id,customer_id);
CREATE TABLE IF NOT EXISTS inventory_assets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  technology TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_user ON inventory_assets(user_id,environment_id);

-- Additive D1 tables for user-controlled lifecycle monitoring.
-- No subscriber is opted in merely by applying this migration.
CREATE TABLE IF NOT EXISTS lifecycle_watches (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 id TEXT NOT NULL,
 product TEXT NOT NULL,
 slug TEXT NOT NULL DEFAULT '',
 cycle TEXT NOT NULL DEFAULT '',
 installed_version TEXT NOT NULL DEFAULT '',
 custom_eol_date TEXT NOT NULL DEFAULT '',
 custom_source_url TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,id)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_watches_user ON lifecycle_watches(user_id);
CREATE TABLE IF NOT EXISTS lifecycle_preferences (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 email_enabled INTEGER NOT NULL DEFAULT 0,
 lead_days INTEGER NOT NULL DEFAULT 90,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_delivery (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 event_key TEXT NOT NULL,
 sent_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,event_key)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_delivery_user ON lifecycle_delivery(user_id);

-- Apply to existing cveharbor-accounts D1 only after backup.
-- Additive, opt-in authenticator MFA storage. No existing account is changed.
CREATE TABLE IF NOT EXISTS user_totp (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 encrypted_secret TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 0,
 last_counter INTEGER NOT NULL DEFAULT -1,
 created_at INTEGER NOT NULL,
 enabled_at INTEGER
);
CREATE TABLE IF NOT EXISTS totp_login_challenges (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 expires_at INTEGER NOT NULL,
 consumed_at INTEGER,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_totp_challenge_expiration ON totp_login_challenges(expires_at);
CREATE TABLE IF NOT EXISTS totp_recovery_codes (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL,
 used_at INTEGER,
 PRIMARY KEY(user_id,code_hash)
);

-- CVEHarbor scheduled email digest migration.
-- Apply once to the existing cveharbor-accounts D1 database before enabling alert delivery.
-- New opt-in is required; previously saved "future" alert preferences do not silently enable email.
CREATE TABLE IF NOT EXISTS alert_optins (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  consented_at INTEGER NOT NULL,
  unsubscribe_token TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS alert_delivery_items (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  advisory_id TEXT NOT NULL,
  revision TEXT NOT NULL,
  delivered_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, advisory_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_items_user ON alert_delivery_items(user_id);
CREATE TABLE IF NOT EXISTS alert_digest_runs (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  slot TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('sending','sent','empty','failed')),
  claimed_at INTEGER NOT NULL,
  completed_at INTEGER,
  attempts INTEGER NOT NULL DEFAULT 1,
  item_count INTEGER NOT NULL DEFAULT 0,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,slot)
);
CREATE INDEX IF NOT EXISTS idx_alert_runs_user_date ON alert_digest_runs(user_id,completed_at);

-- Additive migration for private customer environments and installed technologies.
-- Existing account and remediation records are untouched.
CREATE TABLE IF NOT EXISTS inventory_customers (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_customers_user ON inventory_customers(user_id);
CREATE TABLE IF NOT EXISTS inventory_environments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'Production',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id,customer_id,name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_environments_user ON inventory_environments(user_id,customer_id);
CREATE TABLE IF NOT EXISTS inventory_assets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  asset_type TEXT NOT NULL,
  technology TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_inventory_assets_user ON inventory_assets(user_id,environment_id);

-- Cloudflare D1 migration for CVEHarbor remediation assignments.
-- Apply to the EXISTING cveharbor-accounts database after a D1 backup.
-- The existing remediations table is already present. Do not recreate it.
CREATE TABLE IF NOT EXISTS remediation_assignments (
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  assignee_email TEXT NOT NULL,
  assigned_by TEXT NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('sending','sent','failed')),
  claimed_at INTEGER NOT NULL,
  last_sent_at INTEGER,
  provider_id TEXT NOT NULL DEFAULT '',
  PRIMARY KEY(user_id,cve_id),
  FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_assignment_assignee ON remediation_assignments(assignee_email,state);
-- Separate assignment quota counters from the authentication rate table. 
-- OTP request cleanup must never reset assignment daily limits.
CREATE TABLE IF NOT EXISTS remediation_assignment_limits (
  key TEXT PRIMARY KEY,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL
);

-- Additive D1 tables for user-controlled lifecycle monitoring.
-- No subscriber is opted in merely by applying this migration.
CREATE TABLE IF NOT EXISTS lifecycle_watches (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 id TEXT NOT NULL,
 product TEXT NOT NULL,
 slug TEXT NOT NULL DEFAULT '',
 cycle TEXT NOT NULL DEFAULT '',
 installed_version TEXT NOT NULL DEFAULT '',
 custom_eol_date TEXT NOT NULL DEFAULT '',
 custom_source_url TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,id)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_watches_user ON lifecycle_watches(user_id);
CREATE TABLE IF NOT EXISTS lifecycle_preferences (
 user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 email_enabled INTEGER NOT NULL DEFAULT 0,
 lead_days INTEGER NOT NULL DEFAULT 90,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS lifecycle_delivery (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 event_key TEXT NOT NULL,
 sent_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,event_key)
);
CREATE INDEX IF NOT EXISTS idx_lifecycle_delivery_user ON lifecycle_delivery(user_id);

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

CREATE TABLE IF NOT EXISTS customer_security_score_snapshots (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
 environment_id TEXT NOT NULL DEFAULT '',
 method_version TEXT NOT NULL,
 score INTEGER,
 confidence TEXT NOT NULL,
 coverage INTEGER NOT NULL,
 breakdown_json TEXT NOT NULL,
 metrics_json TEXT NOT NULL,
 recorded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_customer_score_history ON customer_security_score_snapshots(user_id,customer_id,environment_id,recorded_at);

-- Additive account-scoped package inventory for Linux environments.
CREATE TABLE IF NOT EXISTS inventory_packages (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
 asset_name TEXT NOT NULL,
 distribution TEXT NOT NULL,
 release TEXT NOT NULL,
 architecture TEXT NOT NULL,
 package_name TEXT NOT NULL,
 source_package TEXT NOT NULL,
 installed_version TEXT NOT NULL,
 collected_at TEXT NOT NULL,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(user_id,environment_id,asset_name,architecture,package_name)
);
CREATE INDEX IF NOT EXISTS idx_inventory_packages_env ON inventory_packages(user_id,environment_id);

-- Additive setup. Run manually in the CVEHarbor accounts D1 database.
-- No existing versions, findings, statuses or customer records are changed.
-- Capture starts when this trigger is installed; no past dates are inferred.
CREATE TABLE IF NOT EXISTS inventory_software_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer_id TEXT NOT NULL REFERENCES inventory_customers(id) ON DELETE CASCADE,
  environment_id TEXT NOT NULL REFERENCES inventory_environments(id) ON DELETE CASCADE,
  asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
  asset_name TEXT NOT NULL,
  previous_technology TEXT NOT NULL,
  technology TEXT NOT NULL,
  previous_version TEXT NOT NULL,
  version TEXT NOT NULL,
  recorded_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_inventory_software_history_scope
  ON inventory_software_history(user_id,customer_id,environment_id,id DESC);
CREATE TRIGGER IF NOT EXISTS inventory_software_version_changed
AFTER UPDATE OF version,technology ON inventory_assets
WHEN OLD.version IS NOT NEW.version OR OLD.technology IS NOT NEW.technology
BEGIN
  INSERT INTO inventory_software_history
    (user_id,customer_id,environment_id,asset_id,asset_name,previous_technology,technology,previous_version,version)
  SELECT NEW.user_id,e.customer_id,NEW.environment_id,NEW.id,NEW.name,
    OLD.technology,NEW.technology,OLD.version,NEW.version
  FROM inventory_environments e
  WHERE e.id=NEW.environment_id AND e.user_id=NEW.user_id;
END;

-- Additive private plugin scan cache and history; no existing records modified.
CREATE TABLE IF NOT EXISTS plugin_monitor_checks (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 installed_version TEXT NOT NULL,
 plugin_slug TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('checked','unverified','unavailable')),
 reason TEXT NOT NULL DEFAULT '',
 findings_json TEXT NOT NULL DEFAULT '[]',
 checked_at INTEGER NOT NULL,
 next_check_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,asset_id)
);
CREATE INDEX IF NOT EXISTS idx_plugin_monitor_due ON plugin_monitor_checks(next_check_at);
CREATE TABLE IF NOT EXISTS plugin_monitor_history (
 id TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 checked_at INTEGER NOT NULL,
 status TEXT NOT NULL,
 finding_count INTEGER NOT NULL,
 reason TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_plugin_monitor_history_asset ON plugin_monitor_history(user_id,asset_id,checked_at);

CREATE TABLE IF NOT EXISTS plugin_release_checks (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 installed_version TEXT NOT NULL,
 slug TEXT NOT NULL,
 release_status TEXT NOT NULL,
 latest_version TEXT NOT NULL DEFAULT '',
 update_status TEXT NOT NULL DEFAULT 'Unknown',
 release_source TEXT NOT NULL DEFAULT '',
 last_updated TEXT NOT NULL DEFAULT '',
 reason TEXT NOT NULL DEFAULT '',
 checked_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,asset_id)
);
CREATE INDEX IF NOT EXISTS idx_plugin_release_checks_user ON plugin_release_checks(user_id);

-- Additive, account-private plugin source mapping. Existing inventory remains unchanged.
CREATE TABLE IF NOT EXISTS plugin_source_mappings (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 vendor_url TEXT NOT NULL DEFAULT '',
 release_url TEXT NOT NULL DEFAULT '',
 advisory_url TEXT NOT NULL DEFAULT '',
 plugin_slug TEXT NOT NULL DEFAULT '',
 verification TEXT NOT NULL DEFAULT 'Needs Review',
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,asset_id)
);
CREATE INDEX IF NOT EXISTS idx_plugin_source_mappings_user ON plugin_source_mappings(user_id);

CREATE TABLE IF NOT EXISTS plugin_installation_status (user_id TEXT NOT NULL, asset_id TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('Active','Inactive','Network active','Inactive, listing closed')), PRIMARY KEY(user_id,asset_id));

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

CREATE TABLE IF NOT EXISTS web_risk_usage (
 month TEXT PRIMARY KEY,
 reserved INTEGER NOT NULL DEFAULT 0,
 warning_sent_at INTEGER,
 updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS web_risk_account_usage (
 month TEXT NOT NULL,
 user_id TEXT NOT NULL,
 requests INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(month,user_id)
);
CREATE INDEX IF NOT EXISTS idx_web_risk_account_user ON web_risk_account_usage(user_id,month);

-- Account scoped technology catalogue preferences. Existing inventory and watchlists remain unchanged.
CREATE TABLE IF NOT EXISTS user_technology_catalogue (
  user_id TEXT PRIMARY KEY,
  preferences_json TEXT NOT NULL CHECK(length(preferences_json) <= 18000),
  updated_at INTEGER NOT NULL
);

-- Additive, account-private CVIE jobs and source-backed advisories. No inventory is changed.
CREATE TABLE IF NOT EXISTS cvie_products (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name_key TEXT NOT NULL,
  name TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT '',
  cpe TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','scanning','needs_identity','retrying','ready')),
  candidates_json TEXT NOT NULL DEFAULT '[]',
  cursor_json TEXT NOT NULL DEFAULT '{}',
  scan_started_at INTEGER,
  last_attempt_at INTEGER,
  last_success_at INTEGER,
  recent_complete_at INTEGER,
  history_complete_at INTEGER,
  next_attempt_at INTEGER NOT NULL DEFAULT 0,
  lease_until INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL DEFAULT '',
  UNIQUE(user_id,name_key)
);
CREATE INDEX IF NOT EXISTS cvie_due ON cvie_products(next_attempt_at,lease_until);
CREATE TABLE IF NOT EXISTS cvie_subscriptions (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  product_id TEXT NOT NULL REFERENCES cvie_products(id) ON DELETE CASCADE,
  origin TEXT NOT NULL CHECK(origin IN ('catalogue','inventory','stack')),
  PRIMARY KEY(user_id,product_id,origin)
);
CREATE TABLE IF NOT EXISTS cvie_advisories (
  product_id TEXT NOT NULL REFERENCES cvie_products(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  published TEXT NOT NULL,
  record_json TEXT NOT NULL,
  generation TEXT NOT NULL,
  PRIMARY KEY(product_id,cve_id)
);
CREATE INDEX IF NOT EXISTS cvie_advisory_date ON cvie_advisories(published,product_id,cve_id);
-- A durable global NVD request slot also coordinates separate Workers isolates.
CREATE TABLE IF NOT EXISTS cvie_provider_budget (
  provider TEXT PRIMARY KEY,
  next_request_at INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO cvie_provider_budget(provider) VALUES('nvd');

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
 record_retry_at INTEGER NOT NULL DEFAULT 0,
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

-- Additive, repeatable; preserve legacy assignment records and remediation statuses.
CREATE TABLE IF NOT EXISTS remediation_assignment_requests (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  user_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  recipient_email TEXT NOT NULL,
  requester_email TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash)=64),
  delivery_status TEXT NOT NULL CHECK(delivery_status IN ('sending','sent','failed')),
  public_advisory_json TEXT NOT NULL DEFAULT '{}',
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  sent_at INTEGER,
  acknowledged_at INTEGER,
  revoked_at INTEGER,
  provider_id TEXT NOT NULL DEFAULT '',
  FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assignment_request_scope ON remediation_assignment_requests(user_id,cve_id,seq DESC);
CREATE INDEX IF NOT EXISTS idx_assignment_request_recipient ON remediation_assignment_requests(user_id,cve_id,recipient_email,seq DESC);
CREATE TABLE IF NOT EXISTS remediation_assignment_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  assignment_id TEXT NOT NULL REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
  event TEXT NOT NULL CHECK(event IN ('created','sent','delivery_failed','acknowledged','revoked')),
  occurred_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assignment_event_request ON remediation_assignment_events(assignment_id,id);
CREATE TRIGGER IF NOT EXISTS assignment_request_created AFTER INSERT ON remediation_assignment_requests
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'created',NEW.created_at); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_sent AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='sent' AND OLD.delivery_status!='sent'
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'sent',NEW.sent_at); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_failed AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='failed' AND OLD.delivery_status!='failed'
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'delivery_failed',unixepoch()); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_acknowledged AFTER UPDATE OF acknowledged_at ON remediation_assignment_requests
WHEN OLD.acknowledged_at IS NULL AND NEW.acknowledged_at IS NOT NULL
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'acknowledged',NEW.acknowledged_at); END;
CREATE TRIGGER IF NOT EXISTS assignment_request_revoked AFTER UPDATE OF revoked_at ON remediation_assignment_requests
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN INSERT INTO remediation_assignment_events(assignment_id,event,occurred_at) VALUES(NEW.id,'revoked',NEW.revoked_at); END;

-- Optional FYI observers; never receive or share the assignee's bearer token.
CREATE TABLE IF NOT EXISTS remediation_assignment_fyi (
 assignment_id TEXT NOT NULL REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
 recipient_email TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(assignment_id,recipient_email)
);
CREATE TABLE IF NOT EXISTS remediation_assignment_notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id TEXT NOT NULL,
 recipient_email TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('assigned','acknowledged')),
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','unconfirmed','cancelled')),
 created_at INTEGER NOT NULL,
 not_before INTEGER NOT NULL DEFAULT 0,
 claimed_at INTEGER,
 claim_token TEXT NOT NULL DEFAULT '',
 completed_at INTEGER,
 attempts INTEGER NOT NULL DEFAULT 0,
 provider_id TEXT NOT NULL DEFAULT '',
 remediation_status TEXT NOT NULL DEFAULT '',
 UNIQUE(assignment_id,recipient_email,kind),
 FOREIGN KEY(assignment_id,recipient_email) REFERENCES remediation_assignment_fyi(assignment_id,recipient_email) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_assignment_notification_queue ON remediation_assignment_notifications(state,not_before,id);
CREATE TRIGGER IF NOT EXISTS assignment_fyi_sent AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='sent' AND OLD.delivery_status!='sent' AND NEW.revoked_at IS NULL
BEGIN
 INSERT OR IGNORE INTO remediation_assignment_notifications(assignment_id,recipient_email,kind,created_at,remediation_status)
 SELECT NEW.id,f.recipient_email,'assigned',NEW.sent_at,r.status FROM remediation_assignment_fyi f JOIN remediations r ON r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id WHERE f.assignment_id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS assignment_fyi_acknowledged AFTER UPDATE OF acknowledged_at ON remediation_assignment_requests
WHEN OLD.acknowledged_at IS NULL AND NEW.acknowledged_at IS NOT NULL AND NEW.revoked_at IS NULL
BEGIN
 INSERT OR IGNORE INTO remediation_assignment_notifications(assignment_id,recipient_email,kind,created_at,remediation_status)
 SELECT NEW.id,f.recipient_email,'acknowledged',NEW.acknowledged_at,r.status FROM remediation_assignment_fyi f JOIN remediations r ON r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id WHERE f.assignment_id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS assignment_fyi_revoked AFTER UPDATE OF revoked_at ON remediation_assignment_requests
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
 UPDATE remediation_assignment_notifications SET state='cancelled',completed_at=NEW.revoked_at WHERE assignment_id=NEW.id AND state IN ('queued','unconfirmed');
END;

-- Additive: no backfill, invented timestamps or changes to existing remediation records.
CREATE TABLE IF NOT EXISTS remediation_record_metadata (
 user_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 assigned_severity TEXT NOT NULL DEFAULT '' CHECK(assigned_severity IN ('','critical','high','medium','low','info')),
 assessed_by TEXT NOT NULL DEFAULT '',
 assessed_at TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(user_id,cve_id),
 FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS remediation_assignment_metadata (
 assignment_id TEXT PRIMARY KEY REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
 assigned_severity TEXT NOT NULL DEFAULT '' CHECK(assigned_severity IN ('','critical','high','medium','low','info'))
);
CREATE TABLE IF NOT EXISTS remediation_status_changes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 previous_status TEXT NOT NULL,
 new_status TEXT NOT NULL,
 reason TEXT NOT NULL CHECK(length(trim(reason)) BETWEEN 1 AND 1000),
 changed_by TEXT NOT NULL,
 changed_at TEXT NOT NULL,
 FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_status_changes_scope ON remediation_status_changes(user_id,cve_id,id DESC);
-- Transaction-scoped write context, inserted and removed in the same D1 batch.
CREATE TABLE IF NOT EXISTS remediation_change_context (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 reason TEXT NOT NULL,
 actor_email TEXT NOT NULL,
 changed_at TEXT NOT NULL,
 expected_updated TEXT NOT NULL,
 PRIMARY KEY(user_id,cve_id)
);
CREATE TRIGGER IF NOT EXISTS remediation_status_reason_required BEFORE UPDATE OF status ON remediations
WHEN OLD.status!=NEW.status
BEGIN
 SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM remediation_change_context c WHERE c.user_id=OLD.user_id AND c.cve_id=OLD.cve_id AND length(trim(c.reason)) BETWEEN 1 AND 1000 AND length(c.actor_email)>0) THEN RAISE(ABORT,'Remediation status change reason required') END;
END;
CREATE TRIGGER IF NOT EXISTS remediation_update_conflict BEFORE UPDATE ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_change_context c WHERE c.user_id=OLD.user_id AND c.cve_id=OLD.cve_id AND c.expected_updated!=OLD.updated_at)
BEGIN SELECT RAISE(ABORT,'Remediation record changed; reload before saving'); END;
CREATE TRIGGER IF NOT EXISTS remediation_status_changed AFTER UPDATE OF status ON remediations
WHEN OLD.status!=NEW.status
BEGIN
 INSERT INTO remediation_status_changes(user_id,cve_id,previous_status,new_status,reason,changed_by,changed_at)
 SELECT NEW.user_id,NEW.cve_id,OLD.status,NEW.status,c.reason,c.actor_email,c.changed_at FROM remediation_change_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id;
END;
CREATE TRIGGER IF NOT EXISTS remediation_insert_conflict BEFORE INSERT ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_change_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id AND c.expected_updated!='')
 AND NOT EXISTS(SELECT 1 FROM remediations r WHERE r.user_id=NEW.user_id AND r.cve_id=NEW.cve_id)
BEGIN SELECT RAISE(ABORT,'Remediation record changed; reload before saving'); END;

-- Additive. New assignments opt into reviewer access; existing invitations are not backfilled.
CREATE TABLE IF NOT EXISTS remediation_review_access (
 assignment_id TEXT PRIMARY KEY REFERENCES remediation_assignment_requests(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL,
 interval_seconds INTEGER CHECK(interval_seconds IN (86400,172800)),
 last_progress_at INTEGER NOT NULL,
 progress_version INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_review_progress_due ON remediation_review_access(last_progress_at,expires_at);
CREATE TABLE IF NOT EXISTS remediation_review_challenges (
 id TEXT PRIMARY KEY,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 code_hash TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 used_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_review_challenge_scope ON remediation_review_challenges(assignment_id,created_at);
CREATE TABLE IF NOT EXISTS remediation_review_sessions (
 token_hash TEXT PRIMARY KEY,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_review_session_scope ON remediation_review_sessions(assignment_id,expires_at);
CREATE TABLE IF NOT EXISTS remediation_review_activity (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 user_id TEXT NOT NULL,
 cve_id TEXT NOT NULL,
 author_email TEXT NOT NULL,
 previous_status TEXT NOT NULL,
 new_status TEXT NOT NULL,
 reason TEXT NOT NULL DEFAULT '' CHECK(length(reason)<=1000),
 comment TEXT NOT NULL DEFAULT '' CHECK(length(comment)<=2000),
 created_at INTEGER NOT NULL,
 FOREIGN KEY(user_id,cve_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_review_activity_scope ON remediation_review_activity(user_id,cve_id,id DESC);
CREATE INDEX IF NOT EXISTS idx_review_activity_assignment ON remediation_review_activity(assignment_id,id DESC);
CREATE TABLE IF NOT EXISTS remediation_review_notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 event_key TEXT NOT NULL,
 assignment_id TEXT NOT NULL REFERENCES remediation_review_access(assignment_id) ON DELETE CASCADE,
 kind TEXT NOT NULL CHECK(kind IN ('progress','reminder')),
 cycle_version INTEGER,
 recipient_email TEXT NOT NULL,
 actor_email TEXT NOT NULL DEFAULT '',
 status_snapshot TEXT NOT NULL DEFAULT '',
 created_at INTEGER NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','unconfirmed','cancelled')),
 not_before INTEGER NOT NULL DEFAULT 0,
 claimed_at INTEGER,
 claim_token TEXT NOT NULL DEFAULT '',
 attempts INTEGER NOT NULL DEFAULT 0,
 completed_at INTEGER,
 provider_id TEXT NOT NULL DEFAULT '',
 UNIQUE(event_key,recipient_email)
);
CREATE INDEX IF NOT EXISTS idx_review_notification_queue ON remediation_review_notifications(state,not_before,id);
CREATE TRIGGER IF NOT EXISTS review_assignment_sent AFTER UPDATE OF delivery_status ON remediation_assignment_requests
WHEN NEW.delivery_status='sent' AND OLD.delivery_status!='sent'
BEGIN UPDATE remediation_review_access SET last_progress_at=NEW.sent_at WHERE assignment_id=NEW.id; END;
-- Any recorded status change is progress. Unchanged saves, acknowledgement and page views do not count.
CREATE TRIGGER IF NOT EXISTS review_status_progress AFTER INSERT ON remediation_status_changes
BEGIN
 UPDATE remediation_review_access SET last_progress_at=CAST(strftime('%s',NEW.changed_at) AS INTEGER),progress_version=progress_version+1
 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=unixepoch() WHERE kind='reminder' AND state='queued'
 AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'status:'||NEW.id,a.id,'progress',a.requester_email,NEW.changed_by,NEW.new_status,CAST(strftime('%s',NEW.changed_at) AS INTEGER)
 FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id
 WHERE a.user_id=NEW.user_id AND a.cve_id=NEW.cve_id AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>unixepoch() AND a.requester_email!=NEW.changed_by;
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'status:'||NEW.id,a.id,'progress',f.recipient_email,NEW.changed_by,NEW.new_status,CAST(strftime('%s',NEW.changed_at) AS INTEGER)
 FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id JOIN remediation_assignment_fyi f ON f.assignment_id=a.id
 WHERE a.user_id=NEW.user_id AND a.cve_id=NEW.cve_id AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>unixepoch() AND f.recipient_email!=NEW.changed_by;
END;
-- A comment accompanying a status change is already covered by the status trigger.
CREATE TRIGGER IF NOT EXISTS review_comment_progress AFTER INSERT ON remediation_review_activity
WHEN NEW.previous_status=NEW.new_status
BEGIN
 UPDATE remediation_review_access SET last_progress_at=NEW.created_at,progress_version=progress_version+1
 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=unixepoch() WHERE kind='reminder' AND state='queued'
 AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'comment:'||NEW.id,a.id,'progress',a.requester_email,NEW.author_email,NEW.new_status,NEW.created_at
 FROM remediation_assignment_requests a WHERE a.id=NEW.assignment_id AND a.requester_email!=NEW.author_email;
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'comment:'||NEW.id,NEW.assignment_id,'progress',f.recipient_email,NEW.author_email,NEW.new_status,NEW.created_at
 FROM remediation_assignment_fyi f WHERE f.assignment_id=NEW.assignment_id AND f.recipient_email!=NEW.author_email;
END;
CREATE TRIGGER IF NOT EXISTS review_assignment_revoked AFTER UPDATE OF revoked_at ON remediation_assignment_requests
WHEN OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
BEGIN
 DELETE FROM remediation_review_sessions WHERE assignment_id=NEW.id;
 DELETE FROM remediation_review_challenges WHERE assignment_id=NEW.id;
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=NEW.revoked_at WHERE assignment_id=NEW.id AND state='queued';
END;
-- Transaction-scoped context: activity is created only by an update that actually succeeds.
CREATE TABLE IF NOT EXISTS remediation_review_write_context (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL,
 assignment_id TEXT NOT NULL,
 author_email TEXT NOT NULL,
 reason TEXT NOT NULL,
 comment TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 PRIMARY KEY(user_id,cve_id)
);
CREATE TRIGGER IF NOT EXISTS review_record_updated AFTER UPDATE OF updated_at ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_review_write_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id)
BEGIN
 INSERT INTO remediation_review_activity(assignment_id,user_id,cve_id,author_email,previous_status,new_status,reason,comment,created_at)
 SELECT c.assignment_id,NEW.user_id,NEW.cve_id,c.author_email,OLD.status,NEW.status,c.reason,c.comment,c.created_at FROM remediation_review_write_context c WHERE c.user_id=NEW.user_id AND c.cve_id=NEW.cve_id;
END;

-- Additive links. Legacy CVE-only records and invitations retain their original keys.
CREATE TABLE IF NOT EXISTS remediation_finding_links (
 user_id TEXT NOT NULL, record_id TEXT NOT NULL, asset_id TEXT NOT NULL REFERENCES inventory_assets(id) ON DELETE CASCADE,
 cve_id TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(user_id,record_id), UNIQUE(user_id,asset_id,cve_id),
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE TRIGGER IF NOT EXISTS finding_link_owned BEFORE INSERT ON remediation_finding_links
BEGIN SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM inventory_assets a JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id JOIN inventory_customers c ON c.id=e.customer_id AND c.user_id=e.user_id WHERE a.id=NEW.asset_id AND a.user_id=NEW.user_id) THEN RAISE(ABORT,'Asset ownership mismatch') END; END;
-- A finding-status row is a projection for existing dashboards and reporting.
CREATE TRIGGER IF NOT EXISTS linked_remediation_status AFTER UPDATE OF status ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_finding_links l WHERE l.user_id=NEW.user_id AND l.record_id=NEW.cve_id)
BEGIN
 INSERT INTO customer_finding_statuses(user_id,asset_id,cve_id,status,notes,updated_at)
 SELECT l.user_id,l.asset_id,l.cve_id,CASE NEW.status WHEN 'Open' THEN 'Needs Review' WHEN 'Investigating' THEN 'Fix in Progress' WHEN 'Remediated' THEN 'Fixed/Patched' ELSE NEW.status END,'',NEW.updated_at
 FROM remediation_finding_links l WHERE l.user_id=NEW.user_id AND l.record_id=NEW.cve_id
 ON CONFLICT(user_id,asset_id,cve_id) DO UPDATE SET status=excluded.status,updated_at=excluded.updated_at;
END;
CREATE TRIGGER IF NOT EXISTS delete_asset_remediation BEFORE DELETE ON inventory_assets
BEGIN DELETE FROM remediations WHERE user_id=OLD.user_id AND cve_id IN (SELECT record_id FROM remediation_finding_links WHERE user_id=OLD.user_id AND asset_id=OLD.id); END;
CREATE TABLE IF NOT EXISTS remediation_owner_comments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,record_id TEXT NOT NULL,
 author_email TEXT NOT NULL,comment TEXT NOT NULL CHECK(length(trim(comment)) BETWEEN 10 AND 2000),created_at INTEGER NOT NULL,
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_owner_comments_scope ON remediation_owner_comments(user_id,record_id,id DESC);
CREATE TRIGGER IF NOT EXISTS owner_comment_progress AFTER INSERT ON remediation_owner_comments
BEGIN
 UPDATE remediation_review_access SET last_progress_at=NEW.created_at,progress_version=progress_version+1 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.record_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=NEW.created_at WHERE kind='reminder' AND state='queued' AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.record_id);
 INSERT OR IGNORE INTO remediation_review_notifications(event_key,assignment_id,kind,recipient_email,actor_email,status_snapshot,created_at)
 SELECT 'owner-comment:'||NEW.id,a.id,'progress',f.recipient_email,NEW.author_email,r.status,NEW.created_at
 FROM remediation_assignment_requests a JOIN remediation_review_access p ON p.assignment_id=a.id JOIN remediation_assignment_fyi f ON f.assignment_id=a.id JOIN remediations r ON r.user_id=a.user_id AND r.cve_id=a.cve_id
 WHERE a.user_id=NEW.user_id AND a.cve_id=NEW.record_id AND a.delivery_status='sent' AND a.revoked_at IS NULL AND p.expires_at>NEW.created_at AND f.recipient_email!=NEW.author_email;

END;

-- Link an existing standalone assignment without changing invitation IDs or tokens.
CREATE TABLE IF NOT EXISTS remediation_link_audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,record_id TEXT NOT NULL,
 asset_id TEXT NOT NULL,cve_id TEXT NOT NULL,retired_record_id TEXT NOT NULL DEFAULT '',
 previous_status TEXT NOT NULL,selected_status TEXT NOT NULL,snapshot_json TEXT NOT NULL,
 linked_by TEXT NOT NULL,linked_at TEXT NOT NULL,
 FOREIGN KEY(user_id,record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_remediation_link_audit ON remediation_link_audit(user_id,record_id,id);
CREATE TABLE IF NOT EXISTS remediation_retired_records (
 user_id TEXT NOT NULL,record_id TEXT NOT NULL,canonical_id TEXT NOT NULL,
 PRIMARY KEY(user_id,record_id),
 FOREIGN KEY(user_id,canonical_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE
);
-- Reject an assignment writer that was already in flight against a retired placeholder.
CREATE TRIGGER IF NOT EXISTS prevent_retired_remediation_insert BEFORE INSERT ON remediations
WHEN EXISTS(SELECT 1 FROM remediation_retired_records WHERE user_id=NEW.user_id AND record_id=NEW.cve_id)
BEGIN SELECT RAISE(ABORT,'This record was linked to an existing assignment; refresh before saving'); END;
-- A concurrent inline finding edit must not be overwritten while the user reviews a link.
CREATE TRIGGER IF NOT EXISTS validate_link_snapshot BEFORE INSERT ON remediation_link_audit
WHEN json_extract(NEW.snapshot_json,'$.finding.updated_at') IS NOT (SELECT updated_at FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
OR json_extract(NEW.snapshot_json,'$.finding.status') IS NOT (SELECT status FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
OR json_extract(NEW.snapshot_json,'$.finding.notes') IS NOT (SELECT notes FROM customer_finding_statuses WHERE user_id=NEW.user_id AND asset_id=NEW.asset_id AND cve_id=NEW.cve_id)
BEGIN SELECT RAISE(ABORT,'The finding changed; review the link again'); END;

-- New status changes only; no historical updates are replayed as email.
CREATE VIEW IF NOT EXISTS remediation_status_participants AS
 SELECT user_id,cve_id,lower(recipient_email) recipient_email FROM remediation_assignment_requests WHERE delivery_status='sent' AND revoked_at IS NULL
 UNION SELECT user_id,cve_id,lower(requester_email) FROM remediation_assignment_requests WHERE delivery_status='sent' AND revoked_at IS NULL
 UNION SELECT a.user_id,a.cve_id,lower(f.recipient_email) FROM remediation_assignment_requests a JOIN remediation_assignment_fyi f ON f.assignment_id=a.id WHERE a.delivery_status='sent' AND a.revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS remediation_status_notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 change_id INTEGER NOT NULL REFERENCES remediation_status_changes(id) ON DELETE CASCADE,
 recipient_email TEXT NOT NULL,
 state TEXT NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','sending','sent','unconfirmed','cancelled')),
 created_at INTEGER NOT NULL DEFAULT(unixepoch()),not_before INTEGER NOT NULL DEFAULT 0,
 claimed_at INTEGER,claim_token TEXT NOT NULL DEFAULT '',completed_at INTEGER,provider_id TEXT NOT NULL DEFAULT '',
 UNIQUE(change_id,recipient_email)
);
CREATE INDEX IF NOT EXISTS idx_status_notification_queue ON remediation_status_notifications(state,not_before,id);
-- Preserve progress/reminder behavior. Replace the incomplete requester/FYI-only
-- status notifications with a deduplicated set of every assignment participant.
DROP TRIGGER IF EXISTS review_status_progress;
CREATE TRIGGER review_status_progress AFTER INSERT ON remediation_status_changes
WHEN NEW.previous_status!=NEW.new_status
BEGIN
 UPDATE remediation_review_access SET last_progress_at=CAST(strftime('%s',NEW.changed_at) AS INTEGER),progress_version=progress_version+1
 WHERE assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 UPDATE remediation_review_notifications SET state='cancelled',completed_at=unixepoch() WHERE kind='reminder' AND state='queued'
 AND assignment_id IN (SELECT id FROM remediation_assignment_requests WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id);
 INSERT OR IGNORE INTO remediation_status_notifications(change_id,recipient_email)
 SELECT NEW.id,recipient_email FROM remediation_status_participants WHERE user_id=NEW.user_id AND cve_id=NEW.cve_id;
END;

INSERT INTO users(id,email) VALUES('pr270-fictional','pr270-fictional@example.invalid');
