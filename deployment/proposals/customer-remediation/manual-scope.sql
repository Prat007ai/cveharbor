CREATE TABLE remediation_manual_scopes (
  user_id TEXT NOT NULL,
  record_id TEXT NOT NULL,
  cve_id TEXT NOT NULL,
  customer_key TEXT NOT NULL,
  environment_key TEXT NOT NULL,
  customer_name TEXT NOT NULL CHECK(length(customer_name) BETWEEN 1 AND 100),
  environment_name TEXT NOT NULL CHECK(length(environment_name) <= 100),
  PRIMARY KEY (user_id, record_id),
  UNIQUE (user_id, customer_key, environment_key, cve_id),
  FOREIGN KEY (user_id, record_id) REFERENCES remediations(user_id,cve_id) ON DELETE CASCADE,
  CHECK(substr(record_id,1,length(cve_id)+1)=cve_id||'~')
);
CREATE TRIGGER remediation_manual_scope_immutable BEFORE UPDATE ON remediation_manual_scopes
BEGIN SELECT RAISE(ABORT,'Manual assignment context is immutable'); END;
