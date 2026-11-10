-- Reviewed and installed separately from application publication.
CREATE TABLE team_organizations (
  id TEXT PRIMARY KEY,
  created_by TEXT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  data_owner TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  name TEXT NOT NULL CHECK(length(trim(name)) BETWEEN 1 AND 100)
);
CREATE TABLE team_members (
  id TEXT PRIMARY KEY,
  org TEXT NOT NULL REFERENCES team_organizations(id) ON DELETE CASCADE,
  email TEXT NOT NULL COLLATE NOCASE,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('Owner','Editor','Viewer')),
  scope TEXT NOT NULL CHECK(scope IN ('all','selected')),
  customers TEXT NOT NULL CHECK(json_valid(customers) AND json_type(customers)='array'),
  token_hash TEXT UNIQUE,
  expires INTEGER,
  revision INTEGER NOT NULL DEFAULT 1,
  UNIQUE(org,email), UNIQUE(org,user_id),
  CHECK(role!='Owner' OR scope='all'),
  CHECK((scope='all' AND json_array_length(customers)=0) OR (scope='selected' AND json_array_length(customers)>0)),
  CHECK((user_id IS NULL AND token_hash IS NOT NULL AND expires IS NOT NULL)
     OR (user_id IS NOT NULL AND token_hash IS NULL AND expires IS NULL))
);
CREATE INDEX team_members_user ON team_members(user_id,org);
CREATE TRIGGER team_keep_owner_update BEFORE UPDATE OF role ON team_members
WHEN OLD.role='Owner' AND OLD.user_id IS NOT NULL AND NEW.role!='Owner'
 AND NOT EXISTS(SELECT 1 FROM team_members WHERE org=OLD.org AND id!=OLD.id AND user_id IS NOT NULL AND role='Owner')
BEGIN SELECT RAISE(ABORT,'Keep an active workspace Owner'); END;
CREATE TRIGGER team_keep_owner_delete BEFORE DELETE ON team_members
WHEN OLD.role='Owner' AND OLD.user_id IS NOT NULL
 AND NOT EXISTS(SELECT 1 FROM team_members WHERE org=OLD.org AND id!=OLD.id AND user_id IS NOT NULL AND role='Owner')
BEGIN SELECT RAISE(ABORT,'Keep an active workspace Owner'); END;
CREATE TABLE team_last_login (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  signed_at INTEGER NOT NULL
);
INSERT INTO team_last_login SELECT user_id,MAX(created_at) FROM sessions GROUP BY user_id;
CREATE TRIGGER team_track_login AFTER INSERT ON sessions BEGIN
  INSERT INTO team_last_login VALUES(NEW.user_id,NEW.created_at)
  ON CONFLICT(user_id) DO UPDATE SET signed_at=MAX(signed_at,excluded.signed_at);
END;
CREATE TRIGGER team_scope_insert BEFORE INSERT ON team_members
WHEN EXISTS(SELECT 1 FROM json_each(NEW.customers) j WHERE j.type!='text' OR NOT EXISTS(
  SELECT 1 FROM inventory_customers c JOIN team_organizations o ON o.data_owner=c.user_id WHERE o.id=NEW.org AND c.id=j.value))
BEGIN SELECT RAISE(ABORT,'Invalid team customer'); END;
CREATE TRIGGER team_scope_update BEFORE UPDATE OF customers,org ON team_members
WHEN EXISTS(SELECT 1 FROM json_each(NEW.customers) j WHERE j.type!='text' OR NOT EXISTS(
  SELECT 1 FROM inventory_customers c JOIN team_organizations o ON o.data_owner=c.user_id WHERE o.id=NEW.org AND c.id=j.value))
BEGIN SELECT RAISE(ABORT,'Invalid team customer'); END;
CREATE VIEW team_visible_customers AS
SELECT o.id AS org,o.data_owner,m.user_id AS actor,m.role,c.id AS customer_id,c.name
FROM team_organizations o JOIN team_members m ON m.org=o.id AND m.user_id IS NOT NULL
JOIN inventory_customers c ON c.user_id=o.data_owner
WHERE m.scope='all' OR EXISTS(SELECT 1 FROM json_each(m.customers) j WHERE j.value=c.id);
CREATE VIEW team_scoped_records AS
SELECT s.user_id AS data_owner,s.customer_id,s.record_id FROM remediation_customer_scopes s
UNION
SELECT l.user_id,e.customer_id,l.record_id FROM remediation_finding_links l
JOIN inventory_assets a ON a.id=l.asset_id AND a.user_id=l.user_id
JOIN inventory_environments e ON e.id=a.environment_id AND e.user_id=a.user_id;
CREATE TABLE team_audit (
  id INTEGER PRIMARY KEY,org TEXT NOT NULL REFERENCES team_organizations(id),actor TEXT NOT NULL,
  action TEXT NOT NULL, target TEXT NOT NULL, customer_id TEXT, at INTEGER NOT NULL DEFAULT(unixepoch()),
  authorized INTEGER NOT NULL CHECK(authorized=1)
);
CREATE INDEX team_audit_customer ON team_audit(org,customer_id,id);

CREATE TRIGGER IF NOT EXISTS recovery_hold_team_organizations_insert BEFORE INSERT ON "team_organizations" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_organizations_update BEFORE UPDATE ON "team_organizations" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_organizations_delete BEFORE DELETE ON "team_organizations" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_members_insert BEFORE INSERT ON "team_members" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_members_update BEFORE UPDATE ON "team_members" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_members_delete BEFORE DELETE ON "team_members" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_last_login_insert BEFORE INSERT ON "team_last_login" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_last_login_update BEFORE UPDATE ON "team_last_login" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_last_login_delete BEFORE DELETE ON "team_last_login" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_audit_insert BEFORE INSERT ON "team_audit" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_audit_update BEFORE UPDATE ON "team_audit" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_team_audit_delete BEFORE DELETE ON "team_audit" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
