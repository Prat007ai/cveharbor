-- Additive personal-workspace allowance. USD values are integer picodollars.
-- Existing organization ledgers remain unchanged. New accounts start paused.
CREATE TABLE ai_personal_accounts (
 org TEXT PRIMARY KEY REFERENCES users(id), enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1))
);
CREATE TABLE ai_personal_months (
 org TEXT NOT NULL REFERENCES users(id), month TEXT NOT NULL CHECK(length(month)=7),
 allowance INTEGER NOT NULL DEFAULT 20000000000000 CHECK(allowance=20000000000000),
 spent INTEGER NOT NULL DEFAULT 0 CHECK(typeof(spent)='integer' AND spent>=0),
 reserved INTEGER NOT NULL DEFAULT 0 CHECK(typeof(reserved)='integer' AND reserved>=0),
 PRIMARY KEY(org,month), CHECK(spent+reserved<=allowance)
);
CREATE TABLE ai_personal_requests (
 id TEXT PRIMARY KEY, org TEXT NOT NULL, month TEXT NOT NULL, actor TEXT NOT NULL, customer TEXT NOT NULL,
 request_key TEXT NOT NULL, fingerprint TEXT NOT NULL, feature TEXT NOT NULL CHECK(feature='assistance'),
 state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','settled','held','released','blocked')),
 reservation INTEGER NOT NULL CHECK(typeof(reservation)='integer' AND reservation>0),
 charged INTEGER NOT NULL DEFAULT 0 CHECK(typeof(charged)='integer' AND charged>=0 AND charged<=reservation),
 price_id TEXT NOT NULL, model TEXT NOT NULL, input_rate INTEGER NOT NULL, cached_rate INTEGER NOT NULL, output_rate INTEGER NOT NULL,
 input_tokens INTEGER, output_tokens INTEGER, cached_tokens INTEGER, reasoning_tokens INTEGER,
 reason TEXT, created_at INTEGER NOT NULL DEFAULT(unixepoch()), updated_at INTEGER NOT NULL DEFAULT(unixepoch()),
 UNIQUE(org,request_key), FOREIGN KEY(org,month) REFERENCES ai_personal_months(org,month)
);
CREATE INDEX ai_personal_requests_month ON ai_personal_requests(month,org,created_at);
CREATE INDEX ai_personal_requests_actor ON ai_personal_requests(month,actor);
CREATE TRIGGER ai_personal_reserve AFTER INSERT ON ai_personal_requests WHEN NEW.state='reserved' BEGIN
 UPDATE ai_personal_months SET reserved=reserved+NEW.reservation WHERE org=NEW.org AND month=NEW.month;
END;
CREATE TRIGGER ai_personal_request_initial BEFORE INSERT ON ai_personal_requests
WHEN NEW.state NOT IN ('reserved','blocked') OR NEW.charged!=0
BEGIN SELECT RAISE(ABORT,'Invalid AI reservation'); END;
CREATE TRIGGER ai_personal_request_immutable BEFORE UPDATE ON ai_personal_requests
WHEN NEW.id!=OLD.id OR NEW.org!=OLD.org OR NEW.month!=OLD.month OR NEW.actor!=OLD.actor OR NEW.customer!=OLD.customer
 OR NEW.request_key!=OLD.request_key OR NEW.fingerprint!=OLD.fingerprint OR NEW.feature!=OLD.feature
 OR NEW.reservation!=OLD.reservation OR NEW.price_id!=OLD.price_id OR NEW.model!=OLD.model
 OR NEW.input_rate!=OLD.input_rate OR NEW.cached_rate!=OLD.cached_rate OR NEW.output_rate!=OLD.output_rate
 OR NEW.created_at!=OLD.created_at
BEGIN SELECT RAISE(ABORT,'Immutable AI accounting'); END;
CREATE TRIGGER ai_personal_request_transition BEFORE UPDATE ON ai_personal_requests
WHEN NOT ((OLD.state='reserved' AND NEW.state IN ('dispatched','released'))
 OR (OLD.state='dispatched' AND NEW.state IN ('settled','held'))
 OR (OLD.state='held' AND NEW.state='settled'))
 OR (NEW.state!='settled' AND NEW.charged!=0)
BEGIN SELECT RAISE(ABORT,'Invalid AI transition'); END;
CREATE TRIGGER ai_personal_request_settle AFTER UPDATE ON ai_personal_requests WHEN NEW.state IN ('settled','released') BEGIN
 UPDATE ai_personal_months SET reserved=reserved-OLD.reservation,spent=spent+NEW.charged WHERE org=OLD.org AND month=OLD.month;
END;
CREATE TRIGGER ai_personal_request_no_delete BEFORE DELETE ON ai_personal_requests BEGIN SELECT RAISE(ABORT,'Retain AI accounting'); END;
CREATE TRIGGER recovery_hold_ai_personal_accounts_insert BEFORE INSERT ON "ai_personal_accounts" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_accounts_update BEFORE UPDATE ON "ai_personal_accounts" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_accounts_delete BEFORE DELETE ON "ai_personal_accounts" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_months_insert BEFORE INSERT ON "ai_personal_months" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_months_update BEFORE UPDATE ON "ai_personal_months" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_months_delete BEFORE DELETE ON "ai_personal_months" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_requests_insert BEFORE INSERT ON "ai_personal_requests" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_requests_update BEFORE UPDATE ON "ai_personal_requests" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_ai_personal_requests_delete BEFORE DELETE ON "ai_personal_requests" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
