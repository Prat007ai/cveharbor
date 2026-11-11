-- Additive proposal. Execute only after exact owner approval and recovery preflight.
-- Retain aggregate history; no deletion job, backfill, or edits to existing records.
CREATE TABLE workspace_finding_daily_snapshots (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 day TEXT NOT NULL CHECK (length(day)=10 AND date(day,'+0 days') IS NOT NULL AND day=date(day,'+0 days')),
 captured_at TEXT NOT NULL CHECK (date(captured_at) IS NOT NULL AND date(captured_at)=day),
 metric_version INTEGER NOT NULL CHECK (metric_version=1),
 needs_review INTEGER NOT NULL CHECK (typeof(needs_review)='integer' AND needs_review>=0),
 in_progress INTEGER NOT NULL CHECK (typeof(in_progress)='integer' AND in_progress>=0),
 fixed INTEGER NOT NULL CHECK (typeof(fixed)='integer' AND fixed>=0),
 accepted_risk INTEGER NOT NULL CHECK (typeof(accepted_risk)='integer' AND accepted_risk>=0),
 not_applicable INTEGER NOT NULL CHECK (typeof(not_applicable)='integer' AND not_applicable>=0),
 inventory_records INTEGER NOT NULL CHECK (typeof(inventory_records)='integer' AND inventory_records>=0),
 PRIMARY KEY (user_id,day)
);
CREATE TRIGGER recovery_hold_workspace_finding_daily_snapshots_insert BEFORE INSERT ON "workspace_finding_daily_snapshots" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_workspace_finding_daily_snapshots_update BEFORE UPDATE ON "workspace_finding_daily_snapshots" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
CREATE TRIGGER recovery_hold_workspace_finding_daily_snapshots_delete BEFORE DELETE ON "workspace_finding_daily_snapshots" WHEN COALESCE((SELECT database_frozen FROM operations_control WHERE id=1),1)!=0 BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
