-- Operational state only. Never rewrite customer, assignment, token, or history data.
-- Install table guards with scripts/recovery_control.mjs install before deploying the compatible Worker.
CREATE TABLE IF NOT EXISTS operations_control (
 id INTEGER PRIMARY KEY CHECK(id=1),write_hold INTEGER NOT NULL DEFAULT 0 CHECK(write_hold IN(0,1)),
 database_frozen INTEGER NOT NULL DEFAULT 0 CHECK(database_frozen IN(0,1) AND database_frozen<=write_hold),
 revision INTEGER NOT NULL DEFAULT 0,reason TEXT NOT NULL DEFAULT '',changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO operations_control(id) VALUES(1);
CREATE TABLE IF NOT EXISTS operations_leases (
 id TEXT PRIMARY KEY,kind TEXT NOT NULL CHECK(kind IN('fetch','scheduled')),started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS operations_events (
 id INTEGER PRIMARY KEY AUTOINCREMENT,write_hold INTEGER NOT NULL,database_frozen INTEGER NOT NULL,revision INTEGER NOT NULL,reason TEXT NOT NULL,changed_at TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS operations_control_history AFTER UPDATE ON operations_control
BEGIN INSERT INTO operations_events(write_hold,database_frozen,revision,reason,changed_at) VALUES(NEW.write_hold,NEW.database_frozen,NEW.revision,NEW.reason,NEW.changed_at); END;
CREATE TRIGGER IF NOT EXISTS recovery_hold_new_lease BEFORE INSERT ON operations_leases
WHEN COALESCE((SELECT write_hold FROM operations_control WHERE id=1),1)!=0
BEGIN SELECT RAISE(ABORT,'CVEHarbor recovery write hold'); END;
