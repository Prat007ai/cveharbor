"""Exercise generated repair SQL with the observed D1 expression limit, not SQLite's default."""
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
PROCEDURE = ROOT / 'deployment/proposals/production-compatibility/procedure'


def statements(sql):
    pending = ''
    for char in sql:
        pending += char
        if char == ';' and sqlite3.complete_statement(pending):
            yield pending
            pending = ''
    if pending.strip() and not all(line.strip().startswith('--') for line in pending.splitlines() if line.strip()):
        raise AssertionError('Incomplete generated SQL')


class RepairDepthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = """
import {syntheticSQL,markerSQL,previousPlan,rehearsalJournalObjects,journalCorrectionSQL} from './deployment/proposals/production-compatibility/procedure/rehearsal/artifacts.mjs';
import {sqlFiles,originalTables} from './deployment/proposals/production-compatibility/procedure/build.mjs';
import {triggerUpgradeTemplate} from './deployment/proposals/production-compatibility/procedure/pr272-transition.mjs';
import {schemaSQL} from './scripts/production_schema_baseline.mjs';
console.log(JSON.stringify({upgrade:triggerUpgradeTemplate(),baseline:syntheticSQL(),files:sqlFiles(),tables:originalTables(),schemaSQL,markerSQL,previousPlan:previousPlan(),previousJournalRows:rehearsalJournalObjects(true),correction:journalCorrectionSQL()}));
"""
        cls.artifacts = json.loads(subprocess.check_output(['node', '--input-type=module', '-e', script], cwd=ROOT, encoding='utf-8'))

    def database(self, old=False, installed_272=False):
        db = sqlite3.connect(':memory:', isolation_level=None)
        db.row_factory = sqlite3.Row
        self.addCleanup(db.close)
        db.executescript('PRAGMA foreign_keys=ON;\n' + self.artifacts['baseline'])
        for name, limit in [('EXPR_DEPTH', 100), ('FUNCTION_ARG', 32), ('VARIABLE_NUMBER', 100), ('SQL_LENGTH', 100000), ('COLUMN', 100), ('LENGTH', 2000000)]:
            db.setlimit(getattr(sqlite3, 'SQLITE_LIMIT_' + name), limit)
            self.assertEqual(db.getlimit(getattr(sqlite3, 'SQLITE_LIMIT_' + name)), limit)
        sql = (PROCEDURE / 'rehearsal/previous-bootstrap.sql').read_text(encoding='utf-8') if old else self.artifacts['files']['bootstrap.sql']
        if installed_272:
            sql = (PROCEDURE / "pr272-installed-bootstrap.sql").read_text(encoding="utf-8")
        self.run_sql(db, sql)
        return db

    def run_sql(self, db, sql, payload=None):
        # No wrapping transaction: a failing first assertion must stop before DDL.
        for statement in statements(sql):
            self.assertLessEqual(len(statement.encode()), 100000)
            # Version 2 requires the approved live run's payload at release.
            db.execute(statement, (payload,) if '?1' in statement else ())

    def snapshot(self, db, operation='install'):
        now = int(time.time())
        return dict(version=1, operation=operation, not_before=now-1, expires_at=now+600,
                    schema_rows=[dict(r) for r in db.execute(self.artifacts['schemaSQL'])],
                    counts={t: db.execute('SELECT COUNT(*) FROM "'+t+'"').fetchone()[0] for t in self.artifacts['tables']},
                    approval_id='fictional-depth-test', expected_revision=0)

    def insert(self, db, name, payload):
        db.execute('INSERT INTO d1_cveharbor_repair_receipts(id,payload) VALUES(?,?)', (name, json.dumps(payload)))

    def claim(self, db, payload=None):
        payload = payload if payload is not None else self.snapshot(db)
        self.insert(db, 'install-intent', payload)
        self.run_sql(db, self.artifacts['files']['install-start.sql'])
        return payload

    def installed(self):
        db = self.database()
        self.claim(db)
        self.run_sql(db, self.artifacts['files']['install.sql'])
        return db

    def frozen(self, db):
        self.assertEqual(tuple(db.execute('SELECT write_hold,database_frozen,revision FROM operations_control').fetchone()), (1, 1, 0))

    def test_original_exact_bootstrap_reproduces_depth_failure(self):
        old = (PROCEDURE / 'rehearsal/previous-bootstrap.sql').read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(), '01e3ef913b44194b26aecf0e103b077ca5a144ea84a09db8c1f227a0501ef98c')
        db = self.database(old=True)
        with self.assertRaisesRegex(sqlite3.OperationalError, r'Expression tree is too large \(maximum depth 100\)'):
            self.insert(db, 'install-intent', self.snapshot(db))
        self.assertEqual(db.execute('SELECT COUNT(*) FROM d1_cveharbor_repair_receipts').fetchone()[0], 0)

    def test_corrected_claim_install_and_separate_resume(self):
        db = self.installed()
        self.frozen(db)
        self.insert(db, 'resume-intent', self.snapshot(db, 'resume'))
        self.run_sql(db, self.artifacts['files']['resume-start.sql'])
        self.run_sql(db, self.artifacts['files']['resume.sql'])
        self.assertEqual(tuple(db.execute('SELECT write_hold,database_frozen,revision FROM operations_control').fetchone()), (0, 0, 1))
        self.assertEqual(db.execute('SELECT COUNT(*) FROM operations_events').fetchone()[0], 1)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM d1_cveharbor_repair_receipts').fetchone()[0], 5)
        self.assertEqual(list(db.execute('PRAGMA foreign_key_check')), [])

    def test_upgrade_installed_272_then_release_only_exact_separate_run(self):
        db = self.database(installed_272=True)
        table = 'd1_cveharbor_repair_receipts'
        install = dict(self.snapshot(db), run_id='90001')
        self.claim(db, install)
        self.run_sql(db, self.artifacts['files']['install.sql'])
        raw = json.dumps(install)
        rows = lambda: [tuple(r) for r in db.execute('SELECT rowid,* FROM '+table+' ORDER BY rowid')]
        original = rows()
        target = json.loads((PROCEDURE/'target.json').read_text())
        resume = dict(self.snapshot(db, 'resume'), version=2, run_id='90002', approval_id='fictional-resume',
                      database=target['database'], account=target['account'], source_sha='a'*40,
                      verification_sha256='c'*64, preflight_sha256='c'*64,
                      install_receipt_sha256=hashlib.sha256(raw.encode()).hexdigest(),
                      sql_sha256=hashlib.sha256(self.artifacts['files']['resume.sql'].encode()).hexdigest(),
                      resume_scheduled_work_and_eligible_email=True)
        del resume['not_before'], resume['expires_at']
        with self.assertRaises(sqlite3.IntegrityError):
            self.insert(db, 'resume-intent', resume)
        upgrade = self.artifacts['upgrade']
        with self.assertRaises(sqlite3.OperationalError):
            self.run_sql(db, upgrade, raw+' ')
        self.assertEqual(rows(), original)
        self.run_sql(db, upgrade, raw)
        with self.assertRaises(sqlite3.OperationalError):
            self.run_sql(db, upgrade, raw)
        self.assertEqual(rows(), original)
        self.frozen(db)
        for change in (dict(run_id=install['run_id']), dict(expected_revision=1),
                       dict(resume_scheduled_work_and_eligible_email=False), dict(expires_at=None)):
            with self.subTest(change=change), self.assertRaises(sqlite3.IntegrityError):
                self.insert(db, 'resume-intent', dict(resume, **change))
        self.insert(db, 'resume-intent', resume)
        self.run_sql(db, self.artifacts['files']['resume-start.sql'])
        release = self.artifacts['files']['resume.sql']
        self.run_sql(db, release, json.dumps(dict(resume, run_id='90003')))
        self.frozen(db)
        db.create_function('strftime', 2, lambda *_: str(install['expires_at'] + 7200))
        self.run_sql(db, release, json.dumps(resume))
        self.assertEqual(tuple(db.execute('SELECT write_hold,database_frozen,revision FROM operations_control').fetchone()), (0, 0, 1))
        self.assertEqual(rows()[:3], original)

    def test_invalid_approval_formats_rejected_at_each_install_boundary(self):
        now = 1800000000
        for boundary in ('receipt', 'install'):
            db = self.database()
            db.create_function('strftime', 2, lambda *_: str(now))
            base = dict(self.snapshot(db), not_before=now-10, expires_at=now+10)
            cases = {
                'missing version': {k: v for k, v in base.items() if k != 'version'},
                'version 3': dict(base, version=3),
                '3610 seconds': dict(base, expires_at=now+3600),
                '1801 seconds': dict(base, expires_at=now+1791),
                'expired': dict(base, not_before=now-10, expires_at=now-1),
                'future': dict(base, not_before=now+1),
                'reversed': dict(base, not_before=now+1, expires_at=now-1),
                'missing start': {k: v for k, v in base.items() if k != 'not_before'},
                'null end': dict(base, expires_at=None),
                'string end': dict(base, expires_at=str(now+10)),
                'real start': dict(base, not_before=float(now-10)),
            }
            for label, value in [('null', None), ('string', '1'), ('real', 1.0), ('boolean', True),
                                 ('array', [1]), ('object', {'version': 1})]:
                cases[label + ' version'] = dict(base, version=value)
            on_demand = {k: v for k, v in base.items() if k not in ('not_before', 'expires_at')}
            on_demand.update(version=2, run_id='1234', source_sha='a'*40,
                             database=json.loads((PROCEDURE/'target.json').read_text())['database'])
            cases.update({'v2 with start': dict(on_demand, not_before=now),
                          'v2 with null end': dict(on_demand, expires_at=None),
                          'v2 real version': dict(on_demand, version=2.0)})
            raw_cases = {label: json.dumps(payload) for label, payload in cases.items()}
            for key, value in [('version', 3), ('not_before', 0), ('expires_at', 0)]:
                raw_cases['duplicate ' + key] = json.dumps(base)[:-1] + f', "{key}": {value}}}'
            table = 'd1_cveharbor_repair_receipts'
            trigger = table + '_sequence'
            trigger_sql = db.execute('SELECT sql FROM sqlite_schema WHERE name=?', (trigger,)).fetchone()[0]
            insert = 'INSERT INTO '+table+'(id,payload) VALUES(?,?)'
            for case, raw in raw_cases.items():
                with self.subTest(boundary=boundary, case=case):
                    db.execute('SAVEPOINT invalid_format')
                    try:
                        if boundary == 'receipt':
                            with self.assertRaisesRegex(sqlite3.IntegrityError, 'Repair approval'):
                                db.execute(insert, ('install-intent', raw))
                            self.assertEqual(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0], 0)
                        else:
                            # Seed matching but invalid claims locally, restoring the actual trigger
                            # before the batch so the second boundary is tested independently.
                            db.execute('DROP TRIGGER '+trigger)
                            db.executemany(insert, [('install-intent', raw), ('install-started', raw)])
                            db.execute(trigger_sql)
                            with self.assertRaisesRegex(sqlite3.OperationalError, 'malformed JSON'):
                                self.run_sql(db, self.artifacts['files']['install.sql'])
                            self.assertEqual(db.execute('SELECT COUNT(*) FROM '+table).fetchone()[0], 2)
                            self.assertIsNone(db.execute("SELECT 1 FROM sqlite_schema WHERE name='operations_control'").fetchone())
                    finally:
                        db.execute('ROLLBACK TO invalid_format')
                        db.execute('RELEASE invalid_format')

    def test_exactly_1800_seconds_is_valid_at_both_window_endpoints(self):
        for offset in (0, 1800):
            db = self.database()
            start = 1800000000
            db.create_function('strftime', 2, lambda *_: str(start+offset))
            self.claim(db, dict(self.snapshot(db), not_before=start, expires_at=start+1800))
            self.run_sql(db, self.artifacts['files']['install.sql'])
            self.frozen(db)

    def test_every_missing_or_null_count_rejected_by_receipt(self):
        db = self.database()
        valid = self.snapshot(db)
        for table in self.artifacts['tables']:
            for missing in (False, True):
                with self.subTest(table=table, missing=missing):
                    p = copy.deepcopy(valid)
                    if missing: del p['counts'][table]
                    else: p['counts'][table] = None
                    with self.assertRaises(sqlite3.IntegrityError): self.insert(db, 'install-intent', p)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM d1_cveharbor_repair_receipts').fetchone()[0], 0)

    def test_missing_null_schema_clock_and_bad_snapshot_rejected(self):
        db = self.database()
        for key in ('schema_rows', 'counts', 'not_before', 'expires_at'):
            for missing in (False, True):
                p = self.snapshot(db)
                if missing: del p[key]
                else: p[key] = None
                with self.subTest(key=key, missing=missing), self.assertRaises(sqlite3.IntegrityError): self.insert(db, 'install-intent', p)
        for kind in ('schema', 'count', 'expired', 'future'):
            p = self.snapshot(db)
            if kind == 'schema': p['schema_rows'][0]['sql'] += ' changed'
            if kind == 'count': p['counts']['users'] += 1
            if kind == 'expired': p['expires_at'] = 1
            if kind == 'future': p['not_before'] += 1000
            with self.subTest(kind=kind), self.assertRaises(sqlite3.IntegrityError): self.insert(db, 'install-intent', p)

    def test_integrity_and_foreign_key_rejection_even_with_matching_snapshot(self):
        for foreign in (False, True):
            db = self.database()
            if foreign: db.execute('PRAGMA foreign_keys=OFF')
            db.execute("INSERT INTO remediations(user_id,cve_id,status,updated_at) VALUES(?,?, 'Open','2026-11-06')", ('absent' if foreign else 'pr270-fictional', 'CVE-2026-999999' if foreign else 'CVE-2026-999999~ABC'))
            with self.subTest(foreign=foreign), self.assertRaises(sqlite3.IntegrityError): self.insert(db, 'install-intent', self.snapshot(db))

    def test_install_write_boundary_rejects_drift_expiry_and_invalid_operation(self):
        for drift in ('schema', 'count', 'expired', 'null-operation', 'missing-operation', 'wrong-operation', 'absent-claim'):
            db = self.database()
            p = self.snapshot(db)
            if drift == 'null-operation': p['operation'] = None
            if drift == 'missing-operation': del p['operation']
            if drift == 'wrong-operation': p['operation'] = 'resume'
            if drift != 'absent-claim': self.claim(db, p)
            if drift == 'schema': db.execute('CREATE TABLE unexpected(id TEXT)')
            if drift == 'count': db.execute("INSERT INTO users(id,email) VALUES('extra','extra@example.invalid')")
            if drift == 'expired': db.create_function('strftime', 2, lambda *_: str(p['expires_at']+1))
            before = [tuple(r) for r in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name')]
            with self.subTest(drift=drift), self.assertRaises(sqlite3.OperationalError): self.run_sql(db, self.artifacts['files']['install.sql'])
            self.assertEqual([tuple(r) for r in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name')], before)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM d1_cveharbor_repair_receipts WHERE id='installed'").fetchone()[0], 0)

    def test_resume_write_boundary_keeps_hold_for_drift_expiry_bad_revision_or_missing_claim(self):
        for drift in ('schema', 'count', 'expired', 'revision', 'absent-claim'):
            db = self.installed()
            p = self.snapshot(db, 'resume')
            if drift == 'revision': p['expected_revision'] = 99
            if drift != 'absent-claim':
                self.insert(db, 'resume-intent', p)
                self.run_sql(db, self.artifacts['files']['resume-start.sql'])
            if drift == 'schema': db.execute('CREATE TABLE unexpected(id TEXT)')
            if drift == 'count':
                # Inject corruption while restoring the exact schema; ordinary writes are frozen.
                triggers = list(db.execute("SELECT name,sql FROM sqlite_schema WHERE type='trigger' AND tbl_name='users'"))
                for r in triggers: db.execute('DROP TRIGGER "'+r['name']+'"')
                db.execute("INSERT INTO users(id,email) VALUES('extra','extra@example.invalid')")
                for r in triggers: db.execute(r['sql'])
            if drift == 'expired': db.create_function('strftime', 2, lambda *_: str(p['expires_at']+1))
            self.run_sql(db, self.artifacts['files']['resume.sql'])
            with self.subTest(drift=drift): self.frozen(db)

    def test_resume_receipt_rejects_missing_and_null_evidence(self):
        db = self.installed()
        for key in ('schema_rows', 'counts', 'not_before', 'expires_at'):
            for missing in (False, True):
                p = self.snapshot(db, 'resume')
                if missing: del p[key]
                else: p[key] = None
                with self.subTest(key=key, missing=missing), self.assertRaises(sqlite3.IntegrityError): self.insert(db, 'resume-intent', p)
        self.frozen(db)

    def test_generated_sizes_and_parameter_payload(self):
        db = self.database()
        payload = json.dumps(self.snapshot(db)).encode()
        self.assertLess(len(payload), 2000000)
        for name, sql in self.artifacts['files'].items():
            with self.subTest(file=name):
                self.assertLess(len(sql.encode()), 100000)
                for statement in statements(sql): self.assertLess(len(statement.encode()), 100000)

    def preserved(self):
        db = self.database(old=True)
        self.run_sql(db, self.artifacts['markerSQL'])
        db.execute("INSERT INTO d1_pr270_rehearsal_attempts(id,payload) VALUES('plan',?)", (self.artifacts['previousPlan'],))
        return db

    def correction(self, db):
        p = self.snapshot(db)
        p.update(previous_plan=self.artifacts['previousPlan'], previous_journal_rows=self.artifacts['previousJournalRows'])
        return p

    def correct_journal(self, db, payload):
        sql = self.artifacts['correction'].replace('?1', "'" + json.dumps(payload).replace("'", "''") + "'", 1)
        self.assertLess(len(sql.encode()), 100000)
        self.run_sql(db, sql)

    def test_preserved_empty_journal_correction_then_claim_and_install_at_depth_100(self):
        db = self.preserved()
        before = {r['name']:r['sql'] for r in db.execute("SELECT name,sql FROM sqlite_schema WHERE name GLOB 'd1_*'")}
        self.correct_journal(db, self.correction(db))
        after = {r['name']:r['sql'] for r in db.execute("SELECT name,sql FROM sqlite_schema WHERE name GLOB 'd1_*'")}
        self.assertEqual([name for name in before if before[name] != after[name]], ['d1_cveharbor_repair_receipts_sequence'])
        self.assertEqual(db.execute('SELECT COUNT(*) FROM d1_cveharbor_repair_receipts').fetchone()[0], 0)
        self.assertEqual(db.execute('SELECT payload FROM d1_pr270_rehearsal_attempts').fetchone()[0], self.artifacts['previousPlan'])
        self.claim(db)
        self.run_sql(db, self.artifacts['files']['install.sql'])
        self.frozen(db)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM users').fetchone()[0], 1)

    def test_journal_correction_rejects_unexpected_state_before_trigger_replacement(self):
        for drift in ('plan', 'journal', 'receipt', 'schema', 'count', 'expired', 'null-schema', 'missing-counts', 'missing-journal', 'already-corrected'):
            db = self.preserved()
            p = self.correction(db)
            if drift == 'plan': p['previous_plan'] = '{}'
            if drift == 'journal': db.execute('DROP TRIGGER d1_cveharbor_repair_receipts_immutable_delete')
            if drift == 'receipt':
                old = db.execute("SELECT sql FROM sqlite_schema WHERE name='d1_cveharbor_repair_receipts_sequence'").fetchone()[0]
                db.execute('DROP TRIGGER d1_cveharbor_repair_receipts_sequence')
                self.insert(db, 'install-intent', self.snapshot(db))
                db.execute(old)
            if drift == 'schema': db.execute('CREATE TABLE unexpected(id TEXT)')
            if drift == 'count': db.execute("INSERT INTO users(id,email) VALUES('extra','extra@example.invalid')")
            if drift == 'expired': p['expires_at'] = 1
            if drift == 'null-schema': p['schema_rows'] = None
            if drift == 'missing-counts': del p['counts']
            if drift == 'missing-journal': del p['previous_journal_rows']
            if drift == 'already-corrected': self.correct_journal(db, p)
            before = [tuple(r) for r in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name')]
            with self.subTest(drift=drift), self.assertRaises(sqlite3.OperationalError): self.correct_journal(db, p)
            self.assertEqual([tuple(r) for r in db.execute('SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY name')], before)


if __name__ == '__main__':
    unittest.main()
