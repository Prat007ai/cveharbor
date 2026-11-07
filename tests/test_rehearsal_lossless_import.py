import importlib.util
from pathlib import Path
import unittest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('lossless_import', root / 'deployment/proposals/production-compatibility/procedure/rehearsal/lossless-import.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def literal(value):
    return "'" + value.replace("'", "''") + "'"


class LosslessImportTests(unittest.TestCase):
    def convert(self, sql):
        original = sql.encode('utf-8')
        converted, report = m.transform(original)
        verified = m.validate(original, converted)
        self.assertTrue(verified['types_and_full_content_equal'])
        self.assertNotIn(m.SCRATCH, verified.get('tables', []) if isinstance(verified.get('tables'), list) else [])
        self.assertLessEqual(report['converted']['max_statement_bytes'], 100000)
        return converted, report, verified

    def test_unicode_quotes_newlines_null_binary_numeric_types_and_rowid(self):
        value = "🌍é漢字 quote' \"; -- not SQL\n\r" * 6000
        _, report, check = self.convert('CREATE TABLE t(id INTEGER PRIMARY KEY,txt TEXT,n,b BLOB,i,r);'
            + f'INSERT INTO t VALUES(9,{literal(value)},NULL,X\'00ff8027\',9223372036854775807,1.25);')
        self.assertEqual(len(report['changes']), 1)
        for key in ('unicode', 'quotes', 'newlines', 'null', 'blob', 'integer', 'real'):
            self.assertGreater(check['coverage'][key], 0)

    def test_oversized_blob_preserves_nul_invalid_utf8_and_blob_storage(self):
        blob = bytes(range(256)) * 500
        _, report, check = self.convert('CREATE TABLE t(id PRIMARY KEY,b BLOB);INSERT INTO t VALUES(1,X\''+blob.hex()+"');")
        self.assertEqual(len(report['changes']), 1)
        self.assertEqual(check['coverage']['blob'], 1)

    def test_complete_values_reach_constraints_and_preexisting_triggers_once(self):
        text = 'z' * 120000
        sql = 'CREATE TABLE t(id INTEGER PRIMARY KEY,v TEXT NOT NULL CHECK(length(v)=120000)); CREATE TABLE audit(v);'
        sql += 'CREATE TRIGGER a AFTER INSERT ON t BEGIN INSERT INTO audit VALUES(length(NEW.v)); INSERT INTO audit VALUES(NEW.id); END;'
        sql += f'INSERT INTO t VALUES(1,{literal(text)}); INSERT INTO audit VALUES(99);'
        self.convert(sql)

    def test_deferred_foreign_keys_original_order_and_multiple_large_columns(self):
        sql = 'PRAGMA defer_foreign_keys=ON; CREATE TABLE p(id PRIMARY KEY);CREATE TABLE c(id REFERENCES p,a,b);'
        sql += f'INSERT INTO c VALUES(1,{literal("é"*55000)},{literal("x"*110000)});INSERT INTO p VALUES(1);'
        _, report, _ = self.convert(sql)
        self.assertEqual(report['scratch_values'], 2)

    def test_unchanged_small_statements_comments_triggers_and_no_final_newline(self):
        sql = "-- header;\nCREATE TABLE t(v);/* ; */ INSERT INTO t VALUES('a;''b');"
        converted, report, _ = self.convert(sql)
        self.assertEqual(converted, sql.encode())
        self.assertEqual(report['changes'], [])

    def test_preflight_rejects_oversize_utf8_bytes_and_incomplete_sql(self):
        with self.assertRaisesRegex(ValueError, 'Oversized'):
            m.preflight(("SELECT '" + 'é'*50000 + "';").encode())
        with self.assertRaisesRegex(ValueError, 'Incomplete|Unclosed'):
            m.preflight(b"INSERT INTO t VALUES('unfinished)")
        with self.assertRaisesRegex(ValueError, 'NUL'):
            m.preflight(b"SELECT '\x00';")

    def test_collision_unsupported_statement_multivalue_and_d1_value_bound_fail_closed(self):
        for sql in ('-- '+m.SCRATCH+'\nSELECT 1;', 'SELECT '+literal('a'*100001)+';',
                    'INSERT INTO t VALUES('+literal('a'*100001)+'),(2);'):
            with self.assertRaises(ValueError): m.transform(sql.encode())
        with self.assertRaisesRegex(ValueError, 'value limit'):
            m.transform(('INSERT INTO t VALUES('+literal('é'*1000001)+');').encode())

    def test_validation_rejects_full_content_type_schema_and_constraint_changes(self):
        original = b'CREATE TABLE t(v);INSERT INTO t VALUES(1);'
        for changed in (b'CREATE TABLE t(v);INSERT INTO t VALUES(2);',
                        b"CREATE TABLE t(v);INSERT INTO t VALUES('1');",
                        b'CREATE TABLE t(v,w);INSERT INTO t VALUES(1,NULL);'):
            with self.assertRaisesRegex(ValueError, 'mismatch'): m.validate(original, changed)
        with self.assertRaises(Exception):
            m.validate(b'CREATE TABLE t(v CHECK(v=1));INSERT INTO t VALUES(2);', original)


if __name__ == '__main__':
    unittest.main()
