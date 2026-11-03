"""Synthetic restore tests only: no remote resources, credentials or real exports."""
import importlib.util
from pathlib import Path
import sqlite3
import tempfile

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('validator', ROOT / 'staging/scripts/verify-recovery-export.py')
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)
original = (ROOT / 'account-backend/schema.sql').read_text()
db = sqlite3.connect(':memory:')
db.executescript(original)
dump = '\n'.join(db.iterdump())
db.close()
with tempfile.TemporaryDirectory() as temp:
    source = Path(temp) / 'synthetic.sql'
    for sql in [original, dump, dump.replace('CREATE TABLE users', 'CREATE TABLE "users"')]:
        source.write_text(sql)
        assert validator.validate_export(source)['local_restore_passed']
    cases = [
        original + '\nCREATE TABLE unexpected(id TEXT);',
        original + "\nINSERT INTO users(id,email) VALUES('synthetic','test@example.invalid');",
        original.replace('email TEXT NOT NULL UNIQUE', 'email TEXT NOT NULL'),
        original + '\nDROP INDEX idx_sessions_user;',
        original.replace('ON DELETE CASCADE', 'ON DELETE RESTRICT', 1),
        original.replace("CHECK (status IN ('sending','sent','empty','failed'))", "CHECK (status IN ('sending','sent','empty','failed','other'))"),
        original + '\nCREATE VIEW bad AS SELECT * FROM users;',
        original + '\nCREATE TRIGGER bad AFTER INSERT ON users BEGIN SELECT 1; END;',
        original + "\nATTACH DATABASE 'file:external?mode=memory' AS other;",
        original + "\nSELECT load_extension('external');",
    ]
    assert cases[2] != original, 'Constraint mutation must change the fixture'
    for sql in cases:
        source.write_text(sql)
        try:
            validator.validate_export(source)
        except (ValueError, sqlite3.Error):
            continue
        raise AssertionError('Invalid export accepted')
print('PASS: three valid local restore cases and ten rejected drift/data/external-access cases.')
