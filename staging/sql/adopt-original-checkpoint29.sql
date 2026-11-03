-- Staging-only operational state. Never install this file in production.
CREATE TABLE staging_schema_history (
 path TEXT PRIMARY KEY, sha256 TEXT NOT NULL, manifest_version INTEGER NOT NULL,
 applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE staging_mail (
 id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, subject TEXT NOT NULL,
 recipients_json TEXT NOT NULL, payload_json TEXT NOT NULL,
 scenario TEXT NOT NULL, provider_id TEXT NOT NULL UNIQUE
);

CREATE INDEX staging_mail_created ON staging_mail(created_at DESC,id);

CREATE TABLE staging_job_runs (
 id TEXT PRIMARY KEY, job TEXT NOT NULL, scenario TEXT NOT NULL, actor TEXT NOT NULL,
 started_at INTEGER NOT NULL, finished_at INTEGER, state TEXT NOT NULL CHECK(state IN('running','passed','failed'))
);

CREATE UNIQUE INDEX staging_one_job ON staging_job_runs((1)) WHERE state='running';

CREATE TABLE staging_mail_attachment_chunks (
 mail_id TEXT NOT NULL REFERENCES staging_mail(id) ON DELETE CASCADE,
 attachment_index INTEGER NOT NULL, chunk_index INTEGER NOT NULL, body TEXT NOT NULL,
 PRIMARY KEY(mail_id,attachment_index,chunk_index)
);
INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES('staging/schema.sql','0857a7a6c9ae93f92d2e2f25e21848644cd9bd24b591c04b1f2e5171cdfb7ebd',1);
INSERT INTO staging_schema_history(path,sha256,manifest_version) VALUES('account-backend/schema.sql','b89e3589c3df611f2e9cb1c6f6bc6e49fa928329deb2ba3a2c6c9fae675f0e07',1);
