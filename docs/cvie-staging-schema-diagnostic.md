# Read-only schema diagnostic after run #15

Prepared for separate execution approval. No remote diagnostic, migration, continuation, resource mutation or deployment was initiated while preparing this change. PR #243 remains unmerged. This update preserves the intervening permanent-staging integration; it does not activate that integration.

## Investigation and correction

Run #15 attempt 2 at `515e224c093a9102e5075d6daefae2d39c32e2ce` accepted the original `account-backend/schema.sql` batch (29 statements), then returned HTTP 400 / D1 code 7500 for the verifier's 18-term `UNION ALL` table-count query. The read-only reconciliation pass used the same failing query. No later migration files ran.

Cloudflare workerd explicitly sets `SQLITE_LIMIT_COMPOUND_SELECT` to **5** ([pinned source, lines 1482–1494](https://github.com/cloudflare/workerd/blob/bc025717436c0460dfdda68093b029ddbfa9e36a/src/workerd/util/sqlite.c%2B%2B#L1482)). This applies to UNION, UNION ALL and other compound SELECTs. The old query has 18 terms. The regression test sets SQLite's limit to five, reproduces rejection of that exact query shape, then successfully reads all 18 counts with individual SELECTs. The original local SQLite harness had the default, more permissive limit and missed this runtime difference.

The identified compatibility defect is corrected in the shared migration/diagnostic inspector: one quoted-identifier `SELECT count(*) AS n FROM "table"` per request, no UNION and no unbounded SQL construction. Historical provider error text was deliberately omitted from the sanitized run artifact; that artifact alone cannot prove the precise provider error message. This source-backed local reproduction explains the failing query shape without making another live request.

The earlier report also published `actual_state` only after every query succeeded. A count-query failure therefore left the old empty-schema checkpoint visible. The new inspector publishes a new incomplete observation **before** reading, persists schema objects and each completed count as they arrive, and publishes checkpoint matches only after all required reads and consistency checks succeed. Failure clears matches and completeness. A mutation invalidates the current observation before its request; the prior verified step is explicitly historical. Diagnostic failures likewise invalidate any earlier completed observation. A failed final read cannot retain checkpoint 29 as the current confirmed state.

## Frozen reference and proof required

Today's PR head contains a larger permanent-staging manifest with different statement numbering and a ledger. The diagnostic must not interpret its checkpoint 29 as the checkpoint from run #15.

`staging/schema-diagnostic.v1.json` freezes **only the first 29 original statement prefixes**, their schema/count fingerprints and column/index expectations, derived from the original prepared execution plan:

- Original source commit: `515e224c093a9102e5075d6daefae2d39c32e2ce`.
- Original full execution-plan SHA-256: `8f41a391990ade06e9aad08fa848523b273f9ca899e5401e3c6d32fbbd9f9601`.
- Original `account-backend/schema.sql` SHA-256: `b89e3589c3df611f2e9cb1c6f6bc6e49fa928329deb2ba3a2c6c9fae675f0e07`.
- Frozen diagnostic reference SHA-256: **`d2a9af7136414eabe7dc5c74814addbdbb113e43d7edc0c85d8fbaadc1e9248e`**.

Checkpoint 29 expects 18 empty application tables and 10 explicit indexes, plus the automatically created constraint indexes inspected separately. The original first file defines no triggers and inserts no seed/customer/session rows. Any unexpected trigger, view, table, index, row or changed definition prevents confirmation. Both source bytes and reference digest are checked locally before credentials/network use. Checkpoint fingerprints are always identified as belonging to the ORIGINAL plan, never the current expanded manifest.

`first_29_verified=true` requires a full exact original checkpoint-29 match, column/index metadata match, no foreign-key violations, D1 quick-check success, and a second consistent schema/count observation. A partial prefix is reported, not promoted to 29. A false result means the exact reference was not verified; it does not prove that every one of the original statements failed to commit. Unknown objects or data are reported as metadata/count mismatches. No application data is returned to logs or artifacts; seed values are fingerprinted only when the complete schema/count state matches an approved checkpoint. For this reference, approved seed counts are zero, so unexpected data is never fetched. These are stable repeated observations, not a guarantee against all concurrent external activity.

The previous artifact's empty-schema checkpoint is stale evidence. The first batch's success responses and storage growth indicate committed changes, but **checkpoint 29 remains unconfirmed until this approved live diagnostic succeeds**.

## Exact proposed execution scope

Add operation `diagnose-schema` to the existing protected staging workflow's `release` job. Its handler returns before constructing release/migration/deployment clients or performing permanent-profile preflight. It does not require the larger schema, the new private bucket, new Worker flags, readiness endpoints or new secrets to be installed.

Only the existing API token is released to the diagnostic step. Package rebuild/publication steps and the general release execution step are skipped for this operation. Initial pushes and PR events cannot release credentials. Existing repository/branch/exact SHA/explicit operation/protected environment review and concurrency gates remain in force. No new workflow/environment/infrastructure is added.

The runtime permits only:

- GET the exact account identity `9706b4d98ad72884e67fd1eb875c8a61` and exact existing D1 metadata for `cveharbor-accounts-staging`, UUID `fac61562-fc31-426d-8032-550aba63b7f6`.
- POST to that exact database's `/query` endpoint with a **single allowlisted read SQL string**: schema SELECT, one-table counts, approved bounded seed reads, read-only table/index PRAGMAs, `foreign_key_check` and `quick_check`. POST is the REST transport; these statements do not modify database state. No batch, arbitrary SQL, parameters, transaction controls or write PRAGMAs are exposed.
- No Worker, Access, R2, bookmark, import/export, restore, hold, schema-ledger, migration or deployment endpoint. No resource configuration is changed, no background processing enabled, and no synthetic data loaded.

Limits: 2,000 objects, 150 tables, 1,000 seed rows, 1,000 HTTP requests, 100,000 observed D1 rows read, **zero rows written**, and 100,000,000 observed storage bytes. Statement timeouts are 30 seconds; the existing job timeout remains 30 minutes. A single in-flight read can cross a read threshold before execution stops. Missing usage counters, errors, unexpected writes, target mismatch or a failed consistency check stop the operation without retry. Available metrics and partial evidence remain recorded; missing metrics are not reported as zero.

The artifact `schema-diagnostic.json` records fresh object names/types/definition digests, partial or complete table counts, column digests, index metadata, trigger inventory, integrity outcomes, observed original-prefix matches, D1 reads/writes/duration, storage before/after and explicit completeness. It never records raw provider messages, credentials, assertions, application rows or seed values.

## Local validation and approval instructions

**All 64 local staging test groups passed across 16 files**, including nine diagnostic groups and ten migration groups. Full local staging build, egress/build assertions, Node/Python syntax checks and protected-workflow parsing/isolation checks passed. Tests use actual SQLite statements with a five-term compound limit. The diagnostic harness enables SQLite's authorizer to reject writes after fixture setup. Coverage includes original checkpoint 29, partial schemas, extra objects, unexpected rows, API key-order differences, count/final-read failure freshness, wrong targets/digests/commits, missing counters, budget stops, lost response, no retries and release-path isolation. The migration suite exercises the same corrected inspector, including failure of both post-write verification and reconciliation. Local fixture setup is confined to in-memory databases; no Cloudflare calls are made.

Execution is not included in preparation approval. For the separately approved exact implementation commit, set/confirm in existing `cloudflare-cvie-staging`:

```text
CF_STAGING_APPROVED_COMMIT=<full implementation commit supplied with this update>
CF_STAGING_PROVISION_ACTION=diagnose-schema
CF_STAGING_ACCOUNT_ID=9706b4d98ad72884e67fd1eb875c8a61
CF_STAGING_D1_DATABASE_ID=fac61562-fc31-426d-8032-550aba63b7f6
CF_STAGING_SCHEMA_DIAGNOSTIC_SHA256=d2a9af7136414eabe7dc5c74814addbdbb113e43d7edc0c85d8fbaadc1e9248e
```

Existing migration-plan digest and resume variables are **not used** by this read-only operation. Do not set a migration cursor to 29, rerun the old migration, adopt a ledger, reset anything or assume the larger manifest is installed. Codex will initiate only the separately approved diagnostic and the owner will approve its protected environment request. A later continuation needs fresh verified state, reconciliation of original versus current manifest order, and a separate exact execution approval.
