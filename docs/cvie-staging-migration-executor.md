> **Historical staging procedure.** The integrated permanent-staging implementation supersedes these commands and schema counts. Use [the permanent staging activation runbook](reviews/permanent-staging-activation.md). Earlier operation names, hashes and approvals do not authorize the new migration or deployment. This document remains as historical evidence.

# Task 2C staging migration executor: execution approval record

Implementation is prepared in PR #243. **Remote execution is not approved and has not been initiated.** Use the final implementation commit returned with this update; approving the earlier frontend deployment does not approve SQL. PR #243 stays draft and unmerged; PR #252 remains on hold.

## Exact proposed scope

Run operation `migrate-schema` in the existing protected `cloudflare-cvie-staging` job. Only account `9706b4d98ad72884e67fd1eb875c8a61`, D1 database `cveharbor-accounts-staging` / `fac61562-fc31-426d-8032-550aba63b7f6` can receive SQL. No Wrangler default config, generic Cloudflare credentials or SDK retry mechanism is used. No production requests, resources, new environment/workflow, Worker uploads, binding/flag changes, Access-policy writes, migrations of another database, synthetic fixtures, external imports, email or scheduled/background processing belong in this operation.

Bootstrap comprises the base schema, the fourteen auxiliary schema files, and migrations 0016–0027 in the existing approved order, followed by separate 0028 and 0029. The executor submits **29 source-file batches / 370 original SQL statements**, rather than a monolithic bootstrap request. This preserves exact source SQL and allows a verified stop between files. Built-in registry/catalogue seeds and the existing maintenance timestamp are included. No bookkeeping table is added. Final expected schema: **89 application tables**, plus SQLite's internal `sqlite_sequence` and Cloudflare's own internal metadata. The earlier 90-table local report included `sqlite_sequence`; SQL has not changed.

## Checksums (SHA-256)

| Input | Digest |
| --- | --- |
| Aggregate bootstrap through 0027 | `57befd33127ce367729110ed592635d374af2f6d8f93279ccef3877da851974a` |
| 0028_cvie_source_efficiency.sql | `a713d16f9621a724f0df2b8506f7267e216cc45bc6539ba5415c86e5c754551a` |
| 0029_cvie_identity_registry.sql | `315b31b8d66ff745aa2478594cd0ef787d8ec0b8c2c3f3ad163bc94f52f1bef3` |
| Generated execution plan, including every statement/checkpoint | `8f41a391990ade06e9aad08fa848523b273f9ca899e5401e3c6d32fbbd9f9601` |

[Every input-file digest](cvie-evidence/staging-schema-plan-manifest.json) · [Machine-readable execution approval scope](cvie-evidence/staging-schema-executor-approval.json).

`python staging/scripts/migration-plan.py` validates approved source bytes and bootstrap digest, executes all statements in local SQLite, checks foreign keys after every statement and integrity at completion, and generates deterministic checkpoints under ignored `staging/.build/schema/`. The protected job regenerates it without credentials before its authorization check. The executor checks both the committed plan digest and the protected environment's digest, plus all 29 SQL source hashes. The CI preparation artifact includes the generated plan for review. Local SQLite engine differences that change a fingerprint or plan digest fail closed; do not update an approved digest just to pass a remote run.

## Identity, state, invariants and resume

- Existing repository/branch, exact checkout/run/approved SHA, explicit operation and manual rerun/dispatch gates remain. Initial pushes cannot execute the write job. A migration additionally requires the exact pinned database UUID, plan digest and explicit starting checkpoint.
- Fresh preflight must accept the existing staging account, database and Access configuration. GET-only inventory must verify both existing Workers, bindings, variables, private API exposure, frontend assets gate and disabled schedules. The live Access boundary probes must pass before SQL.
- The initial approved start is **step 0, an empty application schema**. The database's schema objects, table counts and seeded row fingerprints must match that checkpoint. Unexpected objects, customer/session rows or changed seeds stop execution. Cloudflare `_cf_KV` and SQLite internal objects are excluded from application fingerprints; they are never modified by the executor.
- Each source-file batch starts with SQL assertions for the exact current schema, all table row counts and built-in seed values, followed by the unchanged pending statements. This closes the check/write gap within D1's batch transaction. Assertions fail by raising a SQLite error; they do not modify database objects. Only the time-dependent `cvie_maintenance.completed_at` seed is normalized, with an integer/positive/not-in-the-future check retained.
- After each batch, re-read schema/counts/seeds, require the expected checkpoint, check foreign keys and record storage. End with D1-supported `PRAGMA quick_check`, unchanged Worker/deployment/configuration and Access fingerprints, plus live boundary probes.
- Any failed, missing, malformed or ambiguous API result stops the run. The executor performs **one read-only reconciliation pass**, records actual schema/counts, matching statement-prefix checkpoints, storage and invariant status, then exits unsuccessfully. If state cannot be read, record that limitation; never infer rollback or success.
- Resume is a **separate owner-approved execution** with `CF_STAGING_SCHEMA_RESUME_STEP` set to an explicitly reviewed matching checkpoint. It skips that exact verified prefix and submits only remaining statements. A blind rerun at step 0 cannot replay an existing schema. Multiple matching checkpoints can arise from no-op SQL; the executor reports them and does not choose a cursor. Unexpected state requires a reviewed forward repair. No automatic retry, rollback, object deletion, restore or recreation is implemented.

Reports identify the failing operation/source-file batch, sanitized category, HTTP status/numeric API codes and result index when available. They contain no raw provider messages, SQL response row contents, policy members, tokens, assertions or sessions. Row fingerprints verify seeds without publishing them. The original source SQL remains reviewable in the repository.

## Efficiency evidence and limits

The sanitized `migration.json` artifact records D1 response `meta.rows_read`, `meta.rows_written`, `meta.size_after` and `meta.duration` for each returned statement/result. Totals separate **migration batches (including their guards)** from **verification/reconciliation SQL**. Database metadata storage bytes are captured before, after each file, after completion/failure, with final delta and peak observed size. Metadata snapshots and query sizes retain their provenance rather than assuming simultaneous values. These measurements describe this executor's requests; they are not account-wide billing or other clients' activity.

Missing counters, statement errors or lost responses set `usage.complete=false`; available sums are lower bounds, never fabricated exact totals. A missing metric stops further migration batches. The report may therefore need a separately approved staging analytics read to recover missing billing evidence after an ambiguous request. No wider analytics permission is required for normal execution.

Proposed stop ceilings: **1,000,000 rows read, 100,000 rows written, 100,000,000 storage bytes**, counting observed migration and verification costs. Checks run before and after each batch; one in-flight batch can cross a ceiling before stopping, so these are stop thresholds rather than a Cloudflare billing quota. No synthetic/performance workload runs within migration approval. The job retains its 20-minute timeout. Persisted artifacts are uploaded on failure; a hard process/runner termination can leave incomplete evidence, and a later approved execution must re-inspect actual state before any write.

Cloudflare references: [D1 query/batch and result metadata](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/) · [Supported D1 PRAGMAs](https://developers.cloudflare.com/d1/sql-api/sql-statements/).

## Local validation and approval steps

**All 50 staging test groups passed locally**, including 10 migration-executor groups. Workflow YAML parsing and Node/Python syntax checks passed. Validation covers all real SQL/guards against local SQLite, foreign keys and final integrity; valid full execution; partial application and explicit resume; committed-but-lost response; concurrent unexpected rows; wrong account/database/commit/operation/cursor/digest; changed SQL; failed Access/inventory checks; changed Worker invariants; API errors; missing counters; budget stops and error sanitization. D1 response counters in the local harness are synthetic contract fixtures, **not estimates of live D1 consumption**. Native D1 accounting and provider behavior remain to be verified during the separately approved remote run.

After owner approval of the exact implementation commit and scope, the owner sets these variables in the existing protected environment (Codex will handle initiating and reviewing the run):

```text
CF_STAGING_APPROVED_COMMIT=<full approved implementation SHA>
CF_STAGING_PROVISION_ACTION=migrate-schema
CF_STAGING_D1_DATABASE_ID=fac61562-fc31-426d-8032-550aba63b7f6
CF_STAGING_SCHEMA_PLAN_SHA256=8f41a391990ade06e9aad08fa848523b273f9ca899e5401e3c6d32fbbd9f9601
CF_STAGING_SCHEMA_RESUME_STEP=0
```

Reuse existing account/Access values and secrets. Codex initiates only the approved exact-SHA operation; the owner approves the protected environment request. Do not set a nonzero resume cursor without reviewing actual-state evidence and approving that specific continuation. No workflow dispatch or write-job rerun was requested during preparation.

## Subsequent CVIE validation

Schema acceptance comes first. Separately review deterministic synthetic fixtures, proper application sessions/MFA, tenant isolation, product onboarding, immediate CVE retrieval, positive/negative version matching and measured D1 reads/writes/storage/latency under the bounded smoke plan. No authentication bypass, unbounded discovery or fixture import is added here.

**Feature-enabled validation is required**, not optional: after baseline smoke, prepare an exact staging-only API configuration/deployment approval for `CVIE_REGISTRY_ENABLED=true` and `CVIE_FAST_EVIDENCE_ENABLED=true`, retaining all delivery/provider/schedule guards. Review any additional prerequisites, then run the same synthetic cases with the flags enabled and compare correctness and D1 cost/latency to baseline. A flag-disabled smoke does not complete validation of the new CVIE serving path. Feature activation, fixture writes and the later larger performance matrix are excluded from this migration operation.

