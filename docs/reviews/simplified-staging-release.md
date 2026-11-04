> **Current application activation:** [cveharborstage.com activation](permanent-staging-activation.md). Run 41923381309 completed production baseline step 209. Do not repeat initialization. The historical preparation notes below describe how that baseline was established; their Worker activation block is superseded by the reviewed staging-only compatibility profile.

# Production-equivalent permanent staging

Status: correction prepared for review; no remote migration or deployment performed.
This supersedes the former 37 → 232 → 740 initialization in this document. Do not
run the queued legacy 37 → 740 operation to establish production parity.

## Reviewed production baseline

`release/baseline.json` now records the reconciled read-only evidence from run
**41909431530**, artifact **13361372888** (ZIP SHA256
`c6f4eac1c2fee433a30a887a521b433d9e36dfb54d6f3bb038f0706c5281c604`).
The audit confirmed the same schema, frontend and backend release identity with a
stable new backend deployment. Its only identity mismatch was the obsolete pinned
backend version. The active-version content ETag check passed. Local source hashing
reconfirmed the identity before updating the pin. No customer records were read.
The earlier schema reconstruction from run 41900058502 remains historical evidence.

- Application schema: **70 tables, 48 explicit indexes, 24 triggers, one view**.
- Ordered, checksum-pinned production SQL: base schemas and migrations through
  `0030`, **excluding `0023_lifecycle_monitoring.sql`**. Neither `0031` nor `0032`
  is part of this baseline. File presence in GitHub does not prove installation.
- All 15 definition differences in the original audit were whitespace-only.
  Comparison now preserves SQL token boundaries, literals, quoted identifiers,
  operators, constraints, column/index order and trigger bodies. It does not erase
  meaningful SQL differences. The old raw fingerprint remains as evidence; the
  new token fingerprint is explicitly versioned `sqlite-tokens-v1`.
- Backend source equivalent: `6e05106ce7d5f4c8741261775f2e4e69c6eea719`;
  deployed version `89380b13-b600-4fef-82f4-69b8cc2f2c17`, deployment
  `32de70d4-aa64-4ea4-b7dd-2a8cc31b4806`. Source equivalence is
  proven by deployed release identity, not a uniquely recoverable deployment Git SHA.
- Frontend application source: `019efc6ca029f4113ce71c6ebfad3680fa66ba68`;
  deployed version `e22850fa-851d-453f-8336-5e78d96babdd`, publication run
  **41882606976**. The public advisory refresh commit is recorded separately.
  Staging replaces feed content with synthetic data.

The audit remains metadata-only: D1 identity and `sqlite_schema`, Worker deployment
metadata, allowlisted boolean runtime flags and backend content. It requires the active version ETag, backend identity,
both pinned version IDs and stable deployments. It never reads customer tables or
calls application readiness endpoints. A changed version/schema stops verification;
do not change pins simply to suppress a mismatch. Existing safe diagnostics remain.

## Exact next operations (separate approvals)

1. Review this draft correction and its CI. Merge only with owner approval.
   Keep production deployment flags disabled and production approvals unchanged.
2. Use the reconciled evidence above for the schema-only initialization review.
   There is no need to obtain another export, change secrets, or rebuild staging
   to accept the verified new deployment ID. If a fresh read is desired or the
   deployment changes again, reuse the existing **Phase 1 readiness - SELECT-only
   production audit** with `audit_mode=schema-baseline` and
   `baseline_source_sha` blank. Its `verified` status means schema/source/version
   verification, **not functional application readiness**. It separately reports
   the incompatible recovery configuration and `application_ready=false`.
3. After the owner approves this reconciliation and staging initialization, retain
   account `9706b4d98ad72884e67fd1eb875c8a61`, database
   `cveharbor-accounts-staging` / `fac61562-fc31-426d-8032-550aba63b7f6`, and both
   existing Workers/bindings. Reuse `cloudflare-cvie-staging` credentials and
   existing Access maintenance restrictions. Set `SIMPLE_STAGING_ENABLED=true`
   only as part of that approved activation; dispatch **Permanent staging
   preparation and approved updates**, `simple_operation=initialize`,
   `operation=none`, on reviewed main.
4. Initialization obtains a fresh Time Travel bookmark privately in memory and
   uses the existing exact-target executor, denied-Access/no-schedule checks,
   per-batch schema/data guards, transactional receipts and integrity verification.
   It preserves the original checkpoint-37 objects and two receipts. It stops at
   **step 209 in the production-baseline plan**, with **74 total tables, 50 explicit
   indexes, 24 triggers, one view, and 30 migration receipts**. Four tables and two
   indexes are existing staging mail/job/ledger support, not production features.
   Step 209 is profile-specific, not a resume cursor for the frozen 740-step plan.
   No Worker deployment, Access restoration or candidate continuation occurs.
5. Worker activation remains a separate approval and is blocked in this correction.
   The integrated deployment path requires `0031`/`0032`, which this baseline
   intentionally excludes. The existing audit now also reports an allowlist of
   boolean runtime flags from the active Worker version (no secrets or other
   binding values). Reconcile those live flags with the separately pinned backend
   and frontend before preparing the existing Worker update. Do not enable newer
   CVIE/product-monitor functionality merely because the candidate staging wrapper
   enables it. Reuse the existing private R2, synthetic publisher, email capture,
   staging authentication and Access setup; no new infrastructure is needed.
6. Complete signed-in synthetic acceptance: authentication, inventory, CVE Findings,
   Remediation Tracker, assignment/acknowledgement/reviewer access, captured mail,
   tickets/history, intelligence snapshots and approved manual notification jobs.
   Exact production code/schema replication is not proof that every production
   feature is healthy; surface any existing code/schema incompatibility rather
   than silently installing excluded migrations.

## Production replica versus a future candidate release

The initialized database deliberately does not satisfy the integrated candidate
readiness check, which requires `0031` integrity objects and `0032` write holds.
`simple_operation=release` therefore stops before any migration or Worker update
for this profile. `resume` also stops because that database has no `0032` hold.
The initializer's receipt is not successful candidate-promotion evidence.

The active-version runtime flags are now confirmed, not inferred from source:

| Setting group | Active-version evidence |
| --- | --- |
| `RECOVERY_CONTROL_REQUIRED` | `true` |
| Assignment email, acknowledgement, FYI, progress and remediation workflow | `true` |
| `CVIE_SHARED_SCANS_ENABLED`, `PLUGIN_MONITOR_ENABLED`, manual website monitoring | `true` |
| Scheduled website monitoring | `false` |
| CVIE registry/fast evidence, product-monitor checks/delivery, alert/lifecycle delivery | Not set in the active version's bindings |

`operations_control`, `operations_leases` and `operations_events` are absent from
the audited database. With that schema and `RECOVERY_CONTROL_REQUIRED=true`, the
released recovery wrapper fails closed: protected HTTP requests return maintenance
503 responses, and scheduled handlers do not run. Local synthetic tests reproduce
both outcomes without writes. This is a configuration/schema incompatibility, not
a formatting issue or an active maintenance record. No live customer endpoint was
probed; the assessment applies to the audited database, which the released Worker
configuration declares as its DB binding. Existing assignments and links are not
deleted by this behavior.

Schema-only staging initialization may proceed after approval while Worker
activation remains blocked. Do not copy this incompatible configuration into an
operational staging release, bypass recovery checks, or add `0032` to hide it.
Any production configuration correction requires separate explicit approval and
is outside this baseline update. The identity evidence does not establish who
created the new version or the deployment mechanism; those details are not claimed.

No application code, runtime flags, provider behavior, deployment ordering or
production promotion guards are changed here. The pinned application sources are
prepared read-only by the existing checkout script and recorded separately. Main
pushes cannot silently advance this baseline to the integrated candidate schema.

## Failure and recovery

The original adoption SQL, frozen migration manifest and 740-step execution-plan
checksum are unchanged. Initialization rejects unexpected rows, schema, receipts,
resource identities, Access policies or concurrent writes. On failure it stops,
reconciles actual state read-only and never retries a mutation or resets the DB.
Do not rerun `initialize` on a partial installation. Review the recorded verified
state and approve an exact forward continuation or a D1 Time Travel restore.

Because `0032` is not installed, maintenance continues to use the existing Access
restrictions and disabled schedules. Do not use the integrated `resume` action or
claim a database write hold exists. Recovery changes and restores remain explicit
operations; bookmarks and exports stay private. Production safeguards are unchanged.

No new resources or credentials are required. The read-only audit evidence has
been reconciled; staging initialization, Worker activation and signed-in acceptance
remain separate operations requiring approval.

### Failed initialization: diagnose before retrying

Run 41916213494 did not preserve the automatic job's underlying exception or
migration progress: `simple-release.mjs` discarded the exception and never
connected the migration runner's `record` callback, and artifact upload was
success-only. Its preparation artifact predates the initialization attempt.
It is not evidence that the database remains at checkpoint 37.

The existing **Permanent staging preparation and approved updates** workflow now
has `simple_operation: diagnose`. Once this correction is reviewed and available
on main, select **Run workflow**, branch **main**, simplified operation
**diagnose**, leaving the legacy `operation` at **none**. Do not use **Re-run
failed jobs** on the initialization run: that would execute initialization again.
No credential changes, backup evidence updates or new workflow are needed.

This explicit read-only operation uses the existing protected staging environment
and exact account/database validation. It inspects schema definitions, table
counts, migration receipts and integrity against the production-only plan first,
then performs existing inventory/maintenance checks and GET-only Time Travel
availability verification. It accepts observation of a partial or completed
initialization; it does not require or set checkpoint 37 as the actual state.
It cannot reach mutation batches, deploy Workers or restore Access policies.

Inspect `staging-tested-<commit>-<attempt>/staging-release.json`, even if the job
fails. `baseline.actual_state.matching_steps` is the observed production-profile
checkpoint, `receipt_count` and receipt file indexes identify applied migrations,
and integrity results are explicit. Unknown state has an empty matching list;
failed/partial observations are marked incomplete. Never interpret an incomplete
observation as checkpoint 37. `failure.operation`, `category`, HTTP status and
numeric API codes identify the failed check without provider response bodies,
credentials, bookmarks or customer row values. Inventory booleans and the
migration runner's per-operation progress are retained. Captured seed values
remain in memory; artifacts contain hashes and counts only.

The remote database state and runtime failure from run 41916213494 remain
unverified until this diagnostic runs with the configured staging credentials.
Review its evidence before approving any correction or exact migration retry.
The destination remains production baseline step **209**; no automatic retry,
rebuild, restore, candidate step 740 migration or Worker deployment is introduced.

### Maintenance authentication redirects

Diagnostic run 41919567329 verified production-profile checkpoint 37 (22 tables,
12 indexes, two receipts, valid integrity and foreign keys). Its maintenance
probe rejected anonymous/forged-JWT HTTP 302 responses; service tokens received
403 and the private backend received 404. Neither its artifact nor its job log
captured the redirect destinations, so those historical destinations are unverified.

The maintenance probe now checks `Location` in memory. Only HTTP 302 for anonymous
or forged-JWT requests can qualify, and only at the configured HTTPS Access issuer
with the exact `/cdn-cgi/access/login` path or that path followed by the exact
staging frontend hostname. Credentials, fragments, other origins, other paths and
other redirect statuses fail. It never follows redirects. Service tokens still
require 403, the private backend still requires 404, and the migration executor's
zero-policy maintenance checks remain unchanged.

After this correction is reviewed and available on main, run the existing workflow
with `simple_operation=diagnose` and legacy `operation=none`. Confirm
`access_check.passed=true` and `login_redirect_verified=true` for each 302 browser
check before approving initialization to step 209. Only a boolean is recorded;
Access redirect query parameters are never published. This change does not itself
run migrations, change policies, restore access or deploy Workers.
