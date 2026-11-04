# Production-equivalent permanent staging

Status: correction prepared for review; no remote migration or deployment performed.
This supersedes the former 37 → 232 → 740 initialization in this document. Do not
run the queued legacy 37 → 740 operation to establish production parity.

## Reviewed production baseline

`release/baseline.json` records read-only audit run **41900058502** and the local
reconstruction of every object definition hash, not a new claim that the old audit
passed. Its `verification_method` identifies that reconstruction. No customer
records were read or copied. The existing audit can independently reconfirm it.

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
  deployed version `aa8ce0f2-73d3-4714-b4c1-583d1f7283e1`. Source equivalence is
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
2. Run the existing **Phase 1 readiness - SELECT-only production audit** on the
   reviewed main revision: `audit_mode=schema-baseline`, leave
   `baseline_source_sha` **blank**. The existing protected
   `cloudflare-production-audit` credentials are reused. Blank selects the reviewed
   backend pin; an arbitrary/different source is rejected. Expect `verified`, both
   version checks true, exact object counts and zero rows written. No new secret,
   workflow or manually updated recovery-evidence contract is needed.
3. After the audit passes and the owner approves staging initialization, retain
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

This distinction addresses a confirmed local finding: the released backend source
sets `RECOVERY_CONTROL_REQUIRED=true`, but the audited production schema has no
`0032` tables. The current integrated staging wrapper additionally enables CVIE
features that require later tables; a synthetic scheduler test against the actual
production schema failed. Production may use live variable overrides. Do not infer
those overrides, disable guards just to pass a test, or silently add missing schema.
The already-authorized metadata audit can report safe active-version flags during
its next run. Source/schema parity is established; full functional parity and the
first Worker activation still require that configuration reconciliation.

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

No new resources or credentials are required by this correction. Remote audit,
initialization, Worker activation and signed-in acceptance remain pending approval.
