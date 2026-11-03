# Original-schema adoption: review package, not execution approval

For the investigated browser CI race, practical maintenance isolation, bookmark/
export commands and the local restore validator, use the
[administrator checklist](staging-adoption-operator-checklist.md).

Prepared November 3, 2026. PRs #243, #251 and #253 remain draft. No remote SQL,
resume setting, resource creation, credential change or deployment is authorized
by this document. Adoption and continuation are separate approvals.

## Verified starting evidence

[Run 41707547474, attempt 2](https://github.com/Prat007ai/cveharbor/actions/runs/41707547474)
artifact **13275811878** was downloaded and its ZIP digest matched GitHub metadata:
`fda5f903499d384033dca8b307205bf35e7c6bb9f25b4f635a5258b0151e204f`.
The contained report digest is
`59c30b1c887aceb853f7b1e1a8359d88010950b3c605d5e8d7e2f03991d9641e`.
The diagnostic completed at 5:06:17 p.m. Toronto time on November 3
(`2026-11-03T22:06:17.067Z`). It establishes:

- Account `9706b4d98ad72884e67fd1eb875c8a61`.
- D1 `cveharbor-accounts-staging`, UUID `fac61562-fc31-426d-8032-550aba63b7f6`.
- Original checkpoint **29**, `first_29_verified=true`, all 18 tables empty,
  10 explicit indexes, no application triggers/views, matching schema/index
  definitions and passing foreign-key/quick integrity checks.
- 406 observed rows read, zero writes, zero mutation requests and zero storage
  change. This confirms the original base initialization completed; it does not
  establish the complete integrated application schema. The original verifier's
  compound-count defect was separately reproduced locally and corrected.

Starting schema fingerprint:
`f9d246474e0d003726dd77be471529fd680eefc243935ce36cff193ca6f7414d`.
Frozen diagnostic reference digest:
`d2a9af7136414eabe7dc5c74814addbdbb113e43d7edc0c85d8fbaadc1e9248e`.
Original source SQL digest:
`b89e3589c3df611f2e9cb1c6f6bc6e49fa928329deb2ba3a2c6c9fae675f0e07`.

Historical diagnostic evidence is not a lock. The adoption operation runs that
complete read-only diagnostic again and requires an exact match before writing.

## Exact proposed operations and hashes

The eight SQL statements are checked in verbatim at
[`adopt-original-checkpoint29.sql`](../../staging/sql/adopt-original-checkpoint29.sql):

1. Create `staging_schema_history`.
2. Create `staging_mail`.
3. Create `staging_mail_created` index.
4. Create `staging_job_runs`.
5. Create unique `staging_one_job` index.
6. Create `staging_mail_attachment_chunks` with its foreign key.
7. Record the checksum of the staging schema just executed.
8. Record adoption of the checksum-verified original account schema.

The last receipt records adoption of existing, verified objects. It does not
claim they were recreated. The pinned diagnostic provenance and adoption report
distinguish adoption from ordinary migration execution without changing the
integrated ledger format. No original CREATE TABLE statements are replayed and
no table is dropped or rebuilt.

| Artifact | SHA-256 |
|---|---|
| Adoption specification | `7ed30868dae48623caaccd9f1bead405333785b7b8c888f0308fb0b11ffe3eea` |
| Eight-statement SQL | `e0e1688936703b027a39b58e924ac05313b55a552436f4950dc60954fd7ae7b8` |
| Complete guarded SQL request | `526b138194b266db8925271144744d1e13e3e32ee9abd99f323c0cfe05a131f9` |
| Integrated execution plan | `a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3` |

Three read-only SQL assertions precede the eight statements in the **same D1 REST
transactional multi-statement query**. They recheck every original schema object
and every table count, closing the read/write race. A mismatch raises an error
before adoption; any batch error rolls back all eight statements. The batch has
no explicit BEGIN/COMMIT and no automatic retry. Response loss triggers bounded
read-only reconciliation, not a repeated write.

Reproduce the exact review artifacts locally, without Cloudflare credentials:

```sh
python staging/scripts/migration-plan.py
node staging/scripts/prepare-adoption.mjs
```

`staging/.build/schema/adoption-batch.sql` contains the complete request including
all guards. `adoption-review.json` contains the hashes, final inventory and every
remaining source file/checksum/start/end. The preparation workflow publishes both
as code-only review artifacts. These files contain no customer data or credentials.

## Result and separate continuation

Successful adoption must verify **current-manifest checkpoint 37**:

- 22 tables, 12 explicit indexes, zero application triggers/views.
- All original 18 table definitions and ten indexes preserved.
- Exactly two manifest receipts; three staging feature tables remain empty.
- Schema fingerprint
  `fb8f3f8dedc0c70181cfa6c7ca3b1a20813424ddbf3dec62446c5f9c334b36e2`.

The action then stops. It accepts no resume cursor and never invokes migration,
publication, Worker deployment, Access configuration, email or scheduler code.
**Checkpoint 37 is not installed yet.** Do not set a cursor during preparation.

After a successful approved adoption, separately review its evidence and approve
`migrate` at current checkpoint 37 with the exact integrated plan digest. The next
file is `account-backend/totp-schema.sql`. The remaining **703 statements** follow
the explicit manifest through auxiliary features, 0016–0027, the remediation
0028/0029, 0030 notifications, 0031 integrity, 0032 recovery, the separate CVIE
0028/0029, and 297 generated recovery guard triggers. No filename sorting is used.

Expected final checkpoint **740** has **102 tables, 66 explicit indexes, 344
triggers and one view**, excluding SQLite/Cloudflare internal objects, with 35
manifest receipts and checked built-in seed data. Final schema fingerprint:
`0627e365f619cf749b34ffcf03fc9aa8db92d38385401436b63121d755bddb7f`.
0030 replaces a trigger introduced by an earlier migration; the full continuation
is not strictly create-only. All original tables remain intact.

## Recovery capture before requesting mutation approval

No recovery bookmark/export has been captured by this implementation. Use an
approved administrator workstation with the existing staging-only credential,
or an explicitly reviewed secure runner. Do not retrieve secrets into chat or
publish exports in GitHub artifacts: this repository is public.

1. Confirm the account/database IDs above, live Worker bindings and versions,
   disabled native schedules and absence of application/administrator writers.
   Record that evidence privately. If a write restriction needs configuration
   changes, obtain separate approval. The 0032 write hold is not installed yet.
2. Select an encrypted private local directory, outside the repository, with
   owner-only permissions. Use the pinned staging Wrangler config; never an
   implicit production/default config. Bind the CLI to the existing staging
   credential without printing its value. For example, in an already secure shell:

   ```sh
   umask 077
   export CLOUDFLARE_ACCOUNT_ID=9706b4d98ad72884e67fd1eb875c8a61
   export CLOUDFLARE_API_TOKEN="$CF_STAGING_API_TOKEN"
   export CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV=false
   export WRANGLER_SEND_METRICS=false
   # Set this to your approved encrypted local directory; no secret value here.
   STAGING_RECOVERY_DIR=/absolute/private/encrypted/staging-recovery
   mkdir -p "$STAGING_RECOVERY_DIR"
   npx --yes wrangler@4.156.0 d1 info cveharbor-accounts-staging --config staging/wrangler.api.json --json > "$STAGING_RECOVERY_DIR/database-info.json"
   ```

   Inspect metadata privately and confirm the UUID before proceeding. The CLI
   config's DB binding fixes that UUID. Do not use these commands with a production
   token/account. No command here deploys the config or changes bindings.
3. Check D1 Time Travel availability and the account's actual retention window;
   do not assume a particular plan. Record a fresh bookmark:

   ```sh
   npx --yes wrangler@4.156.0 d1 time-travel info cveharbor-accounts-staging --config staging/wrangler.api.json --json > "$STAGING_RECOVERY_DIR/bookmark.json"
   ```

4. Obtain approval for the staging export window. **Cloudflare warns that D1 may
   be unavailable to serve queries while exporting.** Leave its confirmation
   prompt enabled. Export schema and data together, even though current user rows
   are empty; do not use `--no-data`, `--no-schema` or a partial table filter:

   ```sh
   npx --yes wrangler@4.156.0 d1 export cveharbor-accounts-staging --remote --config staging/wrangler.api.json --output "$STAGING_RECOVERY_DIR/before-adoption.sql"
   sha256sum "$STAGING_RECOVERY_DIR/before-adoption.sql" > "$STAGING_RECOVERY_DIR/before-adoption.sha256"
   ```

5. Run `python staging/scripts/verify-recovery-export.py --export <private-export.sql> --report <new-private-report.json>`.
   This restores the export into an isolated LOCAL SQLite file, without any Cloudflare
   connection. Inspect its full schema/constraints/indexes, all 18 counts, foreign
   keys and `PRAGMA integrity_check` against the frozen reference. Preserve known
   Cloudflare metadata separately; do not silently ignore unexpected application
   objects or formatting/definition mismatches. Confirm the bookmark timestamp
   is still recoverable and live state remained unchanged across capture. A local
   export restore is not a test of remote Time Travel restoration.
6. Record account, UUID, timestamp, bookmark, export SHA-256, private export
   location and validation/writer-isolation evidence in private administrator
   storage. This package must be captured no more than **60 minutes** before the
   adoption write; expiration requires a new capture, not a larger time limit.
7. Only after reviewing this package and explicitly approving adoption, configure
   the existing protected `cloudflare-cvie-staging` environment. No settings have
   been changed during preparation. Use:

   - `CF_STAGING_PROVISION_ACTION=adopt-schema`
   - `CF_STAGING_APPROVED_COMMIT=<exact reviewed implementation commit>`
   - `CF_STAGING_ADOPTION_SHA256=7ed30868dae48623caaccd9f1bead405333785b7b8c888f0308fb0b11ffe3eea`
   - `CF_STAGING_SCHEMA_PLAN_SHA256=a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3`
   - Keep `CF_STAGING_SCHEMA_RESUME_STEP` **unset/empty** for adoption.
   - Retain the exact staging account/UUID variables and staging-only API secret.

   Add the following JSON as the **environment secret**
   `CF_STAGING_RECOVERY_EVIDENCE` using GitHub's secure settings, never chat or a
   repository file. Fill the real values only after validating the private backup:

   ```json
   {
     "account": "9706b4d98ad72884e67fd1eb875c8a61",
     "database_id": "fac61562-fc31-426d-8032-550aba63b7f6",
     "source_sha": "<exact reviewed implementation commit>",
     "start_schema_sha256": "f9d246474e0d003726dd77be471529fd680eefc243935ce36cff193ca6f7414d",
     "adoption_sha256": "7ed30868dae48623caaccd9f1bead405333785b7b8c888f0308fb0b11ffe3eea",
     "captured_at": "<actual UTC RFC3339 capture time>",
     "bookmark": "<verified D1 bookmark>",
     "export_sha256": "<actual export SHA-256>",
     "private_export_reference": "<private administrator backup location>",
     "writers_quiesced": true,
     "export_validated": true,
     "restore_available": true
   }
   ```

   These booleans are administrator attestations, not automatic proof of export
   contents or retention. The executor validates scope/freshness/digests, requires
   the attestation and rechecks live schema. It logs only evidence hashes, not the
   raw bookmark, private location or credential. Environment review remains
   mandatory. Do not rerun an older marked commit: approval must target the exact
   adoption implementation SHA. The current preparation commit deliberately does
   not activate a release. A reviewed dispatch/marked implementation commit can be
   prepared only after execution approval, without merging to main.

Before the later continuation, confirm writers are still quiescent and both the
original recovery package and a fresh checkpoint-37 recovery package are valid.
Capture/validate the latter using the same secure process against checkpoint 37.
The separate migration approval must include its recovery evidence; the existing
migration executor does not consume the adoption-specific recovery attestation.

## Failure and recovery

- Any failed guard, response, integrity check or checkpoint stops execution.
  A failed transactional adoption leaves the original schema. A lost response
  may leave checkpoint 37 installed; inspect the sanitized report and live state.
  Never repeat the bridge blindly or infer success from HTTP status alone.
- If reconciliation cannot prove a checkpoint, keep staging writers quiescent.
  Collect read-only evidence. Do not reset/drop objects or synthesize ledger rows.
- Restore only following explicit recovery approval, to the **same staging UUID**
  and the previously validated bookmark. Example command, NOT to run during prep:

  ```sh
  npx --yes wrangler@4.156.0 d1 time-travel restore cveharbor-accounts-staging --config staging/wrangler.api.json --bookmark "$APPROVED_STAGING_BOOKMARK"
  ```

  Preserve Cloudflare's returned pre-restore bookmark privately. Confirm target,
  schema, counts, foreign keys, integrity and unchanged bindings/Access settings
  before lifting any approved write restriction. No Worker rollback is needed
  for the adoption because no Worker is deployed. If Time Travel is unavailable,
  stop for a separately reviewed same-database recovery plan from the secure
  export; importing over a partial schema or resetting is not pre-authorized.

## Validation and limits

All **17 staging test files passed locally**. The adoption suite includes ten tests.
Coverage includes exact bridge/ledger/checkpoint verification; preserving original
definitions and root pages; the separate 703-statement continuation; wrong target,
SHA, plan, action and cursor rejection; absent/stale recovery evidence; repeated
adoption rejection; concurrent schema/row changes; transactional rollback; committed
but lost responses; failed readbacks; freshness recheck; and deployment isolation.
Existing diagnostic tests exercise D1's five-term compound SELECT limit and the
read-only SQL boundary. SQLite counters are synthetic, not D1 billing estimates.

The workflow security policy passed for 38 workflows. No secrets were configured
or changed. Remote adoption/continuation, Time Travel recovery, and actual export
validation remain unexecuted and require the stated approvals. The historical
original-state proof is authoritative for planning, not a substitute for the fresh
runtime checks and recovery package. Production and Phase 2 remain untouched.
