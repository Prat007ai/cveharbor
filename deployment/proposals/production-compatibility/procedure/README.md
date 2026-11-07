# Protected production repair procedure

**Implemented for review; not executed, merged or enabled. Production is not
restored. PR #270 must remain draft.** This procedure supersedes the original
plan's missing-executor section. It does not deploy code or activate customer-only
remediation. The original backup remains Plan Z, never an automatic restore source.

**Current isolated-rehearsal status:** imports and full restored-copy verification
completed, but the success claim hit D1's expression-depth limit before any repair
installation. The [focused correction and preserved-state continuation](rehearsal/depth-continuation-review.md)
record the latest evidence, exact approval scope and all remaining production
gates. Historical statements below about missing preparation or no rehearsal
must not be used as the current status. No production gate is waived here.

The separate [isolated rehearsal adapter and approval procedure](rehearsal/README.md)
is now prepared for review. It uses its own manifest and explicitly approved new
UUIDs. It cannot retarget this production executor. No remote rehearsal has run.

## Verified execution blockers

On November 6, read-only GitHub REST inspection found both
`cloudflare-worker-production` and `cloudflare-production-audit` have:

- no required reviewers;
- `deployment_branch_policy=null` (no branch restriction);
- `can_admins_bypass=true`.

The repository variables `PRODUCTION_DEPLOYMENTS_ENABLED` and
`PRODUCTION_COMPATIBILITY_REPAIR_ENABLED` were absent (HTTP 404), so neither gate
is enabled. No setting was changed. The executor **rejects this current state**.
It requires the existing environment to have the owner (`Prat007ai`, user ID
349078288) as its sole required reviewer, an explicit branch policy for `main`
only, and administrator bypass disabled. It also checks GitHub's review history
for that environment's owner approval on this exact, still-running, first-attempt
manual workflow run and verifies the run source/path. Missing API permission is
a blocker, not a reason to omit this check. Self-review policy is not weakened by
this code; the owner must choose a compatible authorized dispatch/review arrangement.

No recovery package, independent restore receipt, private key custody, new secret,
approval JSON or quiet window has been established. Local tests mock these facts.
The Cloudflare and GitHub API adapter has **not** been run against production.
Read-only browser inspection did identify the full active Worker version:
`07055fe8-f1ab-463f-97b2-372b458b6056`, 100% traffic, PR #269 source. Every future
operation verifies this pin and the live DB binding again.

## Fixed artifacts and targets

[`target.json`](target.json) pins production account
`aa99b9b15e0492302e4f6484b8d27bc2`, Worker `cveharbor-accounts`, the full version
above, and D1 `46710e51-7ca4-4571-b89c-921b9969de0b` (`cveharbor-accounts`). It also
pins application commit `1532e732b771f960b6ae7791a9bd2205e1d59390`, backend identity,
the exact baseline and proposed application-schema hashes, and the unchanged
original SQL proposal. No input selects a different target, URL or SQL file.

[`manifest.json`](manifest.json) contains every executable SQL checksum and source
digest, including the workflow and workflow policy. Its authorization digest is
SHA-256 of the parsed manifest serialized with `JSON.stringify`, **not** the hash
of the pretty-printed file. This command verifies files and prints the exact pins:

```text
node deployment/proposals/production-compatibility/procedure/build.mjs
```

`--write` regenerates local files only and invalidates previous approvals. No
execution phase regenerates its own manifest or accepts a replacement schema hash.
The installation has 370 application objects plus four operational journal objects
(one table and three triggers). The journal uses the existing `d1_*` exclusion
from application freeze coverage, with its own immutability/sequence guards.
All original 143 application definitions are preserved. No historical migration
directory or `d1_migrations` journal is replayed or initialized.

## Separate dispatches

The manual-only `production-compatibility-repair.yml` workflow defaults to
`preflight`. No push, pull request or automatic deployment invokes it. A local
validation job must pass before credentials enter either existing environment.
All operations share `cveharbor-production-release`, `cancel-in-progress=false`,
with the existing production/recovery workflows. Credentials cannot override the
hard-coded production target. The workflow token has only contents/actions read.
No private artifact upload or cache exists.

| Operation | Credentials / effect | Required outcome |
| --- | --- | --- |
| `preflight` | Audit environment; GitHub metadata, Cloudflare metadata and SELECTs plus public readiness GET only | Full schema, all original table counts, eight integrity predicates, FK integrity, queue aggregates, exact Worker version/configuration/binding and a fingerprint. Zero writes. |
| `install` | Worker production environment; separate run-specific installation approval and signed recovery evidence | Creates immutable journal; persists installation intent and start claim; submits only reviewed installation SQL once; verifies the result. Leaves control at held=1, frozen=1, revision=0. |
| `verify` | Audit environment; SELECT/metadata/GET only | Exact installed application and journal definitions, matching receipts, original counts, no leases/write contexts, integrity/FK success and held readiness. Prints a fresh verification fingerprint. Zero writes. |
| `reconcile` | Audit environment; same read-only capabilities | Reports observed state or a blocking mismatch. Never repairs, retries, finalizes receipts or changes a hold. |
| `resume` | Separate worker-environment dispatch, new approval ID/run, reviewed verified fingerprint/receipt/revision and queue effects | Persists separate resume intent/start claim; submits a single conditional control UPDATE; verifies history/revision/readiness. Does not deploy. |

The current feature flag remains `RECOVERY_CONTROL_REQUIRED=true`. Readiness
`held=true` by itself never passes verification. An exact complete schema, receipt
chain, real control row, empty leases/context, integrity results and expected
readiness response must agree. A changed binding, partial deployment split,
configuration digest, schema, row count, receipt, queue snapshot or source rejects
the preceding approval. Raw schema comparisons are repeated inside D1 receipt
triggers and at the installation boundary; the final resume UPDATE repeats schema/count/integrity/expiry checks and
the expected held/frozen revision atomically within that statement.

## Durable receipts and interruption

`d1_cveharbor_repair_receipts` is append-only. Its only permitted ordered IDs are
`install-intent`, `install-started`, `installed`, `resume-intent`, `resume-started`.
Payloads bind source SHA, GitHub run, approval ID/hash, target, manifest, SQL,
recovery-evidence hash, the approved observation, raw schema and aggregate counts.
They contain no customer rows, recipients, raw bookmark or private key. The payload
is passed as a bound parameter, never interpolated into shell or SQL source.
The installation payload is preserved exactly through its receipts. Resume binds
the installation receipt hash and uses a different approval ID and GitHub run.

The conditional start claims are **separate successful requests** before schema
or resume submission, and are read back exactly. The API client has no retry loop,
SDK retry layer, redirect following, migration CLI, export, restore or deployment
path. A timeout, bad response, failed report write, interruption or post-write
verification failure stops. It never sends another mutation to log a failure.

This deliberately replaces the original plan's tentative native-migration runner
with a narrowly scoped, direct [D1 query API](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/)
procedure and its own durable journal. The API documents semicolon-separated SQL
as one batch. `install.sql` now starts with a scalar database assertion checking
exactly the two matching intent/start receipts, operation, database-clock approval
window, raw application schema definitions, all 70 original table counts, eight
integrity predicates and FK integrity. A false or NULL result deliberately raises
a malformed-JSON SQL error; returning false or zero rows would not stop installation.
It is the first statement in the **same request** as all repair DDL and the final
installed receipt. The executor never pre-executes, splits or retries this batch.
Thus the earlier start claim is not treated as sufficient authorization to mutate.

[D1 documents implicit transactions](https://developers.cloudflare.com/d1/sql-api/foreign-keys/),
and [binding batches document failure rollback](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch).
The latter is specifically the binding API; these sources do not establish a tested
REST DDL isolation guarantee on our target. No explicit `BEGIN`, `COMMIT`, native
migration rollback, or local SQLite transaction is used as proof of remote safety.
The local tests execute without a transaction wrapper and also simulate partial
execution. The application remains
fail-closed while recovery control is absent, and the newly inserted control row
is held/frozen. A receipt's presence alone never proves successful installation or
resume. **Production execution remains blocked pending an independently approved
isolated remote rehearsal** of this exact REST batch: precondition errors must stop
all repair DDL/receipt creation; schema/count drift and expiry after claim must reject;
concurrent writes and interruption must demonstrate the actual isolation/commit
behavior. If that contract cannot be established, stop and revise the execution
mechanism for review. Do not silently substitute another API, split the batch or
assume a partial failure is safe to retry. No transparent retry is permitted.

| Observed after interruption | Decision |
| --- | --- |
| Baseline and no journal | No completed intent demonstrated. Investigate the original attempt; a new approval is required before considering another attempt. |
| Partial/empty journal, or intent/start without installed receipt | Stop. Unknown/partial installation. No retry or journal deletion tool exists. |
| Exact installed schema, complete installation receipts, original counts, held/frozen state and all checks pass | Installation verified; service remains held. A lost successful response does not require another write. |
| Resume intent/start exists but control/history/readiness do not match | Stop. Resume outcome uncertain or incomplete. No automatic retry, receipt completion or re-hold. |
| Resume start plus matching next revision, recorded reason and healthy readiness | Resume observed. Later normal writes are expected; do not compare them to pre-resume row counts or replay mail. |
| Any other schema/receipt/configuration/integrity mismatch | Block all further writes; prepare a specific correction plan. |

GitHub concurrency and journal uniqueness prevent competing copies of this
procedure. They cannot lock an independent Cloudflare administrator or a different
automation system. The approval must attest a quiet window excluding these writers
and competing Builds. Worker metadata is rechecked before mutations. Cross-service
configuration changes cannot be made atomic with D1; unexpected drift stops further
work. The code never changes Cloudflare settings to manufacture quiescence.
The new assertion closes the observed claim-to-install drift gap; it does not
create an advisory lock against privileged external writers. Until remote batch
isolation is established, exclusion of all such writers remains a required
operational precondition, not something local tests prove. Snapshot checks are
schema/count/integrity checks, not row-content hashes: same-count updates satisfying
integrity predicates are not detected. The quiet window must exclude those too.

## Approval and evidence formats

Before a future dispatch, an authorized operator prepares exact inputs; the owner
need not manually copy hashes or operate development tools. These are proposed
protected-environment configuration, **not values configured by this PR**:

- Both environments: `PRODUCTION_REPAIR_APPROVED_SOURCE` = reviewed immutable
  merged workflow SHA; `PRODUCTION_REPAIR_MANIFEST_SHA256` = verified manifest digest.
- Worker environment only: `PRODUCTION_COMPATIBILITY_REPAIR_ENABLED=true` for the
  separately approved maintenance scope. Do not enable `PRODUCTION_DEPLOYMENTS_ENABLED`.
  This is a **GitHub Actions configuration variable in `cloudflare-worker-production`**,
  not a Cloudflare Worker binding and not a repository/organization variable.
  Do not create a same-name repository/organization fallback. The job condition
  selects only the repository, main branch, manual event and install/resume operation;
  it deliberately does not read this environment variable. After the required
  reviewer gate releases the job, the execution step resolves `vars` and the
  runtime rejects unset/false values before provider access. A disabled invocation
  fails closed rather than being silently skipped. This follows
  [GitHub's environment-variable availability](https://docs.github.com/en/actions/reference/workflows-and-actions/variables#configuration-variable-precedence).
- Worker environment secrets: `CVEHARBOR_PROD_REPAIR_AUTHORIZATION` and
  `CVEHARBOR_PROD_REPAIR_EVIDENCE`. Existing Cloudflare credentials retain their
  present scope; if insufficient, stop for a separate permission decision.
- Worker environment public variable: `PRODUCTION_REPAIR_RECOVERY_PUBLIC_KEY`, an
  independently verified Ed25519 public key. Its private signing key stays offline.

`REPAIR_AUTHORIZATION` is JSON with `version:1`, fresh UUID `approval_id`,
`operation`, `source_sha`, `run_id`, `manifest_sha256`, `account`, `database`,
`worker_version`, `application_commit`, `sql_sha256` for that phase,
`baseline_schema_sha256`, `preflight_sha256`, `recovery_sha256`, integer UTC epoch
`not_before`/`expires_at` (maximum 30-minute window), and all three attestations:
`quiet_window_confirmed`, `independent_writers_excluded`, `no_competing_cloudflare_builds`.
Resume additionally requires `install_receipt_sha256`, `verification_sha256`,
`expected_revision`, and explicit `resume_scheduled_work_and_eligible_email:true`.
The latter covers ordinary eligible work under existing settings, not resending
uncertain mail. The secret must be prepared for the actual run while its environment
review is pending; inspect the prepared operation before owner approval.

Recovery secret format: `{ "payload": "<exact JSON string>", "signature": "<base64>" }`.
The signature is Ed25519 over the exact UTF-8 payload bytes, and `recovery_sha256`
is their SHA-256. Payload fields validated by `verifyRecovery` include production
account/DB/Worker/schema, procedure manifest, original table-count hash, capture
and verification epoch timestamps, ciphertext/export/bookmark/restore-receipt hashes,
the exact private destination, confirmed key custody and writer quiescence, and the
isolated restore account/name/UUID/schema/counts/FK/integrity/isolation results.
Capture must be at most 24 hours old; the restore UUID must differ from production
and permanent staging. See [recovery preparation](recovery-preparation.md).

A valid signature verifies the trusted reviewer's attestation, not the underlying
storage by itself. The independent operator must actually download, decrypt, restore
and compare the package before signing. CI fixtures are never acceptable evidence.
The executor does not read private backup files or raw bookmarks. The old backup,
an unsigned JSON assertion, an untested export, or a stale package cannot satisfy
the gate. If the window expires, stop for a fresh plan/approval; never edit timestamps
to extend an old attestation.

## Data preservation and test limits

Installation inserts operational metadata and adds reviewed schema only. It never
updates, deletes or re-keys existing application records. All original definitions
and table counts are compared, and eight integrity predicates/FK checks are run.
Counts are **not content hashes** and do not prove absence of an equal-count outside
edit. Private restore verification and exclusion of independent writers remain
required. Test data is preserved exactly like customer data.

Tests use the full audited schema plus fictional users/remediations, real SQLite
DDL and mocked provider/GitHub responses. They cover wrong targets, gates and
approvals; schema/configuration/count drift; missing/forged/stale recovery evidence;
concurrent invocation; partial/bootstrap/lost-response outcomes; mismatched receipts;
failed verification; active leases; and resume boundaries. Existing nine plan tests
cover authentication/MFA, tenant isolation, existing remediation, holds and lease
drain. They do not certify remote D1 atomicity, network behavior, API permissions,
provider limits, real backups, live restore readiness or production restoration.

```text
node deployment/proposals/production-compatibility/procedure/build.mjs
node --test account-backend/tests/production-repair-procedure.test.mjs
npm test --prefix account-backend
python scripts/check_workflow_security.py
python -m unittest discover -s tests -p test_workflow_security.py
```

## Remaining approvals, none requested now

1. Review this draft's exact head/manifest/SQL and later authorize merge separately.
   Recheck production Builds and release gates before merge. The new workflow is
   manual-only; the existing backend-test path can still trigger ordinary main CI.
2. Separately approve configuring the two **existing** GitHub environment gates:
   owner required reviewer, custom `main` branch only and no administrator bypass.
   Authorize any associated public-key/protected evidence configuration explicitly;
   no changes are made automatically by this executor.
3. Approve the exact recovery-preparation proposal, resource creation/transfer/restore
   scope, custody, retention and budget. Then collect and independently verify fresh
   evidence. This is not production repair or production restore approval.
4. Approve production installation: exact merged source, procedure manifest and
   install SQL digest, fixed Worker/account/DB/baseline, signed recovery hash,
   preflight fingerprint, unique run/approval ID and UTC quiet window. Scope includes
   journal creation and installation held/frozen; excludes resume/deploy/reset.
5. After independent read-only verification, separately approve resume against the
   exact receipt/fingerprint/revision and fresh queue snapshot, explicitly including
   normal scheduled processing and eligible email. Separate live acceptance writes
   or emails need their own scope. No automatic rollback or clearing of stale leases.

Customer-only remediation remains blocked by the separately documented
[integrity follow-up](customer-integrity-follow-up.md). Staging deployment and its
PR #269 pins remain unchanged. Do not run ordinary initialization, the old staging
migration, any production restore, or the old backup as part of this procedure.
