# Staging adoption: CI finding and administrator recovery checklist

> Adoption is complete: run 41733850483 attempt 2 verified checkpoint 37. The adoption instructions below are historical; do not rerun adoption. Use the [checkpoint-37 continuation procedure](staging-checkpoint37-continuation.md) for the separately approved next phase.

> Current adoption uses the original administrator-machine bookmark/export/local-restore procedure and `CF_STAGING_RECOVERY_EVIDENCE`, pinned to approved commit `545a7b46bdcb77b99f2bc35bd1bb938e7add93a7`. The [R2 recovery mechanism](staging-private-recovery.md) is optional future work requiring separate review; it does not supersede this procedure or invalidate an otherwise current, validated backup. Do not run `recovery-*` operations for this adoption.

## Browser failure investigated

Run **41730562442**, job **126246452191**, failed at
`scripts/finding_links_browser.mjs:37`. `offerLink()` in `shared-remediation.js`
renders the dialog heading and customer context, then awaits the assignments API,
then renders the acknowledgement summary and form. The test waited for the heading
and immediately read text. The failed CI output contains exactly the pre-response
heading/context, including no link form or acknowledgement summary.

A controlled-response browser reproduction using the real Worker and SQLite
confirmed HTTP 200 with `alex@example.net`, `Acknowledged` in the response. Holding
that response reproduces the same failing DOM assertion. Releasing it and waiting
for the form gives the expected acknowledgement. This is a test timing race, not
an API serialization, fixture-data or application UI regression.

Only test synchronization changed: the affected linking/status-mail/integrity
browser checks wait for the link form, which is rendered after the assignment
summary, then retain the original strict assertions. The principal test always
exercises the delayed-response case and confirms that submitting is impossible
before assignments load. No sleeps, assertion removal or application changes.

A separate staging-preparation failure in run **41732643831** exposed concurrent
local plan builders truncating `execution-plan.json` while another test read it.
The builders now publish JSON and guard SQL through same-directory temporary
files and atomic replacement. A concurrent-build/read test verifies complete JSON
and the unchanged approved execution-plan digest. This changes local artifact
publication only; no database SQL, migration checkpoint or adoption digest changes.

## Approval boundaries

The adoption remains prepared only. Original checkpoint 29 was verified by run
41707547474, artifact 13275811878; current checkpoint 37 is not installed.
The [adoption review](permanent-staging-adoption.md) contains exact SQL, hashes,
eight-statement bridge, three guards and expected schema. Do not set a resume
cursor, run migration commands, deploy Workers or merge the draft PRs.

The steps below are the next administrator operations to approve. No Access,
Worker, credential or database settings were changed while preparing them.

## 1. Preserve the established staging maintenance window

For this adoption the owner has already restricted Access by detaching all policy
associations and revoking sessions, and has completed the private backup/local
restore. Preserve this state. The initial-window instructions below are reference
only, not a request to recreate maintenance, add policies or repeat completed
checks. Use the [fixed-SHA execution method](permanent-staging-adoption.md#coordinated-execution-of-the-approved-historical-commit).
Refresh recovery capture only when its 60-minute evidence window has expired.

### Reference: establishing a new maintenance window

Target account: `9706b4d98ad72884e67fd1eb875c8a61`.
Target D1: **cveharbor-accounts-staging**, UUID
`fac61562-fc31-426d-8032-550aba63b7f6`.

There is no installed database write hold at original checkpoint 29. The future
0032 recovery controls cannot be used yet. The adoption's transaction guards
**detect** concurrent changes; they do not prevent other clients from writing.
Do not attest `writers_quiesced=true` merely because the tables are empty.

After explicit approval for a staging maintenance window:

1. Cloudflare → **Workers & Pages** → existing staging Workers → **Settings**.
   Privately record their version IDs and bindings. Confirm the API Worker
   `cveharbor-accounts-staging` has no public workers.dev URL, preview URL or routes,
   and its only authorized ingress is the existing staging frontend service
   binding. Enumerate any other Workers/services with a binding to this D1 UUID;
   each must be included in the maintenance isolation. Stop if any are unknown.
2. In both staging Workers, check **Triggers** and event bindings: no Cron
   triggers, queue consumers, pending background jobs or other event producers
   may write during the window. If anything is active, stop for a separately
   approved suspension procedure. Do not deploy or remove resources to improvise
   a hold. Disabling email delivery alone does not stop database writes.
3. Cloudflare **Zero Trust → Access → Applications** → the application covering
   `cveharbor-site-staging.cveharbor-staging.workers.dev`.
   Privately save its application ID and complete policies for restoration.
   Temporarily detach its Allow, Bypass and Service Auth policy associations and
   use a **Block / Everyone** policy on this staging application only. Preserve
   reusable policy objects; do not delete shared policies. Check more-specific
   path applications and any other staging frontend hostname too.
   Revoke this application's existing sessions using its session-revocation
   control. A Block rule alone is insufficient while a Bypass/Service Auth path
   remains. Do not alter the Cloudflare administrative dashboard's own access.
4. Verify the frontend refuses anonymous access, an existing browser session and
   the existing staging service-token path. Backend direct/public ingress must
   also remain unavailable. Do not write test rows to check this.
5. GitHub → **Actions**: confirm no other staging mutation job is running or
   waiting for approval. Do not approve any other staging jobs during the window.
   Stop local development scripts, close D1 editing consoles and agree that the
   single approved maintenance operator is the only D1 writer. Retain current
   credentials; no rotation is required for this procedure. Account administrators
   and external API clients are not blocked by Cloudflare Access, so this operator
   coordination is an essential precondition.
6. Use Worker invocation logs to confirm already-started requests/background work
   have finished. Consecutive zero row counts alone do not prove requests drained.
   Then run the read-only original-schema diagnostic again. Keep this isolation
   in force through bookmark/export capture, adoption and post-adoption checks.

If all write paths cannot be identified and drained, adoption is **not ready**.
Do not set the recovery attestation or approve the operation in that state.

## 2. Capture the bookmark and complete export privately

Use the existing secure staging credential on an approved administrator machine.
Do not paste tokens into chat. From the reviewed checkout, select a new private
directory on encrypted storage outside the repository:

```sh
umask 077
export CLOUDFLARE_ACCOUNT_ID=9706b4d98ad72884e67fd1eb875c8a61
export CLOUDFLARE_API_TOKEN="$CF_STAGING_API_TOKEN"
export CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV=false
export WRANGLER_SEND_METRICS=false
STAGING_RECOVERY_DIR=/absolute/private/encrypted/staging-recovery
mkdir -p "$STAGING_RECOVERY_DIR"
npx --yes wrangler@4.156.0 d1 info cveharbor-accounts-staging --config staging/wrangler.api.json --json > "$STAGING_RECOVERY_DIR/database-info.json"
```

Inspect that file privately and verify the exact account/UUID above before
continuing. Check the staging account's actual Time Travel retention; do not
assume a plan or window. Then:

```sh
npx --yes wrangler@4.156.0 d1 time-travel info cveharbor-accounts-staging --config staging/wrangler.api.json --json > "$STAGING_RECOVERY_DIR/bookmark.json"
npx --yes wrangler@4.156.0 d1 export cveharbor-accounts-staging --remote --config staging/wrangler.api.json --output "$STAGING_RECOVERY_DIR/before-adoption.sql"
sha256sum "$STAGING_RECOVERY_DIR/before-adoption.sql" > "$STAGING_RECOVERY_DIR/before-adoption.sha256"
```

**D1 may be unavailable for queries during export.** Obtain approval for this
staging window and retain Wrangler's confirmation prompt. Export schema and data
together; do not add `--no-schema`, `--no-data` or table filters. Preserve the
database and its UUID. These commands do not deploy the referenced Worker config.
Keep the export and bookmark out of this public repository and public CI artifacts.

## 3. Prove local restoration

The new validator has no Cloudflare client or network code. It restores the SQL
into a private temporary SQLite database, rejects external file/database access,
compares all original definitions/constraints/index metadata and zero row counts,
and runs foreign-key and full integrity checks. It deletes only its own temporary
local restore, leaving the source export intact.

```sh
python staging/scripts/verify-recovery-export.py --export "$STAGING_RECOVERY_DIR/before-adoption.sql" --report "$STAGING_RECOVERY_DIR/local-restore-report.json"
```

Expected: `PASS`, `status: passed`, 18 tables, ten explicit indexes, zero application
rows, and all restore/integrity checks true. The report includes the export SHA-256
but no exported SQL, customer rows or private paths. It refuses to overwrite an
existing report or write it inside the repository. Unexpected objects, records,
constraints or indexes stop validation. Do not edit the export to force a match.

This validates original checkpoint 29 only. It does not verify the file's live
account identity or test remote Time Travel restoration; those remain separate
administrator checks. It must not be reused as a checkpoint-37 validator.

Privately retain the export, checksum, report, bookmark, UTC capture timestamp,
live diagnostic and maintenance-isolation evidence. Confirm the live state and
recovery bookmark are still valid. Complete the recovery-evidence JSON described
in the adoption review only after these checks pass. The adoption enforces a
60-minute capture freshness limit; recapture if it expires while awaiting approval.

## 4. Final go/no-go and recovery

The exact reviewed commit's CI must pass. Then review the private recovery package,
verify writer isolation remains effective, and obtain explicit adoption approval.
No remote operation is part of this checklist's preparation.

After approval, the guarded adoption rechecks original checkpoint 29, applies one
atomic bridge and verifies **22 tables, 12 explicit indexes and two ledger receipts**
at current checkpoint 37, then stops. No application schema continuation or Worker
update is automatic. Keep the maintenance window until the operator reviews the
post-operation state. The remaining 703 statements require separate approval.

On failure, preserve evidence and keep writers isolated. If the response was lost,
inspect whether the original state or checkpoint 37 actually committed; never
retry blindly. Restore the same D1 UUID to the validated pre-adoption Time Travel
bookmark only with explicit recovery approval. Validate restored schema/counts,
integrity and binding identity before restoring the saved Access policies and
resuming normal staging access. No database replacement, reset or blind SQL import
is pre-authorized. Production and Phase 2 remain outside this procedure.
