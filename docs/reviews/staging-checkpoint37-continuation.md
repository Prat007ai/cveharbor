> Routine staging releases are superseded by [Simplified staging releases](simplified-staging-release.md) once reviewed and activated. This document remains applicable to historical/exception operations and unchanged production safeguards. Do not run the queued legacy continuation concurrently with simplified initialization.

# Checkpoint 37 to 740: existing staging database, separate approval

## Verified starting point

GitHub run [41733850483, attempt 2](https://github.com/Prat007ai/cveharbor/actions/runs/41733850483/attempts/2)
completed adoption at source `545a7b46bdcb77b99f2bc35bd1bb938e7add93a7`.
Artifact **13294075132** was downloaded and its ZIP SHA-256 verified against
GitHub: `4eec62b508fbc1634cc3aed4a53a86b1e590f2588070dd8781c18d82b2a286b1`.
The report verifies checkpoint **37**, **22 tables**, **12 explicit indexes**, two
ledger receipts, no other application rows, and zero Worker/production mutations.
[Sanitized provenance](../cvie-evidence/checkpoint37-adoption-verified.json) is the
starting evidence. Do not rerun adoption or reuse its checkpoint-29 backup as the
checkpoint-37 recovery package.

Target remains account `9706b4d98ad72884e67fd1eb875c8a61`, database
`cveharbor-accounts-staging`, UUID `fac61562-fc31-426d-8032-550aba63b7f6`.
Starting schema SHA-256:
`fb8f3f8dedc0c70181cfa6c7ca3b1a20813424ddbf3dec62446c5f9c334b36e2`.

## Necessary maintenance compatibility correction

The prior migration path required active reviewer/Service Auth policies and
successful authenticated page loads. That conflicts with the established
maintenance window, in which the Access application has no associated policies.
Migration now uses an explicit maintenance-only preflight: the exact Access
application must remain present with zero policy associations, anonymous/forged/
service requests must return 403, and the private backend must remain unavailable
at its public URL. Metadata failures are not accepted as an empty policy list.
Other operations retain their normal positive-authentication checks.

Worker and Access fingerprints are compared before every migration batch and at
completion. Recovery freshness is checked before every write. A policy, Worker,
schema, record, identity or checksum mismatch stops execution. Administrator
writer/session-drain attestations remain necessary: these checks do not stop a
separate administrator from writing or revoke an existing session.

No Access changes, new recovery architecture, SQL edits, manifest/checksum changes,
resources or deployments are part of this correction. A newly reviewed execution
commit is required for this correction; the successful adoption commit cannot run
the corrected continuation. This does not change the adopted schema or its proof.

## Next administrator action: fresh checkpoint-37 recovery package

Keep current maintenance restrictions in place. When CI and the execution commit
are ready, use the existing authenticated staging PowerShell session and private
encrypted backup directory. These are recovery-capture commands, not migration
commands; do not run them as part of code preparation. Retain the checkpoint-29
package separately. Use new filenames and stop after any failing command.

```powershell
$env:CLOUDFLARE_ACCOUNT_ID = '9706b4d98ad72884e67fd1eb875c8a61'
$env:CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV = 'false'
$env:WRANGLER_SEND_METRICS = 'false'
$stamp = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')
$backupBase = "C:\CVEHarbor\Backups\Staging\cveharbor-checkpoint37-$stamp"
$capturedAt = [DateTime]::UtcNow.ToString('o')
npx --yes wrangler@4.156.0 d1 time-travel info cveharbor-accounts-staging --config staging/wrangler.api.json --json | Set-Content -Encoding UTF8 "$backupBase-bookmark.json"
if ($LASTEXITCODE -ne 0) { throw 'Bookmark capture failed' }
npx --yes wrangler@4.156.0 d1 export cveharbor-accounts-staging --remote --config staging/wrangler.api.json --output "$backupBase.sql"
if ($LASTEXITCODE -ne 0) { throw 'Export failed' }
python staging/scripts/verify-recovery-export.py --checkpoint 37 --export "$backupBase.sql" --report "$backupBase-validation.json"
if ($LASTEXITCODE -ne 0) { throw 'Local checkpoint-37 validation failed' }
$capturedAt | Set-Content -Encoding UTF8 "$backupBase-captured-at.txt"
Get-FileHash -Algorithm SHA256 "$backupBase.sql"
```

Use the existing staging credential, never a production/default account. The
fixed Wrangler config targets the existing UUID. Preserve export confirmation
prompts because D1 can temporarily stop serving queries during export. The local
validator checks 22 tables, 12 indexes, exactly two valid migration receipts,
zero other application records, definitions/constraints, foreign keys and full
SQLite integrity. Keep all files and the bookmark private; no repository uploads,
workflow artifacts, R2 recovery bucket or new keys are required. Verify Time Travel
availability using the same existing procedure. The local validator cannot prove
live retention.

## Protected execution configuration, only after separate approval

Use the existing `cloudflare-cvie-staging` environment and workflow. Approve the
exact continuation implementation SHA after its CI passes. Use its original
marked **push** run and **Re-run all jobs** (debug logging off); verify the run's
SHA matches the approved continuation SHA. Do not rerun adoption run 41733850483
for this continuation, dispatch a moving branch head, or run `recovery-*`.

```text
CF_STAGING_APPROVED_COMMIT=<reviewed continuation SHA>
CF_STAGING_PROVISION_ACTION=migrate
CF_STAGING_ACCOUNT_ID=9706b4d98ad72884e67fd1eb875c8a61
CF_STAGING_D1_DATABASE_ID=fac61562-fc31-426d-8032-550aba63b7f6
CF_STAGING_SCHEMA_RESUME_STEP=37
CF_STAGING_SCHEMA_PLAN_SHA256=a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3
```

Retain staging API and Access credentials securely. Replace the existing
`CF_STAGING_RECOVERY_EVIDENCE` environment secret with the migration-specific
contract below, filled from the new checkpoint-37 package. Do not put its actual
contents in chat or the repository:

```json
{
  "operation": "migrate",
  "account": "9706b4d98ad72884e67fd1eb875c8a61",
  "database_id": "fac61562-fc31-426d-8032-550aba63b7f6",
  "source_sha": "<reviewed continuation SHA>",
  "execution_plan_sha256": "a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3",
  "start_step": 37,
  "start_schema_sha256": "fb8f3f8dedc0c70181cfa6c7ca3b1a20813424ddbf3dec62446c5f9c334b36e2",
  "captured_at": "<actual UTC capture timestamp>",
  "bookmark": "<private current checkpoint-37 bookmark>",
  "export_sha256": "<new checkpoint-37 export SHA-256, lowercase>",
  "private_export_reference": "<private checkpoint-37 export path>",
  "writers_quiesced": true,
  "export_validated": true,
  "restore_available": true
}
```

The 60-minute evidence window includes CI/preparation and approval waiting time,
and must remain valid before every batch. If stale, stop and refresh through the
same private procedure; do not extend the timestamp or freshness limit.

## Expected execution and stop condition

Run only `migrate` from 37 to **740**: **34 guarded batches / 703 remaining
statements**, starting with `account-backend/totp-schema.sql` in manifest order.
Preserve all installed objects and the two existing receipts. Expected final
schema: **102 tables, 66 explicit indexes, 344 triggers, one view and 35 receipts**;
schema SHA-256 `0627e365f619cf749b34ffcf03fc9aa8db92d38385401436b63121d755bddb7f`.
Built-in manifest seed data is installed; no customer/synthetic application import
is performed. Migration 0030 replaces a trigger introduced earlier in this same
continuation; it does not remove an object present at checkpoint 37.

Verify each batch's checkpoint and foreign keys, final integrity and exact
schema/seed/ledger state, unchanged Worker/Access fingerprints and continued
maintenance denial. Retain sanitized reports and measured D1 usage. Stop at 740;
do not deploy Workers, restore access, publish feeds or enable schedules.

On failure, preserve reports and keep maintenance active. Earlier successful
batches may remain committed. Use the executor's read-only reconciliation to
identify the actual checkpoint; never blindly rerun with cursor 37. Any resume or
Time Travel restore to the private checkpoint-37 bookmark requires separate
approval, using the same database UUID. No automatic reset, restore or rollback.

## Local validation completed

Seven relevant test files passed: adoption, full continuation, migration failure/
reconciliation, maintenance preflight/probes, release isolation, private export
restoration and Access rejection. The real SQLite rehearsal preserved checkpoint-37
objects and reached 740 with the expected receipts. Tests reject reattached
policies before the first/next batch, unreadable policy metadata, alternate Access
applications, public service/backend access, stale recovery evidence, wrong
schema/rows and lost responses without blind replay. Normal deployment access
requirements remain tested. All 31 workflow-security tests passed and the credential
boundary policy passed across 38 workflow files. The execution-plan and adoption
SQL/specification checksums are unchanged. No remote continuation or recovery capture
was performed; GitHub CI and the fresh private checkpoint-37 package remain release
gates.
