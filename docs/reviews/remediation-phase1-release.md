# Phase 1 release and recovery procedure

This procedure supersedes the earlier manual-hold and conditional old-schema rollback instructions. Production execution remains subject to explicit approval. PR #251 must remain draft until the user authorizes otherwise. No Phase 2 work is included.

## Required secure configuration

- Production uses the existing `cloudflare-worker-production` GitHub environment and its `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN` secrets. Never copy these into chat, source, command arguments, screenshots, or artifacts.
- Confirm required reviewers and deployment branch restrictions on production environments. Production-writing workflows must run only reviewed code. Remove any ability for historical/unreviewed branches to inherit production-write credentials through repository-level secrets; this is an administrator configuration check, not something these code changes can enforce on old workflow revisions. Existing secret values must not be inspected or logged.
- Verify the accounts database identity against `account-backend/wrangler.toml` and baseline schemas through 0030. Migration 0031 does not replace prerequisite schemas.
- Configure the separate `cloudflare-phase1-staging` environment as described in `remediation-phase1-staging.md`. Staging uses distinct secret names and refuses the production database UUID. No default fallback to production is permitted.
- The runtime must retain `RECOVERY_CONTROL_REQUIRED=true`, declared in Wrangler configuration. Missing recovery state then fails closed. Do not remove this setting to work around a failed release.
- A compatible Worker must be fully deployed before recovery leases can prove that Worker activity has drained. Do not use an empty lease table to infer that pre-release Worker versions have stopped.

## Read-only production audit

Use **Read-only remediation production integrity audit**, selecting `preflight` before installation or `installed` afterwards. It uses the existing production environment. It has no deployment/migration/mail command. The shared client permits a single SELECT only, rejects mutation and multi-statement queries before transport, and verifies `rows_written=0`.

Equivalent commands in an authorized runner with credentials already configured:

```sh
AUDIT_PHASE=preflight node scripts/audit_phase1.mjs
AUDIT_PHASE=installed node scripts/audit_phase1.mjs
```

The audit reports aggregate counts for duplicates, invalid account/asset relationships, status drift, detached records, invalid retirements, orphan history/assignments/notifications, and foreign-key violations. The installed mode additionally reports guard coverage, operational state and lease count. It does not print customer rows, emails, tokens, or private notes.

Stop for any inconsistency. Review affected records privately; do not automatically merge matching CVEs, change historical decisions, erase evidence, rotate links, or replay email. The prepared audit has not been run against production from the credential-free development environment. A new workflow on a draft branch may not be dispatchable until it exists on the default branch; use the reviewed command in an already authorized runner if auditing before merge. Do not merge merely to make an audit dispatchable.

## Publication ordering

1. The account Worker build embeds a SHA-256 identity of backend source, checked-in schema/migrations, and Wrangler configuration. Public feed data is excluded so hourly collection does not incorrectly invalidate API compatibility.
2. The public SELECT-only `/v1/release-readiness` endpoint returns this identity and generic readiness flags, not customer data. Readiness requires all Phase 1 integrity guards, zero unfinished finding contexts, clean integrity counts, correct recovery-trigger definitions/coverage, and no active hold.
3. Every production frontend publication, including hourly scheduled publication, checks this endpoint against its own checkout. A missing/old backend, incomplete schema, detected drift, recovery hold, malformed response, or unreachable endpoint blocks publication.
4. The gate is both in the site workflow and at the beginning of `deploy_site_gate.py`, before any secret/routing/Worker/DNS mutation. There is no bypass environment variable.
5. Backend, frontend, recovery-control, and auxiliary production-writer workflows share `cveharbor-production-release` concurrency. Auxiliary writers also check the recovery hold before mutation and refresh table-guard coverage after schema additions. Old branch revisions still require the credential restrictions above.

A site run that reaches the gate before the backend is ready fails safely; it does not publish an incompatible frontend. Retry after backend verification or allow the next scheduled run. GitHub may replace queued pending runs; inspect cancelled runs and explicitly retry the appropriate reviewed mode. Never bypass the gate to force a publish.

## Worker release modes

- **code-only**: default for manual dispatch; no migrations or unrelated maintenance. Requires installed Phase 1 integrity/recovery prerequisites and no hold.
- **phase1-integrity**: explicitly installs 0031 and 0032, installs recovery guards for existing tables, verifies the database, then deploys the compatible Worker. It never enables unrelated CVIE maintenance.
- **recovery-code-only**: compatible backend fix only. Requires an active, fully drained, frozen hold and complete guards. It performs no migrations or maintenance and leaves the hold active. Its postdeploy check accepts maintenance HTTP 503 only with the expected backend identity and healthy schema; frontend publication stays blocked.
- **cvie-maintenance**: unrelated maintenance runs only when this is deliberately selected. It is not the Phase 1 release procedure and is blocked by an active hold.

Push releases classify the isolated Phase 1 diff. Unknown schema changes fail instead of falling through to maintenance. Unknown code-only changes are subject to the safe code-only prerequisites. The actual current Phase 1 file set was checked against this classifier.

## Exact approved production sequence

Do not execute these steps until the user approves production release.

1. Pin the reviewed revision, recheck CI/current-main compatibility, finish the isolated D1 rehearsal, verify environment protection, and run the production `preflight` audit. Retain its aggregate results. Resolve every nonzero result before proceeding.
2. Record the previous Worker version, frontend artifact/version, deployment settings and D1 recovery bookmark. Use the existing protected release environment; do not change DNS, mail settings or participant access as part of this release.
3. After explicit merge/deployment approval, use the isolated push release or manual **phase1-integrity** mode on approved main. Confirm `remediation_integrity=true`, `maintenance=false`, and no active recovery hold before any mutation.
4. The workflow runs the following from `account-backend`:

   ```sh
   node ../scripts/verify_remediation_integrity_d1.mjs --preflight
   npx --yes wrangler@4.156.0 d1 time-travel info cveharbor-accounts --json
   npx --yes wrangler@4.156.0 d1 execute cveharbor-accounts --remote --file=migrations/0031_remediation_integrity.sql
   npx --yes wrangler@4.156.0 d1 execute cveharbor-accounts --remote --file=migrations/0032_recovery_control.sql
   node ../scripts/recovery_control.mjs install
   node ../scripts/verify_recovery_ready.mjs
   node ../scripts/verify_remediation_integrity_d1.mjs
   npx --yes wrangler@4.156.0 deploy
   node ../scripts/verify_remediation_integrity_d1.mjs
   node ../scripts/verify_backend_release.mjs
   ```

   The build command generates the backend identity. `install` adds guards to all currently installed application tables, including optional schemas, without creating absent feature tables or changing customer data. 0032 creates operational control/lease/audit tables and an initially inactive hold; repeated installation never resets an existing hold.
5. Verify the successful backend release and installed read-only audit. Only then allow a matching frontend run to pass its gate and publish. Run the authenticated route/asset verifier. No customer test records or test assignments should be created.
6. Monitor errors, conflict responses, acknowledgements, notification queue/provider states, and aggregate integrity results. Provider acceptance is not proof of inbox delivery. Cached stale forms may require refresh. Keep Phase 2 blocked until separately approved.

Partial migration or guard installation fails closed at the publication gate. Preserve logs and inspect installed objects. Repeat additive installation only after the cause is understood; do not delete customer records to clear an error.

## Recovery: hold, drain, freeze, repair, resume

Use **Controlled recovery write hold (no deployment)** in the protected production environment. `status` is read-only and the default. `hold`, `freeze`, and `resume` require the current revision and an operational reason/change reference. Inputs are passed as structured environment values, not interpolated into shell code. All mutations append operational audit evidence.

1. **Status and runtime check.** Confirm the compatible leased Worker is serving the recovery protocol. The control workflow verifies this before a mutation. Review the current revision and guard coverage. Pause other deployment activity.
2. **Hold admission.** Select `hold` with the current revision. New account requests (including write-capable GET routes), assignment creation, acknowledgement POSTs, reviewer verification/updates, inventory changes, and all scheduled Worker processes stop. APIs return maintenance 503 with Retry-After. Public acknowledgement/reviewer GETs remain SELECT-only during normal operation; during the hold they show maintenance rather than mutate anything.
3. **Drain.** Re-run `status` until `active_leases=0`. Existing requests and their `waitUntil` tasks may finish normal writes and email delivery bookkeeping. This avoids freezing between provider acceptance and its delivery-state update. A lease covers nested background tasks and all Worker cron work. No lease expires automatically. A crashed worker leaves a visible lease; investigate Cloudflare execution/provider evidence before any separately approved stale-lease cleanup. Do not assume age proves completion.
4. **Freeze database writes.** Select `freeze` using the latest revision. It requires admission already held, complete guard definitions, and zero leases, rechecked atomically. INSERT/UPDATE/DELETE on all installed application tables are then rejected, including direct writes and cascades. Only operational control, lease cleanup, and its audit tables remain writable. This is an account-database maintenance pause, not just hidden UI controls. SELECT-only audit/diagnostic queries remain available.
5. **Recover while frozen.** Prefer a compatible forward fix. The manual `recovery-code-only` release supports a backend-only fix without clearing the hold. Keep canonical aliases, retired-row filtering, assignment/token semantics, and all history guards. Recovery tooling does not provide automatic customer-data repair, guard removal, reverse linking, notification replay, or schema downgrade. Arbitrary DDL/administrative actions are outside row-trigger protections and must remain under the protected operational process.
6. **Verify and resume.** Run the installed read-only integrity audit, inspect guard coverage, confirm zero leases, verify the compatible backend and external delivery evidence as needed. Select `resume` with the latest revision. It requires clean integrity and foreign-key checks and clears admission/freeze flags atomically. Original acknowledgement/reviewer links and notification states remain unchanged. Confirm normal inventory/status/assignment operations and re-run readiness/audit; frontend publication can now pass its gate.

A cancelled hold may be resumed after drain and successful checks without freezing. Normal passage of time still applies to link/session expiration and reminder deadlines; the hold does not extend credentials or reset reminder clocks. Due work resumes under existing deduplication/delivery rules. No historical emails are replayed by activation or resume.

Do not roll back to an unleased/pre-Phase-1 Worker during recovery. It would not respect admission/drain tracking and does not handle retained canonical records correctly. The earlier conditional 0031 object-removal recipe is no longer the routine recovery plan once 0032 is installed. Any schema downgrade needs its own reviewed plan preserving recovery protection and later writes.

A D1 time-travel restore remains a separately approved disaster-recovery action. It can lose legitimate post-bookmark writes and may remove the recovery-control schema. Preserve/reconcile later changes, keep incompatible runtimes stopped, and restore compatible controls before resuming. No time-travel restore was performed in development.
