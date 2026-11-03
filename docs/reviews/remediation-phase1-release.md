# Phase 1 release and rollback procedure

## Release prerequisites

- Review the Phase 1 implementation and test results. Do not include Phase 2 changes.
- Use the existing `cloudflare-worker-production` release environment and its configured credentials; do not copy credentials into source or logs.
- Required baseline: existing inventory, finding status/ticket/history, remediation workflow, assignment/access, and migrations 0028–0030. Migration 0031 is not a replacement for those schemas.
- The release classifier recognizes the specific Phase 1 backend files. It skips unrelated CVIE migrations, cache refreshes, rescans, secret changes, and bootstrap jobs.

## Read-only production preflight

Run from the repository root using the configured release credentials:

```sh
node scripts/verify_remediation_integrity_d1.mjs --preflight
```

This issues SELECTs only and reports counts for duplicate finding relationships, invalid identities/ownership, status drift, detached asset records, invalid retirements, orphan status history, orphan assignments, and orphan status-email records. It does not print customer records, addresses, tokens, or private notes. A nonzero integrity count fails the gate.

If a check fails, stop rollout and investigate the relevant records privately. Do not bulk merge matching CVEs, rewrite decisions, discard notifications, or manufacture missing history. Existing standalone investigations can be legitimate and are not automatically converted by this release.

A successful source-code review does not substitute for this live-data preflight. It has not been run from the credential-free development workspace.

## Migration and deployment

The scoped deployment workflow performs the following after preflight:

```sh
cd account-backend
npx --yes wrangler@4.156.0 d1 time-travel info cveharbor-accounts --json
npx --yes wrangler@4.156.0 d1 execute cveharbor-accounts --remote --file=migrations/0031_remediation_integrity.sql
node ../scripts/verify_remediation_integrity_d1.mjs
npx --yes wrangler@4.156.0 deploy
```

Retain the pre-migration recovery bookmark and deployment/version evidence from the workflow. The migration adds guards and an empty transaction-context table; it performs no customer-data DML or automatic linking. It is repeatable.

Deploy the compatible frontend assets using the existing site workflow and run the source/asset production verifier. Run the aggregate integrity audit again after the Worker deployment.

During mixed-version rollout, an older unsafe link attempt may receive a conflict/error instead of deleting history. An older client missing the new snapshot/confirmation fields should refresh. This is preferable to silently applying an unreviewed status or losing data.

Use synthetic staging for create/link/assignment/status tests. Do not generate test assignments or historical replay emails against real customer records.

## Rollback and recovery

1. Pause affected finding/link/status writes while investigating a failed rollout. Preserve logs and the recovery bookmark. Do not delete the new context/retirement/audit data.
2. If only frontend behavior fails, roll back frontend assets or fix forward while keeping the compatible backend and integrity guards. Old clients may be asked to refresh before a protected write.
3. Do **not** blindly roll the backend back to pre-Phase-1 code after a link has retained a placeholder row. That code does not exclude retained rows from the active queue and can attempt destructive deletes. Prefer a compatible code fix while retaining the migration.
4. Before any schema/code reversal, privately check for retained placeholders:

```sql
SELECT COUNT(*) AS retained_placeholder_rows
FROM remediation_retired_records t
JOIN remediations r ON r.user_id=t.user_id AND r.cve_id=t.record_id;

SELECT COUNT(*) AS unfinished_transactions
FROM remediation_finding_write_context;
```

5. If there are **no** retained placeholder rows, no in-flight writers, and no unfinished transaction contexts, the additional guards/context table may be removed as a reviewed rollback, followed by restoring the prior Worker. This restores the old behavior and its known risks. Remove only these Phase 1 objects:

```sql
DROP TRIGGER IF EXISTS validate_finding_write;
DROP TRIGGER IF EXISTS finding_link_identity;
DROP TRIGGER IF EXISTS finding_link_immutable;
DROP TRIGGER IF EXISTS retired_remediation_read_only;
DROP TRIGGER IF EXISTS preserve_remediation_history;
DROP TRIGGER IF EXISTS preserve_asset_finding_history;
DROP TRIGGER IF EXISTS linked_finding_status_insert;
DROP TRIGGER IF EXISTS linked_finding_status_update;
DROP TABLE IF EXISTS remediation_finding_write_context;
```

6. If retained placeholders exist, do not delete them to make old code work. Retain compatible canonical-read/list filtering and the write guards. Any reverse-link/data repair needs its own reviewed transaction using the recorded snapshots and event IDs; it must preserve later updates and all assignments/notifications.
7. A full D1 time-travel restore is a disaster-recovery action, not the routine rollback. It can erase legitimate writes made after the bookmark. Preserve/export subsequent changes and obtain explicit authorization for a data restore before considering it.

Migration 0031 itself does not need customer-data reversal because it does not transform existing rows. Runtime linking is a separate, explicitly confirmed operation with durable audit evidence.
