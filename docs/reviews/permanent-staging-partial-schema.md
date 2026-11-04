# Permanent staging: partial schema assessment

> Current coordinated plan: [Task 2C two-phase continuation](../cvie-staging-continuation-plan.md). Original checkpoint 29 is verified. Adoption 29→37 and remaining migration 37→740 remain separate approvals, both requiring fresh private recovery evidence; nothing has executed beyond original 29.

> **Historical assessment superseded by verified evidence.** Run 41707547474,
> artifact 13275811878 subsequently confirmed the exact original checkpoint 29.
> Use the [adoption review package](permanent-staging-adoption.md) for current
> instructions. The earlier pending-evidence observations below describe the
> preceding review, not the current verification status. No migration is approved.

Status: awaiting exact live schema definitions. No remote initialization approved.
The account owner reports 18 application tables, zero rows in each, existing
indexes and no application triggers. This supersedes the earlier empty-schema
observation. A table count cannot identify installed migrations or prove schema
compatibility; the actual definitions have not yet been provided to this review.

Target, unchanged:

- Account: `9706b4d98ad72884e67fd1eb875c8a61`.
- D1: `cveharbor-accounts-staging`, `fac61562-fc31-426d-8032-550aba63b7f6`.
- Existing private API and frontend Workers and their bindings remain in place.

## Immediate read-only action

Cloudflare → staging account → Storage & databases → D1 →
`cveharbor-accounts-staging` → Console. Run
[`inspect-existing-schema.sql`](../../staging/sql/inspect-existing-schema.sql).
Provide all result rows with the full `sql` field, preferably as a CSV/JSON export.
It returns definitions, not customer records. Retain D1/migration metadata objects
in the result so they can be distinguished from application objects and preserved.

The schema comparison cannot be completed from the reported counts. No missing
object list or forward SQL is approved until the definitions are available.

PR #243's intervening commit `57069a36a98fed0b29a4b2fb537255e11e80ab90`
adds a [read-only original-checkpoint diagnostic](../cvie-staging-schema-diagnostic.md).
Its frozen original checkpoint expects 18 empty tables, 10 explicit indexes and
no triggers. This is consistent with the owner's report but is not a verified
match. The diagnostic checks exact definitions, counts, column/index metadata,
foreign keys and integrity using individual count queries compatible with D1's
compound SELECT limit. It requires a separately approved execution; none ran in
this review. It verifies the original plan, not the expanded permanent-staging
manifest. Even a successful original checkpoint-29 result does not authorize
cursor 29 in the current plan or establish migration ledger receipts.

## Recommended approach after inspection

1. Compare every existing table/column/type/default/constraint, foreign key,
   unique/partial index, view and trigger with the ordered manifest's intermediate
   and final states. Identify exact matches, earlier compatible definitions,
   missing objects and incompatible/unknown objects. Inspect existing migration
   bookkeeping separately; never invent receipts for migrations not verified.
2. Reconstruct the reported schema in local SQLite. Prepare an explicit,
   checksum-pinned adoption/forward plan starting from that exact state. Preserve
   matching objects, apply only justified missing prerequisites and ordered
   migration statements, and retain both branches' distinct 0028/0029 migrations
   plus 0030–0032. Do not run the complete bootstrap with IF NOT EXISTS: it cannot
   correct incompatible existing definitions and can mask differences.
3. If the state matches a recorded checkpoint exactly, including schema, counts,
   seed values and bookkeeping, review that checkpoint for explicit resume.
   Otherwise create a reviewed adoption plan, not an arbitrary nonzero cursor.
   Unexpected/incompatible definitions stop the process. Any required rebuild or
   destructive statement must be identified for separate approval, not inferred
   from zero row counts. No table drop/reset is currently authorized.
4. Locally test initialization, expected seed creation, full schema/foreign-key
   integrity, preservation of existing objects, receipt correctness, partial/lost
   responses, approved resume and rejection of changed schema or newly added rows.
   Keep per-batch transactional preconditions, usage limits and response readback.
5. Before any approved write, re-confirm the exact account/database and live
   Worker binding/version metadata; verify that application/cron writes cannot
   race initialization. Do not assume recovery controls from 0032 already exist.
   If a temporary write restriction needs infrastructure changes, seek separate
   approval. Capture a fresh D1 Time Travel bookmark and verify its retention/
   recoverability; save a secure D1 export, schema inventory and current row counts.
   Preserve migration metadata and built-in seeds. Record checksums and the UTC
   capture time. Export/restore instructions must be scoped to this staging UUID.
6. Present the exact SQL, start-state fingerprint, plan digest, batch counts,
   recovery evidence and local test results for owner approval. Only then execute
   the guarded database operation. Verify final objects, seeded values, foreign
   keys, receipts and unchanged Worker/Access settings before considering any
   separately approved publication or Worker update.

A Time Travel bookmark/export has NOT been captured by this review: the current
execution environment has no configured Cloudflare credential or authorized
Cloudflare API network route. GitHub environment secrets are not accessible from
this shell. Use the existing secure administrator environment for the approved
read-only capture; never paste tokens into chat. A schema listing is evidence for
comparison, not a substitute for a verified recovery point.

## Release isolation correction

Review of PR #243 at `6e05106ce7d5f4c8741261775f2e4e69c6eea719` found a dispatch
fall-through: a completed `migrate` or `publish-synthetic` action could reach the
Worker update branch. The prepared correction makes the action branches mutually
exclusive and independently requires `update` or `recover-code` at the deployment
boundary. Two regression tests reproduce the old failure and pass with the fix.
No live operation was run. This correction does not enable partial-schema adoption
or authorize any migration, publication, deployment, reset or restore.

The correction preserves the intervening diagnostic changes and its early-return
isolation. Local validation covers release dispatch, SQLite migration checkpoints,
manifest/schema inventory and read-only diagnostic behavior. Remote D1 validation
and actual partial-schema adoption remain outstanding.

The existing bootstrap remains blocked for unrecognized schemas. The older
activation runbook's step-0 instruction applies only to a verified empty starting
schema and must not be used for this reported partial database.
