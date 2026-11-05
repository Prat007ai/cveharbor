# Customer remediation: inactive migration proposal

This plan and SQL are **not** in an automatic migration directory. Code review
or merging the feature does not authorize applying this proposal. No live data,
database, Worker, baseline file, resource or credential has been changed.

## Reviewed identity model

Keep `remediations(user_id,cve_id)` as the stable work-record identity used by
assignments, acknowledgements, status changes, reviewer activity and comments.
Existing CVE-only rows remain Unassigned; no backfill infers their customer.

- Existing asset work continues to use `remediation_finding_links`, its stable
  asset/CVE key and the existing finding status/ticket projections.
- A new customer/environment work record gets a `CVE~UUID` key recognized by
  the existing routes. The UUID identifies work, not an invented inventory asset.
- `remediation_customer_scopes` attaches that record to an authenticated user's
  real customer and optional real environment. One record per customer,
  environment (including no environment), and CVE prevents duplicate contexts.
- An explicit confirmed association can retain a legacy CVE-only record's ID.
  Assignments/tokens/history remain referenced by the same key. Association is
  immutable; no implicit reparenting or merging into an existing customer record.
- Distinct customer, environment and asset contexts can independently track the
  same CVE. Customer summaries count work records, not distinct public CVE IDs.
- Append-only customer ticket references use the work-record key. Asset ticket
  history remains in its existing tables. User-facing public CVE links use only
  the CVE portion, never the private work key.

The backend validates all IDs by authenticated user and validates each parent
relationship. Database triggers independently enforce ownership and immutable
associations. Existing context deletion is refused while history is retained.
Scoped records cannot be overwritten by legacy browser imports.

## Approval and preflight

1. Review the application PR and this migration separately. Verify the exact SQL
   checksum with `node scripts/customer_remediation_plan.mjs` (local SQLite only).
2. Independently authorize the staging account, existing database, approved
   source commit, schema extension and execution window. Do not run `initialize`
   or repeat step 209, synthetic publication, Access setup or resource creation.
3. Confirm current schema/receipts and foreign-key integrity with existing
   read-only tools. The checked-in production baseline must remain unchanged.
   Require the reviewed baseline and existing support objects to match exactly.
4. Pause writes for the approved window. Capture an existing D1 recovery bookmark
   and the approved private export using existing controls. Keep both out of PRs,
   logs and public artifacts. Record table counts and private row/history hashes
   for before/after comparison, not customer data in CI.
5. Apply the reviewed SQL once, as an atomic approved staging change. It creates
   only two tables, one unique index and ownership/history triggers. It does not
   backfill, rename, alter, delete or update existing rows. Refuse partial or
   pre-existing objects rather than silently accepting an unknown version.
6. Verify the new tables are empty, original rows/counts/history hashes unchanged,
   new objects match the plan, and `pragma_foreign_key_check` is empty.

## Application and staging profile boundary

The source changes are a candidate, not a change to the production replica.
`release/baseline.json`, existing migrations, step-209 receipts and the current
staging source-mode configuration remain unchanged. The current production-
baseline build intentionally pins its old application sources and exact schema;
ordinary `release` will **not** activate this candidate and may reject an extended
schema. Do not edit baseline hashes or weaken readiness to bypass that boundary.

Before any live feature validation, review a **separate staging candidate build
and schema profile** pinned to the approved application commit plus this proposal's
checksum and expected schema. Approval must include its deployment path; the
existing automatic production-baseline lane must not run against the extended
schema. This PR does not enable a new profile or deploy an unreviewed candidate.
Without the tables, customer-only writes return 503 and capability is false;
existing reads and asset/standalone work retain their compatibility.

## Acceptance with fictional data only

Use two fictional customers with environments/assets and a second fictional
account. Create the same CVE independently with different owners/status/dates,
notes, tickets and reviewers. Check All Records, each customer and Unassigned,
all four cards, queue, CSV, refresh persistence and stale-write rejection. Verify
customer selection on navigation from inventory/dashboard. Associate one old
unassigned record explicitly and verify unchanged record/assignment IDs/history.
Verify foreign user/customer/environment/asset IDs cannot read or mutate data.
Complete an acknowledgement for one customer and verify the other is still
Pending. Inspect reminders/history through the existing flows. Send email only
through staging capture. Do not use customer records or production requests.

## Rollback and preservation

Before feature writes, code can be rolled back and the empty new objects removed
only under a separately approved inverse plan, checking both tables are empty
first. The original schema/data are unchanged by the forward proposal.

After any association or new record/ticket/assignment exists, **do not drop tables**
or blindly revert to code that cannot resolve the new IDs. Stop new feature
writes and retain compatible readers. Prefer a forward correction. Export and
reconcile new associations/history before approving a full restore: restoring a
bookmark can discard unrelated changes made after that bookmark. There is no
automatic rollback, bulk unlinking, re-keying, ownership change or token replay.
