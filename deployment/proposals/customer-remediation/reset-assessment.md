# Test-data clarification and reset assessment

The owner confirms that existing production Remediation Tracker records and their
assignments, acknowledgements and history are test data. This removes a business
requirement to retain those particular rows; it does not authorize deleting them.
No live database was inspected or changed for this assessment.

## Recommendation: additive migration, no reset

The proposed migration creates empty tables/index/guards. It does not transform,
copy, re-key or backfill existing rows. A reset eliminates none of those objects
or the need for independent customer identities, authenticated ownership checks,
assignment relationships and future history protections. It adds destructive
work, email/reminder coordination and shared-view reconciliation to activation.
Keep cleanup separate and optional after staging acceptance. Do not infer that
staging data is disposable from the production test-data clarification.

## Exact schema-level scope of a hypothetical reset

`impact.json` is generated from the checked-in 143-object production baseline by
`node scripts/customer_remediation_impact.mjs`, using in-memory SQLite only. It
lists every foreign-key edge and relevant deletion trigger. It is not a live row
inventory, reset script or authorization.

The root set would need explicit approval as a fixed list of `(user_id,cve_id)`
keys, captured at a cutoff before any future real data. A blanket predicate such
as “all remediation rows at execution time” is unsuitable. Descendants would be
selected only by these keys and their assignment/status-change IDs:

| Tables | Rows affected by deleting approved roots |
| --- | --- |
| `remediations` | Exactly the approved work-record keys |
| `remediation_assignments`, `remediation_assignment_requests` | Assignments with those user/work keys; request rows include acknowledgement state and bearer-token hashes |
| `remediation_assignment_events`, `remediation_assignment_fyi`, `remediation_assignment_metadata`, `remediation_assignment_notifications` | Children of those assignment IDs, including FYI notification queues |
| `remediation_record_metadata`, `remediation_status_changes`, `remediation_owner_comments` | Metadata, status audit and comments for approved work keys |
| `remediation_status_notifications` | Children of the selected status-change IDs |
| `remediation_review_access`, `remediation_review_challenges`, `remediation_review_sessions`, `remediation_review_activity`, `remediation_review_notifications` | Reviewer access, OTP/session and progress/reminder rows attached to those assignments/work keys |
| `remediation_finding_links`, `remediation_link_audit` | Asset relationships and association audit for selected work keys |
| `remediation_retired_records` | Rows whose **canonical_id** points to a selected root; deleting only a retired placeholder does not remove its canonical relationship |

These are 19 tables including the root, not 19 blanket table truncations.
`remediation_change_context` and `remediation_review_write_context` have no root
cascade: any matching transient rows require explicit analysis, with writers
stopped. `remediation_assignment_limits` contains quota keys, not per-record
foreign keys: retain it, including security/anti-abuse counters.

If the candidate schema has already been installed, its two additional tables,
`remediation_customer_scopes` and `remediation_customer_ticket_history`, are also
involved; their guards intentionally block deletion while the user exists. Do
not disable these guards or delete users to make a reset work. Later integrity
migrations, if present in live production, can add more blockers and context
rows (`remediation_finding_write_context`); the baseline inventory cannot prove
which later migrations are installed.

## Features outside a tracker reset

Foreign keys run from remediation children toward users/assets, so deleting a
tracker root does not cascade upward into user accounts, normal login challenges,
normal sessions, MFA/recovery settings, inventory customers/environments/assets,
technology/package inventory, alert preferences, monitors or intelligence tables.
The guest reviewer OTP/session tables listed above are assignment-specific and
must not be confused with normal account authentication tables.

However, **zero functional impact on other views cannot be confirmed**:

- Workspace summary queries count `remediations`; their statistics change.
- Customer findings expose the linked shared remediation record, its assignments
  and receipt/history. Removing its link changes that experience.
- `customer_finding_statuses`, `customer_finding_tickets` and
  `customer_finding_ticket_history` are separate asset/CVE data. They are not root
  cascade descendants and must remain untouched. Clearing them would change
  Customer Environments/dashboard/report state. Retaining them means a reset
  does not necessarily produce a blank finding view.
- Existing emailed acknowledgement links stop resolving; already sent external
  emails cannot be recalled. Sending/claimed reminders need coordination before
  any cleanup; clearing database queues alone cannot stop an in-flight send.

Consequently this review does not propose a reset or claim a live no-impact
confirmation. If cleanup is later requested, first use an explicitly authorized
read-only audit of the actual schema/triggers, foreign-key integrity, exact root
keys, linked assets and descendant counts. Keep row IDs and content private;
review sanitized counts and a digest of the approved scope. Snapshot/export,
writer quiescence, a fixed cutoff and postchecks would need separate approval.
Production cleanup must never become part of the staging deployment workflow.
