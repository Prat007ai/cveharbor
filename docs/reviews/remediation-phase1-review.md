> **HISTORICAL REVIEW — NOT AN EXECUTION RUNBOOK.** Findings, workflow names, credentials, test counts and procedures below describe earlier revisions. Do not execute their rollout/rollback commands. Use [the consolidated administrator checklist](phase1-administrator-checklist.md), [current release/recovery procedure](remediation-phase1-release.md) and [R2 architecture](intelligence-publication.md).

# CVEHarbor remediation improvement plan: review and Phase 1 results

Review date: 2026-11-03. Source baseline: `1cc762663b1fd176041f37b5512f8e802403b880` on `main`.

Input: “Comprehensive UI, UX, and Remediation Workflow Improvements - Nov 2.txt”. The user's request authorizes a review and Phase 1 only. Later-phase requirements in the attachment are recommendations to assess, not authorization to implement them now.

## Scope and evidence

Reviewed current repository source, versioned database schemas/migrations, API handlers, frontend integrations, email/reviewer flows, and automated tests. GitHub comparison confirmed that changes since the previous notification fix were public advisory/feed updates, not remediation implementation changes.

No live customer database credentials are available in this workspace. Production records, current database contents, actual recipient inboxes, and the exact historical decision behind the user's screenshot were **not** inspected. Tests use synthetic SQLite data and intercepted mail. The supplied production audit script reports aggregate inconsistency counts without printing customer content, addresses, or tokens.

Phase 1 is implemented on a review branch. It is not a UI redesign or a new status model. Production rollout is separate from implementation/test completion; no production record consolidation is performed by the migration.

## Existing architecture

| Area | Current implementation | Important relationship |
|---|---|---|
| Vulnerability intelligence | Public advisory index/catalogue, inventory matching, WordPress/plugin sources, on-demand public CVE lookup | A potential match is not confirmed exploitation or verified applicability |
| Customer inventory | `inventory_customers` → `inventory_environments` → `inventory_assets` | An asset/technology row has a stable ID; name and version are attributes, not finding identity |
| Finding decisions | `customer_finding_statuses`, keyed by account/asset/CVE | Saved treatment; not a complete durable registry of every generated finding |
| Work records | `remediations`, primary key `(user_id,cve_id)` | `cve_id` is an overloaded record key: plain CVE for legacy/unscoped records, CVE plus asset UUID for scoped work |
| Finding/work relationship | `remediation_finding_links`, unique account/asset/CVE and one link per record | One-to-one today, not many findings per work item |
| Assignment and receipt | `remediation_assignments`, `remediation_assignment_requests`, `remediation_assignment_fyi`, assignment metadata | Invitation IDs, tokens, receipt evidence, and FYI membership belong to a record-specific assignment |
| Reviewer access | `remediation_review_access`, challenges, sessions, activity | Email verification gives access to a particular assignment; acknowledgement alone is not identity verification |
| Status history/comments | `remediation_status_changes`, `remediation_owner_comments`, reviewer activity | Actors and timestamps are retained separately from the current row |
| Linking history | `remediation_link_audit`, `remediation_retired_records` | Preserve link decisions and resolve a retired placeholder to its canonical record |
| Notifications | `remediation_status_notifications`, `remediation_review_notifications`, FYI delivery history | Status outbox deduplicates by event/recipient; reminder cycles are separate |

`finding-remediation.js`, `finding-assignment-links.js`, and `remediation-workflow.js` coordinate linked writes. A database trigger projects the shared work status into `customer_finding_statuses`. Dashboard and Tracker are views of the same work only after explicit linking. Neither matching CVE text nor assignment email is a sufficient customer/asset identity.

Core APIs:

- `GET/POST /v1/finding-remediations/:asset/:cve`: preview or open/create linked work.
- `POST /v1/finding-remediations/:asset/:cve/link-existing`: explicitly connect an unscoped investigation.
- `GET /v1/finding-assignments`: scoped assignment/acknowledgement summaries.
- `GET /v1/remediation-records/:record`, `POST .../comments`: shared detail and owner comments.
- `PUT /v1/remediations/:record`: status/owner/date/notes with concurrency checks.
- `PUT /v1/finding-statuses/:asset/:cve`: finding-side status writer.
- Assignment, receipt, reviewer activity and status-history endpoints retain their existing identities.
- `confirm.cveharbor.com/assignment/:assignment`: verified reviewer access; emailed invitation URLs must remain valid.

## Findings, conflicts, and risks

| Priority | Finding | Risk / decision |
|---|---|---|
| High — Phase 1 | Creation used separate read/insert/link steps with `INSERT OR IGNORE` and returned a precomputed key | A concurrent confirmed link could leave an unused row or return the wrong record. Resolve the canonical database relationship and guard creation transactionally. |
| High — Phase 1 | API creation could create asset work despite an existing standalone investigation without an explicit separation decision | Require the existing review/link choice or an explicit keep-separate decision; never auto-merge by CVE. |
| High — Phase 1 | First status save on an unlinked finding could write only the finding projection | Shared status history and notifications could be bypassed. Use one atomic shared-record/status-history path for new saves. |
| High — Phase 1 | Existing linking selected a final status, but could synthesize a reason and did not validate changed asset context | The screenshot cannot prove whether reopening was deliberate. Show both statuses, preserve the finding status by default, require a reason for a transition, and validate reviewed customer/environment/asset context. |
| High — Phase 1 | Linking physically deleted the unassigned placeholder after moving its history | Keep the original row as a read-only retired record, retaining IDs and notes while exposing one canonical active work item. |
| High — Phase 1 | Inventory deletion cascaded to finding/work records and their assignments/history; standalone removal could cascade history too | Block destructive removal when retained finding/remediation data exists. Keep deletion of genuinely empty records/assets and explicit account deletion behavior. A future archive UX is separate work. |
| Medium — Phase 1 | Finding identity and projection consistency relied partly on handler conventions | Add database guards against mismatched/reassigned links and direct writes that disagree with the shared status. Existing uniqueness constraints remain. |
| Later phase | Findings are partly generated from the current intelligence/index; saved outcomes do not constitute a full durable finding registry | A software/index change can alter what appears in the current table. Persisted finding lifecycle and reevaluation require a deliberate design, not recreating records on every scan. |
| Later phase | Applicability, progress, and treatment share five existing status values | Do not rename historical `Remediated` to Verified Fixed. New semantics require additive fields, compatibility mappings, evidence, and permissions. |
| Later phase | One work item currently has one asset finding; status projection assumes this | Removing the unique constraint to enable bulk work would propagate one outcome to every linked asset. Design independent per-finding outcomes before many-to-many support. |
| Later phase | Any recorded status change/qualifying comment resets all related assignment timers | Does not measure Alex's individual response. Retain current behavior in Phase 1; introduce separate assignee-response events/timestamps in Phase 3. |
| Later phase | Reminder interval is captured at assignment creation; reviewer access lasts 30 days | Changes to urgency do not automatically redesign existing cycles. Clarify expiry, interval changes, reassignment, and revocation before changing reminders. |
| Later phase | Status, comment, FYI, and reminder notifications have distinct recipient policies | Status updates deduplicate all eligible participants, but comments are not an identical all-participant notification system. Unify policy deliberately, retaining role/privacy boundaries and prior delivery evidence. |
| Later phase | Provider acceptance is not inbox delivery; uncertain status sends are not blindly replayed | Keep wording and duplicate protection; any richer retry design needs provider idempotency/reconciliation. |
| Later phase | FYI email does not grant access to the private Tracker | Scoped, email-verified read-only manager access needs its own authorization model. Do not reuse reviewer edit sessions or expose the full account. |
| Later phase | Tracker renders its advisory map from public index/catalogue; dashboard can also use plugin/intelligence results | Different source availability can explain missing advisory details. High published severity versus Critical assigned severity can be intentional. Verify source resolution and display them separately; the specific production historical row was not inspected. |
| Later phase | Ticket references are append-only; the plan proposes removal | Implement reversible reference retirement/audit if needed, not deletion of ticket history. No automatic Azure DevOps synchronization is present. |
| Later phase | Timeline data is split across record-level and assignment-level tables | A combined UI must preserve reviewer-specific visibility, actor attribution, pagination, and email attempt states. |

## Phase 1 implementation

### Data integrity and duplicate prevention

- Reuse existing stable account/asset/CVE identity and uniqueness constraints.
- New transaction-local finding context validates the relationship, standalone record version, saved finding state, and customer/environment/asset snapshot before creating or linking.
- Concurrent create/create and create/link requests resolve to the canonical winning record; a failed status transaction rolls back all record, link, audit, and notification writes.
- Finding creation requires an explicit keep-separate decision when an unscoped investigation exists. The existing Keep separate action supplies it. Different customers/assets remain separate even for the same CVE.
- An unexpected detached record is reported for review rather than silently adopted.

### Correct linking and preservation

- Require confirmation of the customer asset, plus a reason when either prior status differs from the selected outcome.
- The existing dialog shows current finding status and existing assignment status. Its default preserves the finding's decision; a deliberately selected status-save action remains explicit.
- Retain the original placeholder row unchanged, remove only its active relationship, and store its canonical mapping. Active lists and summary/capacity counts exclude retired rows.
- Existing history/comment IDs, content, actors, and times are preserved; their record references move to the canonical work as before. Link audit snapshots preserve original source/target information and retained event IDs.
- Old record GET links resolve within the authenticated account to the canonical record. Stale writes to a retired ID return 409 rather than applying an old form to different work.
- Assignment IDs, bearer-token hashes, acknowledgement timestamps, FYI records, reviewer sessions/access expiry, ticket references, and existing email notification rows are preserved.
- Database guards prevent deletion of records/assets with retained remediation/finding data. Parent customer/environment deletion is consequently blocked when it would cascade into this data. Empty-item deletion remains available.

### Status synchronization

- The first finding-side status save now creates the shared record from the saved finding baseline and records an actual transition with actor/reason in the same transaction.
- A matching standalone investigation requires a deliberate link/separate choice first.
- Database guards reject direct writes that would make a linked dashboard status disagree with the canonical work status.
- Status vocabulary, acknowledgement semantics, reviewer permissions, reminder policy, and email templates remain unchanged.
- Unchanged saves/linking do not enqueue status emails. Actual confirmed status changes continue to notify existing participants; historical rows are not replayed.

### Database/API compatibility

Migration `0031_remediation_integrity.sql` adds a transaction-context table and guards. It does not rewrite existing records, convert statuses, backfill events, link records, delete rows, change tokens, or send emails.

New code can read the pre-0031 schema. Until the migration exists, existing behavior remains available for rollout compatibility; the Phase 1 protections are active only after migration. After migration, older unsafe clients may receive a refresh/conflict response instead of bypassing integrity checks.

Additive API fields: preview `integrity` and asset identity context; creation `keep_separate`/`expected_manual`; first-save `expected_finding`; confirmed linking `expected_asset`. Existing linked status updates continue to use `expected_updated`.

Only the existing linking/status controls were adjusted for these integrity requirements. No drawer redesign, table restyling, new statuses, bulk workflow, verification system, or manager-access feature was introduced.

## Validation

Executed locally:

- All 38 backend test files passed, including the existing acknowledgement, reviewer expiry/revocation, status notification, reminder, finding-link, and tenant-boundary suites.
- 11 focused Phase 1 scenarios passed against the real Worker and SQLite with foreign keys/triggers enabled.
- Phase 1 browser journey passed against the real Worker with synthetic data and intercepted mail, including retained rows, canonical old links, first-save history, explicit linking, one active queue row, notification deduplication, and separate-customer isolation.
- 118 Python tests passed.
- Site build, deployment asset preflight, customer-security smoke, browser smoke, and release-mode tests passed.

The Phase 1 scenarios cover:

1. Repeatable additive migration without changing existing records and delivery/access data.
2. Explicit standalone separation, stable identity across rename/version changes, and distinct customer findings.
3. Create-versus-link race returning the canonical winner with no orphan row.
4. Create-versus-create idempotence and newly appearing unscoped work.
5. Atomic first status save with actor/reason/history and no invented recipients.
6. Full rollback after a concurrent first-save conflict.
7. Preserved original rows, event IDs, receipt tokens, reviewer sessions, tickets and emails after linking; canonical read aliases and rejected stale writes.
8. Explicit resolution of Accepted Risk/Not Applicable conflicts and changed asset-context rejection.
9. Database-level identity, reassignment, status-drift and deletion-cascade protection.
10. Unchanged linking retains reminder/email state; the aggregate audit performs no writes and reports drift without repairing it.
11. Retention guards do not interfere with explicit account deletion.

No test sends a real email or changes production data. CI results and the review PR provide an additional validation record. Exact historical production data consistency remains subject to the read-only preflight.

## Recommended implementation order

1. **Phase 1 — this review and integrity work:** review the branch/results; run the aggregate production preflight; resolve any reported historical exceptions individually; deploy the additive guards and compatible code through the scoped release procedure.
2. **Phase 2 — UI, only after user approval:** improve queue placement, tables, filters, reusable detail presentation and navigation while preserving the Phase 1 data model and five status values. Do not show counts for states that do not yet exist.
3. **Phase 3 — workflow:** separate applicability/progress/treatment with backward compatibility; assignee-specific progress/reminder clocks; explicit assignment/receipt/expiry display; consistent notification policy; scoped manager read access and an authorized unified timeline.
4. **Phase 4 — verification/risk:** introduce pending verification and verified outcomes, evidence and approver controls, accepted-risk ownership/expiry/review. Historical completion remains unverified unless evidence supports it.
5. **Phase 5 — automation/reporting:** independent outcomes for multiple selected findings, durable reevaluation lifecycle, optional external integrations, bulk operations and customer reports. Many-to-many work must wait until independent finding outcomes and permissions are defined.

## Outstanding and limits

- Phase 2 is not started and requires the user's review and approval.
- This implementation has not been merged/deployed, and the production database preflight has not run from this credential-free workspace.
- Existing contradictory/orphaned relationships are detected, not automatically repaired. Same-CVE standalone records can be intentional and are not automatically merged.
- Previous deletion of data by older versions cannot be reconstructed from source code; recovery would require actual retained audit information or a backup and a separate reviewed repair.
- The 250 active-work limit and one-work/one-finding model remain. No synthetic Verified Fixed, risk approvals, or new manager privileges are introduced.
- Current record-wide reminder-reset semantics remain intentionally unchanged until Phase 3.
- See `remediation-phase1-release.md` for release gates and rollback constraints.
