> **Phase 1 deployment notice:** Use [the consolidated administrator checklist](reviews/phase1-administrator-checklist.md) for current release, credential, staging and recovery steps. Deployment/migration/rollback recipes below are feature-history references, not instructions to execute during Phase 1. Feature behavior descriptions remain applicable unless superseded by the current implementation.

# Optional FYI recipients for vulnerability assignments

The Assign by email dialog accepts up to five optional FYI addresses (comma, semicolon or newline separated). Server validation normalizes and deduplicates addresses, excludes the assignee, and rejects the entire request if any address is invalid or setup is unavailable. The pre-send confirmation lists the assignee and all FYI recipients. Existing external-recipient behavior is preserved; no domain restriction has been added.

Each FYI recipient receives a separate message when the primary assignment email is accepted, and a receipt update when the assignee explicitly acknowledges. No address list, private notes, customer details, target date or acknowledgement token is copied into FYI emails. Public advisory fields come from the assignment's existing server-fetched snapshot. Only the assignee receives the acknowledgement link. The requester receives FYI messages only if explicitly included.

Receipt updates say “acknowledged receipt,” with a UTC timestamp and the saved remediation status at acknowledgement. They never claim that work has started or change remediation status. Investigating is displayed as “In Progress (Investigating).” Link use is not verified identity or a read receipt.

## Persistence, delivery and access

Additive migration `0025_assignment_fyi.sql` creates observer and notification tables, a queue index, and three transactional triggers. Existing records are not backfilled. Primary-send acceptance creates initial jobs; the first acknowledgement creates one update per observer atomically with receipt recording. Unique keys prevent repeated clicks/concurrent confirmations from creating duplicate jobs. GET/HEAD never queue or send mail.

The existing SMTP2GO service and assignment sender/key deliver these messages. Each job has a conditional claim and unique lease so concurrent workers and stale completions cannot overwrite another attempt. Immediate Worker `waitUntil` processing is backed by the existing minute cron; no new cron, scan, ingestion service or paid service is introduced. Up to ten jobs are examined per invocation. Receipt updates wait until the initial FYI has completed or become unconfirmed. Existing recipient quota (20/day, shared with assignment mail) and a FYI sender quota (50/hour) defer excess jobs for an hour.

Provider acceptance is shown as “Accepted by email provider,” not inbox delivery. An uncertain provider response or interrupted send is shown as “Delivery unconfirmed” and is not automatically retried because provider idempotency is not guaranteed. The sender may deliberately retry from assignment history, with a duplicate-mail warning and a maximum of three provider attempts per notification. Queued jobs survive request interruptions. Revoking or rotating the assignment cancels unsent jobs. An already in-flight provider request cannot be recalled. Record/account deletion cascades observer and notification rows.

History is paginated and account-scoped through the existing `GET /v1/remediations/{cve}/assignments` response, now optionally including `fyi` delivery entries. `POST /v1/remediations/{cve}/assignments/{id}/fyi/retry` requires the existing MFA-backed account session and origin checks. Public confirmation pages never expose FYI addresses. Resend pre-fills the prior FYI list for review; it sends a new assignment rather than altering another assignment's observer list.

## Configuration and release

`ASSIGNMENT_FYI_ENABLED=true` requires migration 0025. With the flag off or schema absent, the field is hidden, nonempty FYI requests fail before any email is sent, and normal assignments without FYI recipients continue to work. Disabling the flag pauses queued FYI delivery. Previously registered observers still receive an audit-backed queued event upon acknowledgement while paused; delivery resumes only when re-enabled.

The release workflow records a D1 Time Travel bookmark, applies only migration 0025, runs SELECT-only schema/tenant probes, deploys the Worker, and checks private API boundaries. Unrelated CVIE maintenance is excluded. Frontend deployment verifies the versioned `assignment-fyi-1` assets. Rollback can disable the FYI flag and restore previous frontend code; retain additive tables/history. Do not rewind customer records for a code rollback.

## Verification

The real SQLite/Worker tests cover validation, duplicate exclusion, primary/FYI provider failures, independent recipients, atomic receipt events, read-only GET/HEAD, account isolation, quotas/deferred delivery, explicit retries, stale leases, revocation/rotation/deletion, and safe email output. The browser test exercises field validation, recipient confirmation, two separate FYI messages, guest acknowledgement, two receipt updates, history, resend prefill and desktop/mobile screenshots. All test recipients are synthetic; no real emails are sent. Native Gmail/Outlook rendering and live inbox delivery are not certified by these tests.
