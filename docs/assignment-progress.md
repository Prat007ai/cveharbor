# Reviewer progress and inactivity reminders

New assignment emails include **View / Update Assignment** at `confirm.cveharbor.com/assignment/<invitation-id>`. The recipient verifies their assigned email with a one-time code; a CVEHarbor account is not required. The invitation ID alone grants no access. Old invitations are not enrolled or emailed retroactively. The owner can deliberately resend an invitation to enable this workflow, revoking the previous invitation through the existing resend flow.

Verified reviewers can choose Open, In progress (Investigating), Completed / Remediated, or Not applicable. A status change requires a reason, up to 1,000 characters. A comment-only update requires at least 10 characters, up to 2,000. Reviewers can include findings, blockers, evidence descriptions and work-item URLs as plain text. The minimum length validates that something was supplied; it does not assess the quality or truth of progress. Accepted Risk is reserved for the account owner. Reviewers cannot edit private owner notes, the owner or target date, or another record.

A successful update changes the same private record shown in **Recent Records**, with verified email, timestamp, status reason and private comment history. Visible tracker pages refresh every minute and on focus, while avoiding open dialogs; the Refresh button remains available. Concurrent changes require the reviewer to reload before saving. The owner sees all reviewer activity for that record; each reviewer sees only activity for their own invitation. Sender/FYI recipients receive a brief status/update summary, excluding comments, reasons, private notes and verification credentials. FYI inclusion does not grant access to private history.

## Reminder policy

| Severity at assignment | First reminder after inactivity |
| --- | --- |
| Severity 1 / Critical | 24 elapsed hours |
| Severity 2 / High | 24 elapsed hours |
| Severity 3 / Medium | 48 elapsed hours |
| Low / Informational / Unknown | No automatic reminder |

Use the selected assigned severity; otherwise use the published advisory severity. The interval is fixed for that invitation. Resend deliberately to change the invitation assessment. Elapsed hours include weekends and holidays. The initial timer starts when the primary assignment email is confirmed as sent. The existing one-minute scheduled dispatcher checks due notifications; provider availability and email budgets can delay delivery beyond the threshold.

**One reminder per inactivity period**, as requested. A reasoned status change by the owner or reviewer, or a substantive reviewer comment, resets the record's timer for all its active invitations. Acknowledgement, opening an email/page and unchanged saves do not reset it. New progress permits one reminder after another full interval. Completed, Not applicable and Accepted Risk stop reminders; reopening starts a new interval. Revoked, failed or expired invitations cannot send reminders. Access and reminders end 30 days after invitation creation; the owner can issue a new invitation if work continues.

Reminders go only to the assigned reviewer. They ask for progress, blockers or an outcome and state when progress was last recorded. They do not claim the recipient failed to work or that an email was read. No manager escalation or repeating daily chase is enabled.

## Access and delivery guarantees

- Codes expire in 10 minutes, allow five attempts and are single-use. Codes and session tokens are stored as hashes. Requests are capped at three codes per invitation per hour and share the existing 20-email recipient daily budget. Native IP rate limiting applies before guest handling.
- Verified sessions expire after 30 minutes (or sooner if invitation access ends). The host-only cookie is Secure, HttpOnly and SameSite=Strict. Writes require exact same-origin POST, a session-bound form proof, an unexpired grant/session and a matching record version inside the transaction. Revocation removes active sessions and codes.
- Guest GET/HEAD requests do not change records or send emails. Pages use no-store, no-index and a restrictive CSP; `Referrer-Policy: same-origin` suppresses cross-origin referrers while permitting native forms to retain their Origin header. The confirmation hostname still rejects private account APIs.
- Status audit, reviewer activity, timer reset and notification enqueue occur within the same D1 transaction via triggers. Conditional updates cannot resurrect deleted records or insert activity for a failed write. Record/account deletion cascades the dependent data.
- A unique event key plus recipient prevents duplicate enqueue. Conditional claims and claim tokens prevent overlapping scheduled runs from sending the same queued event. The dispatcher rechecks current status, progress version, access expiry and revocation before the provider call. An email already in flight cannot be recalled.
- Provider failure or a stale 15-minute delivery claim becomes **Delivery unconfirmed**, with no automatic replay. The owner can explicitly retry, up to three total attempts, with a duplicate-delivery warning. A no-longer-applicable reminder cannot be retried. This provides one automatic attempt per period, not a guarantee of exactly-once inbox delivery.
- Delivery shares existing sender/FYI and recipient budgets; quota delays do not create a second reminder. Up to 50 due events are enqueued and 10 notifications dispatched per tick. Expired verification codes and sessions are cleaned during dispatch. Audit and notification metadata follow record retention and deletion.

## Release and rollback

Migration `0027_assignment_progress.sql` adds six tables, six indices and five triggers. Apply it after existing migrations 0024–0026 and before enabling `ASSIGNMENT_PROGRESS_ENABLED=true`. It is repeatable and does not rewrite or enroll existing invitations. The scoped release records a D1 Time Travel recovery point, applies only 0027, performs SELECT-only schema probes with a nonexistent tenant, deploys the compatible Worker, then checks guest/private HTTP boundaries. It preserves the already-active confirmation hostname and dashboard-managed origin variable. Unrelated CVIE maintenance, DNS changes and customer test emails are excluded.

The feature flag requires all six new tables. Missing schema blocks new workflow-enabled assignment sends and guest writes safely. Disabling `ASSIGNMENT_PROGRESS_ENABLED` pauses reviewer access and dispatch; ordinary account record updates and existing acknowledgements continue. Triggers remain installed and can record/queue owner status changes while paused. On re-enable, only currently eligible reminders dispatch, but queued progress summaries may still send. Do not delete audit tables or rewind customer records for a code rollback. Retain the compatible migration-0026 writer. Existing legacy assignment links keep their original behavior and expiry.

## Validation

The Worker/SQLite suite checks threshold boundaries, overlapping dispatch, one reminder per period, progress reset, terminal states, quotas, delivery uncertainty, revocation, expiry, OTP attempts, CSRF, tenant/invitation isolation, stale writes, deletion cascades, activity pagination and private email contents. Production schema probes are tested as SELECT-only.

The browser test runs the real Worker handlers against synthetic SQLite data and intercepts all network/provider requests. It checks email verification, secure cookies, progress comments, status completion, tracker history, reminder suppression, responsive layouts, sign-out and account clearing. For intercepted 303 responses only, its harness models the redirect using a fresh browser navigation because Playwright cannot intercept a fulfilled redirect continuation; handler tests independently assert the actual 303 response and cookie headers. No customer data, real recipient addresses or real email sends are used. Real inbox delivery and native email-client rendering are outside this validation.
