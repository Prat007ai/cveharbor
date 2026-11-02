# Vulnerability assignment email and acknowledgement

The existing authenticated remediation assignment workflow now sends the professional navy/teal email and an expiring guest acknowledgement link. Acknowledgement confirms receipt through an emailed bearer link. It is not identity verification, a read receipt, proof of exposure, investigation, or remediation. It never changes the saved remediation status.

## Routes and authorization

- Existing `POST /v1/remediations/{cve}/assign` keeps MFA-backed account authorization, verified requester identity, existing external-recipient policy and SMTP2GO sender/key selection. Optional `resend: true` explicitly sends a replacement link. Normal repeated sends to the same recipient within 24 hours are suppressed when a live request already exists.
- `GET /v1/remediations/{cve}/assignments?before={sequence}` returns at most 50 account-scoped history entries and a next cursor. It never returns token hashes or raw tokens.
- `POST /v1/remediations/{cve}/assignments/{id}/revoke` revokes a link within the authenticated account. Audit history is retained.
- `GET /v1/acknowledge/{token}` and HEAD are public on **api.cveharbor.com**, independent of the site's temporary password gate. They perform no D1 writes. They show only a public advisory snapshot and a masked recipient.
- `POST /v1/acknowledge/{token}` requires the same HTTPS origin, form encoding, bounded body and explicit `confirm=receipt`. An atomic conditional update records receipt once. Already-acknowledged links show the same success timestamp; expired unacknowledged, revoked, rotated and failed-delivery links cannot acknowledge.

The guest route grants no general access to the user's account or customer records. The token is 32 cryptographically random bytes, stored only as SHA-256. Tokens appear only in emailed links and recipient browser URLs; never in application logs or authenticated history responses. Guest pages contain no third-party resources, scripts, analytics or redirects, and use no-store, no-referrer, noindex, frame protection and a restrictive CSP. Cloudflare's native rate limiter uses a hash of the connecting IP, never the token, and does not write to customer D1 on GET. A missing rate binding fails closed.

## Data and migration

`account-backend/migrations/0024_assignment_acknowledgements.sql` adds `remediation_assignment_requests`, `remediation_assignment_events`, scoped indexes and transactional audit triggers. It is repeatable and does not backfill or modify existing remediation/customer records. Legacy assignment rows remain readable; they display “Not requested” because old emails contain no acknowledgement link.

Each issuance has its own request ID, recipient, requester, hash, timestamps and delivery state. Latest-per-recipient statistics prevent prior retries from inflating current acknowledgement totals. Resending invalidates earlier links for that recipient after the new email is accepted; other recipients stay independent. An explicit revoke handles reassignment/removal of a recipient. Prior events remain until the parent remediation/account is deleted, at which point foreign-key cascades clean up requests and their events under the existing deletion policy. There is no background cleanup job.

Only provider acceptance creates Pending. Provider rejection creates Delivery failed; neither implies inbox delivery. Requester notes are escaped into the email only, not persisted into the public snapshot. Advisory fields come from the existing CVE Program lookup. Missing data stays unavailable, and unknown reference domains are omitted. From/provider settings are unchanged; no new Reply-To or identity is invented. Azure DevOps work remains the recipient's responsibility.

## Configuration and deployment

- `ASSIGNMENT_ACK_ENABLED=true` activates new email issuance. Keeping it false retains the legacy assignment flow for staged rollback. Previously issued guest links remain usable while their underlying code/schema/rate binding remain installed.
- `ASSIGNMENT_ACK_TTL_SECONDS=604800` defaults to seven days; values are bounded to five minutes–30 days.
- `ASSIGNMENT_ACK_RATE_LIMITER` is the native Worker rate binding (namespace 23501), 60 requests per minute per IP/location according to Cloudflare's rate-limit semantics. Existing durable sender 10/hour and recipient 20/day email quotas remain in force.
- Migration 0024 must precede Worker activation. The production workflow records a D1 Time Travel recovery bookmark, applies **only 0024**, verifies the schema with SELECT-only probes, deploys, then checks the guest route's headers and private endpoints' authentication boundary. Unrelated CVIE maintenance is skipped.
- No independent database export is created. D1 Time Travel is the recovery mechanism for the additive migration; the bookmark is recorded in release logs. For rollback, redeploy the prior Worker and frontend; retain additive tables/history. Do not drop tables or rewind customer records as routine code rollback.
- The existing frontend deployment packages the tracker changes and verifies the live versioned assets. No new paid service or scheduled task is introduced.

## Validation

`account-backend/tests/assignment-acknowledgement.test.mjs` uses SQLite and the actual Worker routes. It covers migration replay, account isolation, token hashing, GET/HEAD read-only behavior, explicit POST, concurrent confirmations, exact audit counts, independent recipients, rotation, expiry, revocation, deletion, provider failures, limits, CSRF, XSS/unsafe URLs, pagination and sensitive-data exclusion.

`scripts/assignment_ack_browser.mjs` runs the real Worker handlers behind intercepted browser requests and renders desktop/mobile email, confirmation, success, revoked/expired and tracker/history screenshots. All provider messages and account records in these tests are synthetic and never published into the application build. Existing application suites run alongside these checks.

Email compatibility uses presentation tables, inline CSS, web-safe fonts, a 620px MSO wrapper, responsive widths and plain text. Browser previews and structural tests cover these properties. Native Gmail, Outlook desktop/web and screen-reader sessions are not available in this environment; do not describe browser previews as native email-client certification. No real recipient is emailed by automated deployment checks.
