# Remediation workflow and confirmation hostname

The tracker describes private CVEHarbor storage without exposing infrastructure names. The assignment form uses **Assigned reviewer email** and offers **Assigned severity**: Critical, High, Medium, Low, Informational, or the published advisory rating. External recipients remain supported.

Assigned severity is the requester's assessment, separate from the published severity/CVSS. Each sent assignment stores its own assessment snapshot; the latest successfully sent assignment updates the tracker assessment. Primary and FYI emails and the guest confirmation page identify the assessment separately. Failed primary deliveries do not publish a new assessment. Choosing the published rating clears the override for future assignments without changing historical email snapshots.

Recent Records shows full available timestamps in the viewer's timezone; old date-only values say “time not recorded.” Target dates remain calendar dates. Current acknowledgement timestamps are shown separately. Once a current recipient has acknowledged, the row's ordinary Assign action disappears. Assignment history still supports deliberate resend/revocation; acknowledgement never changes remediation status.

Changing an existing remediation status requires a reason (1–1,000 characters). The server checks this for individual saves and imports. Transactional triggers record the previous/new statuses, trimmed reason, authenticated account email and timestamp. The latest change appears in its own column; paginated history is available to the owning account. Reasons remain separate from general notes and never enter assignment/FYI emails or the public confirmation page. Concurrent edits/deletions fail rather than silently overwriting or recreating a record. Browser-only records retain local history; importing does not claim those entries as authenticated audit evidence.

## Release

Migration `0026_remediation_workflow.sql` adds four tables, an index and four triggers. It does not rewrite existing records or fabricate historical timestamps. Record/account deletion cascades its private metadata/history. The release classifier applies only this migration, records the D1 recovery point, verifies schema using SELECT-only queries against a nonexistent account, then deploys the compatible writer. It skips unrelated CVIE maintenance, scans and secret changes. Existing authentication, recipient limits, delivery queue and schedules remain unchanged.

`REMEDIATION_WORKFLOW_ENABLED=true` requires migration 0026. Missing schema fails writes safely with a customer-facing unavailable message. Migration triggers intentionally reject unaudited status changes: after migration, **do not roll back to a writer that lacks change-context support or disable this flag**. A UI rollback can retain this compatible backend; cached old forms must reload to supply a reason for status changes. If Worker deployment fails after migration, status-changing requests from the old writer fail closed until compatible code is deployed. Do not delete audit tables or rewind customer data for a code rollback.

## Cloudflare setup for confirm.cveharbor.com

Deploy and verify the compatible Worker code before adding the hostname. No static IP or manually chosen A record is used for a Cloudflare Workers Custom Domain.

1. In Cloudflare, open **Workers & Pages → cveharbor-accounts → Settings → Domains & Routes → Add → Custom Domain**.
2. Enter **confirm.cveharbor.com** in the existing cveharbor.com zone and confirm the binding. Cloudflare creates/manages the DNS record and TLS certificate. Keep the existing api.cveharbor.com binding. If a conflicting record already exists, review that record before replacing it.
3. Wait for the hostname/certificate to become active. Check `https://confirm.cveharbor.com/acknowledge/` plus 64 zero characters: it must return the branded invalid-link page with HTTP 404, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, and a restrictive Content-Security-Policy. This synthetic token cannot acknowledge any real assignment. `/v1/me` and `/v1/remediations` on this hostname must return 404 without API CORS headers. Do not use a real customer's bearer token for release checks.
4. Only after those checks pass, add the non-secret Worker variable **ASSIGNMENT_CONFIRM_ORIGIN = https://confirm.cveharbor.com** and deploy that setting. `keep_vars=true` preserves this dashboard-managed variable because it is intentionally absent from wrangler.toml.

New emails then use `https://confirm.cveharbor.com/acknowledge/<token>`. Before activation they continue to use the working API hostname. Old emailed links remain valid until their original expiration or revocation. Both hosts enforce the existing explicit POST, token-bound confirmation proof, expiry/revocation checks and native rate limit. The confirm host rejects every private/account API route before authentication or CORS handling; no login account is required for confirmation. The ordinary application's API remains discoverable in browser network traffic; hostname branding does not replace access controls.

To switch new email links back, set ASSIGNMENT_CONFIRM_ORIGIN to https://api.cveharbor.com (or remove it). Keep the confirmation hostname bound while already-sent links may still be valid. This PR does not change DNS or activate the new origin.

## Validation

`remediation-workflow.test.mjs` uses the real Worker handlers and SQLite to check migration repeatability, status enforcement/audit atomicity, concurrent writes/deletion, account isolation, pagination, severity validation/snapshot persistence, provider failure behavior, guest confirmation across both hostnames and private-route isolation. The release probe is tested as SELECT-only.

`remediation_workflow_browser.mjs` intercepts every network request and provider send. It exercises reason validation, audit history, local timezone timestamps, assigned severity, FYI notification, guest confirmation, action removal, CSV export, account switching and desktop/ultrawide/mobile layouts. Existing assignment, FYI, remediation and general browser regressions remain part of verification. Screenshots contain synthetic records only. Native email-client rendering and real inbox delivery are not certified by these tests.
