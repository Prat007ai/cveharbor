# CVEHarbor Accounts — deployment guide

The public dashboard remains on GitHub Pages. **Account sign-in and synchronization do not work until this separate API is deployed.** The account screen displays a setup notice until then.

Architecture:
- Cloudflare Worker at `https://api.cveharbor.com`.
- Cloudflare D1 database storing users, session hashes, local-to-cloud technology profiles, remediation entries and saved preferences.
- SMTP2GO verification emails from a verified sender address.
- HTTPS-only HttpOnly SameSite=Strict session cookies, per-user SQL filtering, 10-minute one-time codes, login throttling.
- The user explicitly uploads or downloads data. There is no silent replacement of local records.

## Provisioning

1. Confirm `cveharbor.com` is managed by Cloudflare DNS and that Workers routes can be assigned for `api.cveharbor.com`. GitHub Pages may continue to host the static website.
2. Install Wrangler with Node and authenticate using `npx wrangler login` in a trusted administrative environment.
3. From `account-backend/` run `npx wrangler d1 create cveharbor-accounts`. Set `DB`, the database name and the returned database ID in `wrangler.toml`.
4. Run `npx wrangler d1 execute cveharbor-accounts --remote --file=./schema.sql` to create tables. Back up the database before future schema migrations.
5. Configure the Worker secret using `npx wrangler secret put SMTP2GO_API_KEY`. Restrict this key to the send endpoint and consider enforcing an SMTP2GO daily quota.
6. Set `EMAIL_FROM` to a verified sender address using `npx wrangler secret put EMAIL_FROM` (or a protected configuration variable). Never commit the key or a user's sign-in code.
7. Deploy with `npx wrangler deploy` and set up the custom hostname `api.cveharbor.com` through Cloudflare Workers custom domains.
8. Verify `GET https://api.cveharbor.com/v1/health` shows `ready:true`. Confirm email delivery and sign-in, test an upload from one device and download on another, then verify account deletion.
9. Review Cloudflare request protections, rate limits, billing, D1 backup/restore and privacy/retention policy before inviting the public.

## Authentication and synchronization contract

- `POST /v1/auth/request`: requests email OTP, with one-hour IP and email limits.
- `POST /v1/auth/verify`: verifies the OTP and sets a 7-day session cookie.
- `GET /v1/me`, `POST /v1/auth/logout`: account status and logout.
- `GET|PUT /v1/stack`: saved technology profile. PUT replaces the full user's stack.
- `GET|PUT /v1/remediations`: remediation records. PUT replaces the full user's dataset.
- `GET|PUT /v1/alerts`: preferences only. **No alert sending service is active.**
- `DELETE /v1/account`: removes user and related data (cascading foreign keys).

The browser can continue using My Technology Stack and Remediation Tracker without an account. Cloud actions require explicit confirmation, and replacement is **not** merge or conflict resolution. Each user should export local remediation records before a cloud download.

## Security hardening required before broad public signup

- Perform external security and abuse testing of OTP code issuance, login throttling and rate-limit enforcement; add edge-level Cloudflare WAF rate limiting.
- Add audit/event logging that excludes OTPs, tokens, credentials and sensitive remediation notes.
- Review passwordless email security, account recovery, consent, CAN-SPAM/CASL and privacy requirements.
- Implement scheduled deletion of expired challenges and sessions.
- Add verified version inventory schemas, tenant isolation and concurrency controls before offering multi-user organizations.
- Implement a separate opt-in alert delivery service with consent tracking, source deduplication, unsubscribe flows, bounces, throttling and observability **before** enabling email notifications.
- Set monitoring and alerts for API health, elevated error rates, email send failures and D1 capacity.


## Personalized vulnerability digest (October 2026)

The account API now contains a branded, responsive HTML and text email report. It includes matching critical/high advisories with CVE IDs, reported affected products, dates, CVSS when supplied, CISA KEV indicators, remediation review and links to original advisories. Email content is escaped. The first digest uses the last 30 days of indexed publications, updates and initial collection dates, then each subscriber receives only matching advisories that have not already been emailed at the same source revision. Each email contains at most 30 items; remaining recent matches continue in later digests. No email is sent if there are no unreported matching items. This is a bounded index and does not prove asset exposure or exhaustive coverage.

### Existing database migration: one time

Before deploying the new account UI for subscribers, go to Cloudflare → Storage & databases → D1 SQLite Database → cveharbor-accounts → Console. Back up the existing database and execute the statements in [alert-schema.sql](./alert-schema.sql). They create three new tables without removing the seven existing tables:

* alert_optins stores explicit email consent and an unsubscribe-only token.
* alert_delivery_items tracks delivered source advisory revisions to suppress repeat findings.
* alert_digest_runs stores daily/hourly processing outcomes and provider message IDs.

Do not re-run the original schema unnecessarily. The migration uses CREATE TABLE IF NOT EXISTS, and it is safe to retry. Confirm all three tables exist before enabling scheduled delivery.

### Subscriber setup

An account may save technology selections without receiving email. A signed-in user must explicitly check **Email me advisories matching my saved technology stack** and choose **Save preferences** after migration. A previously saved "future email notification" preference does not opt the user in automatically. User selections must be uploaded from their browser to the account. Disabling the checkbox or clicking the email unsubscribe link prevents subsequent digests. Unsubscribe is protected by a random token that only allows disabling email, never account access or profile changes.

### Activation, testing and limits

1. Ensure the Worker has the encrypted SMTP2GO_API_KEY secret and a verified EMAIL_FROM sender.
2. Deploy the Worker from account-backend. It schedules a cron event at five minutes past each hour, but does not send automatically unless ALERT_DELIVERY_ENABLED is explicitly set to the string value true as a **runtime variable**.
3. Until activation, use **Send me a sample vulnerability report** on the My Account page after uploading the selected technology stack. It sends an email only to the authenticated account owner and is limited to two requests per rolling hour. The sample is marked TEST and does not count as a delivered advisory.
4. When you are satisfied with the sample and have completed a privacy, consent and SMTP2GO sending quota review, set the Worker **runtime** variable ALERT_DELIVERY_ENABLED=true in Cloudflare production Settings → Variables and Secrets. Deploy the variable change.
5. Verify a new subscription from My Account, check Cron Events/Worker Logs and SMTP2GO Activity. Set reasonable daily quotas and rate limits. For public use, ensure a valid organization identity, contact details, consent evidence, privacy policy and unsubscribe process. Consider Canadian CASL obligations if the content qualifies as commercial electronic messages.

The cron uses UTC scheduling and determines the local time using America/Toronto. Daily subscribers are eligible from 08:00 Toronto time, and hourly subscribers from the next scheduled hourly tick. The Worker caps scheduled sends to eight subscribers per invocation. Additional subscribers can be picked up on later ticks. Send failures are recorded as retryable without logging email addresses or tokens. Cloudflare and feed availability affect timing, so delivery is best effort rather than a guaranteed exact minute.

### Operations notes

* A separate ALERT_SMTP2GO_API_KEY secret may be configured to isolate report traffic. Otherwise the existing SMTP2GO_API_KEY is used.
* Keep ALERT_DELIVERY_ENABLED disabled until the database migration and sample test are complete. Workers deployed from GitHub may overwrite dashboard variables unless keep_vars=true is configured.
* Only the verified domain https://cveharbor.com is permitted to call authenticated API endpoints from a browser.
* A scheduled report depends on publicly published data.js and feed-health.json and will refuse to send if the feed is older than eight hours. It will disclose partial feed coverage if source health is degraded or the index is capacity limited.
* Reports may cover old vulnerabilities whose upstream records were recently updated. Publication dates remain those supplied by the original sources. A matched category does not prove an installed version is vulnerable.
* A sample report is available immediately without scheduled delivery. No other account is emailed just because this code was deployed.
* Review contact information and unsubscribe requirements before inviting public subscribers; do not send promotional material through this security digest without an appropriate compliance review.
