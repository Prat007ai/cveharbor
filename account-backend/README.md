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
- `GET|PUT /v1/remediations`: authenticated remediation records. Legacy PUT safely merges entries by CVE ID without deleting other cloud records or assignments. Individual PUT and DELETE operations manage one CVE.
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


## Unified My Technology Watchlist and Email Alerts

The website now displays the technology checkbox list alongside account sign in and alert preferences in one security workspace. Technology selections are still stored locally first. Only the technology list saved in D1 is used by personalized email reports.

When a user signs in, the page compares this browser's list with the cloud account watchlist. If they are identical, future technology checkbox changes save automatically to D1. If the lists differ, the user must choose **Use these selections for email reports** or **Load my saved selections** before automatic synchronization starts. This prevents an empty new browser from silently erasing an existing cloud watchlist. A clear selection requires confirmation.

A subscription is separate from saving technologies. Users must choose a severity, delivery frequency and explicit email consent. The sample email action checks that the current browser list has been saved before generating a report. Scheduled report delivery continues to use the independent ALERT_DELIVERY_ENABLED setting.

## D1 remediation tracker and emailed Azure DevOps assignments (October 2026)

CVEHarbor already has a `remediations` D1 table. Do not recreate the database or rerun the original schema. This release adds private per-CVE updates and assignment notifications. It does not access Azure DevOps or create work items automatically. The recipient creates and manages work items inside their own organization's Azure DevOps project.

### Required existing-database migration and activation

1. Back up the existing Cloudflare D1 `cveharbor-accounts` database.
2. From `account-backend`, run `npx wrangler d1 execute cveharbor-accounts --remote --file=./remediation-schema.sql`, or apply the file in the D1 console. The migration adds an assignment history table, its index, and a separate rate limit table. Authentication rate limit cleanup cannot reset assignment limits. Existing account records stay in place.
3. Deploy the Worker using `npx wrangler deploy`. No new database is created.
4. After signing in, check `GET /v1/remediations/features`. It should report `storage: d1`, `version: 2`, and `assignments_available: true`. If migration is missing, records work but assignment emails are unavailable.
5. Add Worker runtime variable `ASSIGNMENT_ALLOWED_DOMAINS` containing comma-separated trusted organization email domains (e.g. `example.org,example.net`). The sender and recipient domains must both be on the list. Set `ASSIGNMENT_EMAIL_ENABLED=true` only after reviewing your SMTP2GO limits, privacy and abuse controls. Until then, leave it unset or false. Existing `EMAIL_FROM` and `SMTP2GO_API_KEY` can be reused. Optional `ASSIGNMENT_SMTP2GO_API_KEY` can isolate assignment traffic. Never commit credentials.
6. Test with a verified CVEHarbor account and approved recipient, review SMTP2GO Activity and confirm that a work item was manually opened in the correct Azure DevOps Boards project. SMTP2GO acceptance is not proof of final delivery.

### Security and behaviour

The assignment API requires sign in and an approved sender and recipient email domain. An explicit user confirmation is required before dispatch. Five assignments per sender per rolling hour and two messages per recipient per rolling day are allowed. Repeat assignment of the same CVE to the same recipient is suppressed for 24 hours. The fixed message avoids customer names, private notes, server details, untrusted links and claims of confirmed exposure. The assignee cannot read or modify the requester's D1 account records simply by receiving an email. No scheduled digest starts these notifications.

Once the updated Worker is deployed, remediation records are saved directly in D1, keyed to the signed-in user. Browser records remain intact and may be explicitly imported through the tracker; imports upsert by CVE without deleting unrelated cloud records or assignment history. Before Worker deployment the browser tracker continues in clearly labelled legacy local mode, so no existing records silently disappear. The user may export CSV at any time. The watchlist's advanced cloud buttons now manage the technology watchlist only.

### API

* `GET /v1/remediations/features` reports authenticated D1 and email capability.
* `GET /v1/remediations` returns only the authenticated user's entries and assignment state.
* `PUT` or `DELETE /v1/remediations/CVE-YYYY-NNNN` manages one CVE.
* `PUT /v1/remediations` merges imported browser records, never deleting other entries.
* `POST /v1/remediations/CVE-YYYY-NNNN/assign` with an email address stores the assignment and, when enabled, sends the standard Azure DevOps triage request.

The existing watchlist, vulnerability digests, malware popups and public security feed remain unchanged.

## My Environments and customer inventory

The public page includes a signed-in, private inventory with customer names, multiple environments per customer and installed asset technology versions. Each row belongs to the authenticated CVEHarbor user. Customer records are not visible to other accounts or public website visitors. This does not yet include shared organization accounts or automatic inventory scanning.

Production migration: back up the existing D1 database first and apply `account-backend/inventory-schema.sql` to the existing `cveharbor-accounts` database. Do not recreate the database. The three additive tables are `inventory_customers`, `inventory_environments` and `inventory_assets`. Deploy the updated Worker after applying the migration. The website will display a migration-required status until the Worker can access the tables.

The authenticated API provides `GET /v1/inventory/status`, `GET /v1/inventory`, `POST /v1/inventory/customers`, `POST /v1/inventory/environments`, `POST /v1/inventory/assets`, per-resource DELETE, and individual asset PUT updates. Each environment must reference a customer owned by the user, and each asset must reference an environment owned by the user. The limits are 100 customers, 500 environments and 3,000 asset entries per account. Deleting a customer permanently deletes its environments and assets.

The fields are customer name, environment name and type, asset name and type, technology, installed version and optional non-sensitive notes. This is a manually maintained inventory, not a verification of affected versions. The next phase can provide advisory matching after verified version range coverage is available. Do not put customer secrets, credentials, access tokens or private IP addresses into the inventory.

## Multiple installed technologies per customer asset

The My Environments page supports multiple technology versions for the same named asset. Enter the first technology and version in the existing fields, then provide additional lines formatted as Technology | Version. The browser creates an individual existing D1 inventory asset row for each technology while retaining the same environment, asset name and type. The page visually groups rows by that asset name and type, and vulnerability matching evaluates every technology row separately. Edit and Remove operate on individual technology entries. No destructive schema migration or new database tables are required for this extension. Do not use the same asset name for physically different assets within one environment, because the UI groups by name and type.

## End of Support and Patch Availability Watch

The website publishes a source-limited lifecycle calendar and allows signed-in users to save product watches in their existing private Cloudflare D1 account. The collector uses endoflife.date product feeds, with links to the original page and a timestamp. Covered choices include Windows Server, Windows client, Microsoft SQL Server, SharePoint, .NET, Microsoft server tools, Sitefinity when sourced, WordPress, PHP and several Linux distributions. Products unavailable in the source are shown as unavailable rather than assigned fabricated dates. Users can add another product by entering their own verified end of support date and source.

### Database migration

Back up the current D1 database before applying `account-backend/lifecycle-schema.sql` to the existing `cveharbor-accounts` D1 database. The schema creates `lifecycle_watches`, `lifecycle_preferences`, and `lifecycle_delivery`, all scoped to the authenticated CVEHarbor user. Existing user, watchlist, customer and remediation records are not replaced. The manual, approval-gated `.github/workflows/deploy-account-worker.yml` includes the additive migration. Do not deploy this Worker as part of public GitHub Pages publication.

### Emails and consent

Lifecycle notifications are off by default in D1. The user must explicitly check the lifecycle email opt-in box and save. Even then, no lifecycle emails send until the Cloudflare Worker runtime variable `LIFECYCLE_DELIVERY_ENABLED` is set to `true` by the administrator. Leave it unset during initial migration and testing. It does not turn on the independently gated vulnerability digest or remediation assignment sender. The scheduled handler evaluates lifecycle watches each hour, with up to 8 successful outgoing messages per invocation. Emails are deduplicated by watch, release/date event, and actual SMTP2GO provider acceptance. A newer release notice indicates release availability, not a verified security fix or installed asset exposure. Only confirmed vendor bulletins should be described as security patches.

### Scope and limitations

Use `GET /v1/lifecycle/status` to check if the new D1 tables are present (authenticated). `GET /v1/lifecycle`, `POST /v1/lifecycle/watches`, `DELETE /v1/lifecycle/watches/{id}`, and `PUT /v1/lifecycle/preferences` manage watches and settings in the current account. A watch contains product, tracked source slug and exact cycle, optional installed build, and optional user-supplied support date and source URL. There is no automatic installation scan, license/extended support detection, automatic patch installation, or vendor patch bulletin verification. Source dates can differ by edition, release channel and paid extended security support.

## On-site lifecycle details and full product search

The public lifecycle section loads a complete product-slug directory from the endoflife.date `api/all.json` endpoint during the scheduled collection. Searches include products outside the predefined CVEHarbor lifecycle collection. Search results open a CVEHarbor-owned dialog showing the product's release cycles, published end of support/end of life dates, latest versions and other supplied metadata. Selecting a result requests the public `https://endoflife.date/api/{slug}.json` endpoint directly from the user's browser. This request contains no CVEHarbor account cookie or private customer information. If the provider API is unreachable or cross-origin access is not permitted, the dialog falls back to CVEHarbor's saved snapshot for the monitored products; otherwise it explains that details are unavailable and offers the original source link. All source information is presented as unverified for specific license agreements and extended support, and no date is invented. The source link appears at the end of the on-site dialog.

## Multiple product watchlist and release notes

The Lifecycle page now lets visitors build a multi-product selection list, with optional installed builds and customer-supplied products that have a verified end-of-support date and HTTPS source reference. Up to 30 products can be saved together using the authenticated `POST /v1/lifecycle/watches/bulk` endpoint, with a maximum of 100 products per account. Existing single-product saves and deletions still work.

The account's 90-day end-of-support notification preference remains the default, and users can choose 30, 60, or 180 days. The scheduled Cloudflare Worker checks lifecycle watches and deduplicates notices per watch and end-of-support date. **No email sends without explicit user opt-in, the existing D1 migration, deployed Worker, and `LIFECYCLE_DELIVERY_ENABLED=true`.** That setting is not changed by this public website release.

The site collector also reads public release metadata from maintained upstream GitHub releases and attempts to verify SQL Server CU and GDR builds against Microsoft's official servicing history. It fetches the corresponding Microsoft KB summary when available. CVEHarbor only includes verified publisher summaries and links, rather than inventing fixes or treating every release as a security patch. Missing upstream data means limited coverage, not an assurance that no patch exists. Patch details are deliberately incomplete for products without a verified, machine-readable source. The release feed `patch-notes.js` is public, contains no customer data, and is refreshed by the existing GitHub Actions collection process. Notification matching remains account-private in the Cloudflare Worker.
