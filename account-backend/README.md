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
