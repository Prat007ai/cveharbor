# Activate the production replica at cveharborstage.com

Updated 2026-11-04. **Prepared code; no live configuration or deployment approval.**
This replaces the obsolete checkpoint-29/37/740 application activation instructions.
Do not rerun initialization: run **41923381309** verified the existing database at
production baseline **209**, including all **143 production schema objects**.
The installed staging support tables and receipts remain intact.

## What is established and what still needs verification

| Item | Evidence / action |
|---|---|
| Staging account | `9706b4d98ad72884e67fd1eb875c8a61`; unchanged |
| D1 | `cveharbor-accounts-staging`, `fac61562-fc31-426d-8032-550aba63b7f6`; initialized, do not recreate |
| Workers | Existing `cveharbor-accounts-staging` and `cveharbor-site-staging`; initialization artifact verified both initial profiles, no deployment |
| Production backend | Source `6e05106ce7d5f4c8741261775f2e4e69c6eea719`; version `89380b13-b600-4fef-82f4-69b8cc2f2c17` |
| Production frontend | Source `019efc6ca029f4113ce71c6ebfad3680fa66ba68`; version `e22850fa-851d-453f-8336-5e78d96babdd` |
| Domain ownership, zone and TLS | **Unverified**. No staging Cloudflare administrative credentials are available in the development session; the public RDAP lookup also could not be retrieved. Do not assume registration or DNS exists. |
| Private R2 bucket and secrets | Expected name `cveharbor-intelligence-staging`; existence/privacy and worker keys are verified by the approved release, not assumed from a manifest |
| Access | Maintenance restrictions were established previously. Restoring allow policies or adding hostnames requires explicit administrator approval. |

The production baseline file remains historical evidence of production, including
`RECOVERY_CONTROL_REQUIRED=true` with no 0032 tables. Only the staging wrapper sets
that flag to `false`, using the released backend's existing compatibility path.
Staging readiness checks the full audited schema and foreign keys, not nonexistent
0031/0032 guards. No application migrations are introduced.

The production schema excludes 0023. Its product/lifecycle monitoring API returns
“Monitoring Not Yet Active”; the replica preserves this observed behavior. Existing
lifecycle preferences, digest functionality and other released features remain.
This is a production limitation, not a reason to install an unreleased migration.
The live production flag inconsistency remains unchanged and requires separate review.

## Administrator configuration (once, after approval)

1. **Domain registration and DNS.** Check ownership of `cveharborstage.com` at your
   registrar. If unregistered, approve and register it first. In the existing
   **CVEHarbor Staging** Cloudflare account, use **Websites → Add a domain** and
   add this zone. Update the registrar to the exact Cloudflare nameservers shown
   for this staging zone; wait for **Active**. Do not add it to the production
   account or change any production zone. Registration may have a recurring fee;
   no purchase or paid resource has been authorized by this PR.

2. **Protect both hostnames before connecting the custom domain.** In the staging
   account's **Zero Trust → Access → Applications**, edit the existing
   **CVEHarbor Staging** self-hosted application. Make `cveharborstage.com` its
   primary public hostname and retain
   `cveharbor-site-staging.cveharbor-staging.workers.dev` as an additional public
   hostname. Cover all paths; do not use a path-only restriction. Retain the same
   issuer/AUD if supported by the existing application. Configure exactly the
   existing named policies:
   - **CVEHarbor staging reviewers**: Allow, explicitly listed administrator/tester
     email addresses. No Everyone, domain-wide allow, Bypass or additional allow.
   - **CVEHarbor staging automated tests**: Service Auth, only the existing
     `cvie-staging-validation` service token.
   This restores access only after your separate approval. Application login and
   MFA are still required after Access; a service token grants no customer session.

3. **Connect the existing frontend only after Access is protected.** In
   **Workers & Pages → cveharbor-site-staging → Settings → Domains & Routes → Add
   Custom Domain**, enter `cveharborstage.com`. Cloudflare creates the required DNS
   record and certificate; do not manually point an arbitrary CNAME at workers.dev.
   Wait for domain/certificate activation. The old frontend denies the unfamiliar
   hostname until the approved update; this is expected. Do not add a custom domain
   to the backend. Keep backend workers.dev and previews disabled and frontend
   previews disabled. No `www` alias is configured in this release.

4. **Staging-only resources and secrets.** Reuse the existing private
   `cveharbor-intelligence-staging` R2 bucket if present; otherwise request approval
   before creating this one required bucket. Disable both its r2.dev public URL
   and custom public domains. In the existing backend Worker's **Settings →
   Variables and Secrets**, securely configure separate random secrets named
   `STAGING_TOTP_ENCRYPTION_KEY` and `STAGING_MONITOR_WEBHOOK_TOKEN` if missing.
   Generate/store them through your approved secret manager; never paste values
   into chat, commit them, or copy production values. Do not rotate an existing
   TOTP key after test accounts have enrolled without a deliberate recovery plan.
   Do not install SMTP2GO, production API or production notification secrets.

5. **GitHub → Settings → Environments → cloudflare-cvie-staging.** Retain:

   | Kind | Names / expected values |
   |---|---|
   | Variables | `CF_STAGING_ACCOUNT_ID` and `CF_STAGING_D1_DATABASE_ID` as above |
   | Variables | `CF_STAGING_ACCESS_ISSUER` = existing `https://<team>.cloudflareaccess.com`; `CF_STAGING_ACCESS_AUD` = existing application AUD |
   | Variable | `CF_STAGING_ADMIN_EMAILS` = comma-separated explicit administrators allowed to inspect captured mail and run synthetic jobs; a subset of Access-approved users |
   | Secrets | `CF_STAGING_API_TOKEN`, `CF_STAGING_ACCESS_CLIENT_ID`, `CF_STAGING_ACCESS_CLIENT_SECRET` (existing staging-only credentials) |
   | Secrets | `CF_STAGING_R2_ACCESS_KEY_ID`, `CF_STAGING_R2_SECRET_ACCESS_KEY`, restricted to Object Read & Write on the private staging intelligence bucket only |
   | Activation flags | Keep `SIMPLE_STAGING_ENABLED=true`. Leave new `STAGING_APPLICATION_ENABLED` unset/false until the application deployment is explicitly approved. |
   | Controlled jobs | `CF_STAGING_MANUAL_JOBS_ENABLED=false` initially; set true only after approving captured-email/synthetic scheduler tests. Native Worker schedules remain disabled regardless. |

   The existing management token needs staging-account Worker deployment, account
   metadata, Access read, D1 read and private R2 metadata access. It must have no
   production account scope. If Worker custom-domain publishing needs zone route
   permissions, authorize only the `cveharborstage.com` zone; do not broaden the
   token automatically. Check token metadata using the existing preflight.

   Restrict the environment to protected `main`. Require reviewed PRs and successful
   **CI / application regression**, **Security / workflow policy** and staging
   **prepare** checks before merging; block direct/force pushes. The current read-only GitHub metadata reports `main` as **unprotected**;
   these protections must be configured before automatic staging is enabled. Verify
   your GitHub plan enforces them. Production environments retain their
   approval requirements. Staging can omit repeated environment-reviewer approvals
   once you explicitly authorize automatic staging releases; changing this setting
   itself requires your approval. No settings were changed by this PR.

## Approved activation sequence

Use the existing **Permanent staging preparation and approved updates** workflow.
Do not run legacy migration, adoption, recovery-capture or checkpoint-740 actions.

1. Review the draft and passing CI. Approve/complete the one-time domain, Access,
   bucket, secret and environment configuration above. Keep all test data synthetic.
2. After deployment authorization, set `STAGING_APPLICATION_ENABLED=true` once.
   On `main`, dispatch `simple_operation=publish-synthetic`, legacy `operation=none`.
   This uses the existing versioned R2 publisher, preserves synthetic history and
   does not deploy Workers or write D1 records.
3. Dispatch `simple_operation=release`, legacy `operation=none`. The existing job
   validates the exact production schema/receipts, Access policies, current Worker
   identities, private bucket and already-connected custom domain. It builds the
   pinned sources, dry-runs both packages, updates the **existing backend**, checks
   its bindings/version and actual readiness through the old authenticated frontend,
   and only then publishes the frontend. It rechecks custom-domain readiness, schema
   and Access boundaries. A failed backend check stops frontend publication.
4. Sign in at **https://cveharborstage.com/workspace/** with a synthetic test email.
   An allowlisted administrator can read the captured OTP at **/__staging/**; enroll
   a new authenticator seed and save the *staging* recovery codes. No real email is
   sent. Session and reviewer cookies remain Secure/HttpOnly and host-only.
5. Complete the remote acceptance checklist below. This cannot be claimed complete
   from local tests or schema initialization alone.

The authenticated `/v1/staging-readiness` exception is the only route retained on
the old frontend origin after deployment. All other workers.dev application paths
return 403 even with a valid Access token. The exception still requires a valid
Access JWT. The private backend has no public workers.dev endpoint. Every custom
host route runs the Access-verifying Worker before assets/API forwarding.

## Acceptance and recovery

Local tests exercise actual released handlers against the production-only schema:
OTP registration, mandatory TOTP, replay protection and sessions; customer isolation;
inventory/workspace; assignment email, acknowledgement, reviewer verification and
progress; linked findings/status notifications; ticket/history preservation;
report attachments/exports; digest and existing lifecycle capture; synthetic provider
responses; controlled reminder idempotency; denied public/provider access. A real
Chromium test additionally signs in through the pinned UI and visits workspace,
account, inventory, customer security, remediation, reports and captured mail.

After deployment, repeat these with two distinct synthetic customers/users. Verify
invalid/missing Access JWTs and unauthorized testers cannot obtain HTML, JavaScript,
feeds, APIs, reviewer pages or mail. Test MFA login/logout/recovery, assignment →
acknowledgement → reviewer progress → finding status/history, cross-customer denial,
CSV/PDF/report email, and captured reminder/digest jobs with authorized admin access.
Confirm frontend/backend feed versions agree and public bucket access is disabled.
Production credentials or real customer data must never be imported.

R2 uses synthetic timestamps and the existing eight-hour digest freshness guard.
Do not extend/disable it. Refresh synthetic data with the existing `publish-synthetic`
operation when needed before testing notifications; no recovery-secret updates are
needed. Native scheduled jobs do not run automatically in staging.

A code-only failure does not require a D1 restore. Keep Access private and retain
artifacts/previous Worker version IDs. If the backend fails verification, leave the
frontend unchanged. If an uploaded version needs rollback, separately approve
rollback of the existing Worker to its previously recorded compatible version or
review a forward fix; do not delete resources or run schema initialization. Current
activation never writes application schema/data. The optional historical private
R2 recovery mechanism is not used by this release and is not adapted to this domain.
Destructive/schema-changing work continues to require its own reviewed safeguards.

## Routine development after acceptance

`staging/application-release.json` initially selects `production-baseline` so the
first activation reproduces the verified production release, not the newer candidate.
After acceptance, make one reviewed change to `source_mode: reviewed-main`. The
same build, safety wrappers, schema checks, CI and deployment job then use the exact
reviewed main commit for both application sources. Each subsequent reviewed merge
stages code automatically with no per-release variables, backup evidence or recovery
secrets. Schema drift is blocked; schema-changing features require a reviewed schema
profile/migration rather than silently continuing to 740. Production promotion
still requires its protected approval and matching staging identity evidence; an
initial pinned-baseline receipt cannot certify unrelated newer production code.
