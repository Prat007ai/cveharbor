# Task 2C: Staging preparation and secure credential setup

**Current workflow instructions:** see [protected provisioning and first database creation](cvie-staging-provisioning.md). The execution job is now prepared; the initial push skips it and actual execution awaits separate approval. The setup/sequence below retains the earlier preparation context.

**Preparation only. No Cloudflare resources have been created or deployed by this work.** Keep [PR #243](https://github.com/Prat007ai/cveharbor/pull/243) open and unmerged. Credentials and Access are ready; execution remains subject to approval of the bounded [resource creation plan](cvie-staging-resource-creation-plan.md). Migrations and validation follow separately.

**Read-only preflight update:** credentials are configured and remote checks have run. The rerun after adding Access: Service Tokens Read verifies account identity, both Access policies and service-token linkage. Management-token write-grant/scope metadata returned 403; the owner has now personally confirmed all five permissions and exclusive staging-account scope. This is recorded separately as manual verification, resolving the pre-creation evidence gap. See the [updated preflight results](cvie-staging-preflight.md). No resources have been created or deployed.

This supplements the [full Task 2C plan](cvie-staging-plan.md). The account, hostname and names below are approved. Cloudflare Access replaces the earlier proposed Basic Auth gate. Initial source-provider mode is **blocked**, not live or fixture-driven; controlled source fixtures and the remote performance campaign remain subsequent work.

## Approved targets

| Setting | Exact value |
|---|---|
| Cloudflare account | `9706b4d98ad72884e67fd1eb875c8a61` — CVEHarbor Staging, Workers Paid |
| Workers subdomain | `cveharbor-staging.workers.dev` |
| API Worker | `cveharbor-accounts-staging` |
| Frontend Worker | `cveharbor-site-staging` |
| D1 database | `cveharbor-accounts-staging` |
| Website | `https://cveharbor-site-staging.cveharbor-staging.workers.dev` |
| API | Same website origin, `/v1/*`, forwarded through a service binding |
| GitHub environment | `cloudflare-cvie-staging` |

The API has no public workers.dev address, preview URL, route or Cron Trigger. Its only D1 binding is `DB` to the new staging database. The frontend has no D1 binding and forwards only to the staging API. No production account is selectable in the scripts.

## 1. Create the staging deployment API token securely

Perform these steps yourself while the Cloudflare dashboard is switched to **CVEHarbor Staging**. Do not paste the token into chat, issues, PR descriptions, files or shell command arguments.

1. Open **Manage Account → Account API Tokens** in the dedicated staging account. Prefer an account-owned token, which is independent of a user's other account memberships. This requires the account's Super Administrator role. If the dashboard only offers user tokens, use **My Profile → API Tokens → Create Custom Token**, and explicitly restrict its resources to this staging account only.
2. Name it `cveharbor-staging-pr243-deploy`.
3. Grant these account permissions:

   | Permission | Purpose |
   |---|---|
   | **Workers Scripts: Edit** (also labeled Write in some API documentation) | Create/update the two staging Workers, versions and bindings |
   | **D1: Edit** | Create the staging database and later apply approved staging schema/fixtures |
   | **Account Settings: Read** | Account/subdomain discovery used by deployment tooling |
   | **Access: Apps and Policies: Read** | Verify the exact staging Access app and policies before any mutation |
   | **Access: Service Tokens: Read** | Verify the existing automation token and its policy linkage |

   Optional later: **Workers Tail: Read** for runtime diagnostics and **Account Analytics: Read** for aggregate usage. They are not required for the initial local build. No Access Edit, DNS Edit, Workers Routes, KV, R2, production account or account-administrator permissions are needed by the deployment token.

4. Under account resources select **Include → Specific account → CVEHarbor Staging**, ID `9706b4d98ad72884e67fd1eb875c8a61`. Do not select all accounts. Review this again on the confirmation screen. For an account-owned token, verify it belongs to that exact account.
5. Use a short expiration appropriate for the staging campaign, for example 30 days, and rotate if the campaign continues. Do not apply a fixed IP restriction unless the intended runner has a known static egress address.
6. Create the token and place the one-time value directly into the GitHub environment secret described below, or into your password manager until that environment is ready. Do not use a Global API Key or copy an existing production token.

Cloudflare's current permission reference describes [D1 Edit and Workers permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/); [account-owned API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/account-owned-tokens/) are preferable for this isolated account. If the UI shows a different permission model, choose the narrow equivalent or pause to review it—do not broaden to production resources to make a command pass.

## 2. Configure Cloudflare Access for the exact staging hostname

Workers Paid and Zero Trust configuration are separate. In the **staging account**, open Cloudflare Zero Trust and establish a staging team if one does not exist. A Zero Trust team name is **not necessarily** the Workers subdomain. Record the actual team domain, for example `your-staging-team.cloudflareaccess.com`.

1. In Zero Trust, go to **Access → Applications → Add an application → Self-hosted**.
2. Name the app `CVEHarbor Staging`.
3. Protect the whole public hostname `cveharbor-site-staging.cveharbor-staging.workers.dev`, with **no path restriction**. This must include `/`, static assets, `/v1/*`, account pages and all future staging test paths. Do not select `cveharbor.com`, `api.cveharbor.com`, the production account or a wildcard covering other Workers.
4. Add an **Allow** policy named `CVEHarbor staging reviewers`, listing your exact email identity and any explicitly approved testers. Use your identity provider with MFA where available. Do not use **Everyone**, **Bypass**, a public email-domain-wide rule or a path exception. Choose a short application session, for example one hour.
5. Copy the application's **Application Audience (AUD) tag** into the GitHub environment variable below. Set the issuer to the exact `https://<actual-staging-team>.cloudflareaccess.com` URL, without a trailing slash.
6. Do not expose the API Worker through a separate public route. The frontend validates the Access JWT's RSA signature, issuer, audience and expiry before serving anything or invoking the service binding. Missing or invalid configuration returns 403, including before Access setup is complete.

Cloudflare documents hostname-based protection for workers.dev in [Cloudflare Access for Workers](https://developers.cloudflare.com/workers/configuration/cloudflare-access/). If your dashboard will not let you register the hostname before the Worker exists, save the policy/team details, then tell us this is the remaining dependency. After the next approved creation step, use **Workers & Pages → cveharbor-site-staging → Settings → Domains & Routes → workers.dev → Enable Cloudflare Access**, then set the app's policies/AUD. Do not disable the in-Worker JWT check to work around setup. The current cloud preflight intentionally refuses creation/deployment until the matching Access app is visible; a bootstrap adjustment would be reviewed if required.

For later automated browser testing, create a **separate Access service token** named `cvie-staging-validation`, with a short expiry. Add a **Service Auth** policy selecting only that token for this same app. Save its client ID and client secret as separate GitHub environment secrets. An Access service token is not the Cloudflare management API token and does not authenticate a CVEHarbor account: tests still require valid synthetic application sessions.

Access authentication is an outer protection layer. No CVEHarbor SMTP keys are installed, and its login emails remain unavailable. Prefer an existing MFA identity provider for Access if you also want to avoid Cloudflare's own email one-time-code login; that is separate from application notification delivery.

## 3. Create the protected GitHub environment

In `Prat007ai/cveharbor`, open **Settings → Environments → New environment**, name it exactly `cloudflare-cvie-staging`.

1. Add yourself or an approved reviewer as a required reviewer. Prevent self-review when there is another authorized reviewer available; avoid creating a workflow approval deadlock for a sole repository owner. Do not bypass whatever protection is configured.
2. Under deployment branches/tags, allow only the branch `codex/cvie-core-phase012`; do not allow arbitrary branches or tags with a similar name.
3. Add the following **environment variables** (not repository-wide production variables):

   | Variable | Value now |
   |---|---|
   | `CF_STAGING_ACCOUNT_ID` | `9706b4d98ad72884e67fd1eb875c8a61` |
   | `CF_STAGING_ACCESS_ISSUER` | Actual staging team issuer from step 2 |
   | `CF_STAGING_ACCESS_AUD` | Staging app's 64-character AUD tag |
   | `CF_STAGING_D1_DATABASE_ID` | **Leave unset until creation returns the new UUID. Never copy the production UUID.** |

4. Add these **environment secrets**:

   | Secret | Required when | Source |
   |---|---|---|
   | `CF_STAGING_API_TOKEN` | Read-only readiness check and subsequent approved provisioning | Token from step 1 |
   | `CF_STAGING_ACCESS_CLIENT_ID` | Automated browser/API validation | New staging Access service token's client ID |
   | `CF_STAGING_ACCESS_CLIENT_SECRET` | Automated browser/API validation | Same service token's client secret |
   | `STAGING_TOTP_ENCRYPTION_KEY` | Later synthetic MFA fixtures/enrollment | Newly generated random value of at least 32 characters, stored only here/password manager |

   Only `CF_STAGING_API_TOKEN` is consumed by the current credential-check workflow. The service-token/MFA secrets are reserved for the later validation step; they are not installed into either Worker by this preparation. No `STAGING_TEST_TOKEN` is required now because no staging control endpoint is exposed.

5. Do not add SMTP2GO, NVD, production gate, production MFA, production Cloudflare API tokens or customer data. The earlier Basic Auth `STAGING_SITE_GATE_PASSWORD` is no longer needed.
6. If required environment reviewers/branch restrictions are unavailable on the repository's GitHub plan, report that limitation. Do not put credentials into an unprotected repository workflow as a substitute; use a reviewed, staging-only runner instead.

A token stored in GitHub cannot be read back by this assistant. You can simply confirm **“staging credentials and Access are ready”**, providing the non-secret issuer/AUD if needed. Do not send secret values. The new workflow's preparation job deliberately has no secrets or cloud permissions.

## 4. Prepared configuration, scripts and safeguards

| File | Purpose |
|---|---|
| `staging/wrangler.api.json` | Approved account/API name, private exposure, disabled schedules/delivery, unresolved D1 UUID placeholder |
| `staging/wrangler.site.json` | Approved frontend, Access variables, static assets and `STAGING_API` service binding |
| `staging/target.mjs` | Fixed approved target identity and explicit production-D1 rejection |
| `staging/scripts/configure.mjs` | Validates targets and generates local resolved configs; never contacts Cloudflare |
| `staging/access.mjs`, `staging/frontend.mjs` | Verify Access JWT before every path; strip Access credentials from downstream requests; same-origin API; no public API fallback |
| `staging/api-wrapper.mjs`, `staging/blocked-fetch.mjs` | Positive runtime-binding/credential allowlist, forced delivery-off settings, no-op scheduled handler and compiled outbound-fetch blocker |
| `staging/scripts/build.mjs`, `build-assets.py` | Build isolated staging bundle and synthetic static data without changing production output/source |
| `staging/scripts/schema.py` | Full local schema verification and checksummed bootstrap manifest; 0028/0029 stay separate |
| `staging/scripts/cloud.mjs` | Fixed staging-account preflight and explicitly gated later create/deploy commands; no arbitrary SQL or account override |
| `staging/tests/isolation.test.mjs`, `scripts/check-build.mjs` | Access, target, auth, egress, schedule and generated-build checks |
| `.github/workflows/cvie-staging.yml` | Credential-free preparation on the PR/branch; optional protected read-only credential check; protected provisioning job; initial push skips execution |
| `.github/workflows/cvie-phase012.yml` | Skip the old production read-only baseline job for PR #243; PR path filters evaluate the entire diff and would otherwise rerun it on staging updates |

The API staging bundle rewrites existing hardcoded web/API origins at build time. It does not change production code defaults. All backend free `fetch` references are compiled to a rejecting staging transport, and the one-time production mail-test module is replaced by an inactive stub so its embedded recipients are not included. The frontend uses the approved same origin and a restrictive `connect-src 'self'` CSP. Static taxonomy/identity definitions are reused; collected advisory, malware and threat snapshots are replaced by empty, explicitly synthetic data. No customer database is copied.

Email is blocked independently of environment flags and supplied credentials. Missing intelligence still remains missing; the provider blocker must not be interpreted as coverage. New registry/fast-evidence feature flags start disabled and will be enabled deliberately during validation after schema/fixture setup. Existing remediation audit-compatible behavior is preserved.

## 5. Local preparation commands — safe now

From the existing PR checkout:

```sh
npm install --prefix staging --no-save --no-package-lock esbuild@0.25.12
node staging/tests/isolation.test.mjs
node staging/tests/cloud.test.mjs
python staging/scripts/schema.py
node staging/scripts/build.mjs
node staging/scripts/check-build.mjs
```

These do not need a Cloudflare token. Generated files stay in ignored `staging/.build/`; no .env/dev-vars files or runtime credentials are committed. Do not deploy the templates directly: the D1/Access placeholders intentionally prevent a usable deployment. The resolved generator needs the verified staging UUID and Access variables first.

## 6. Sequence after credentials are ready — not executed now

The [final resource creation plan](cvie-staging-resource-creation-plan.md) supersedes this outline for the next approval step. It separates empty database creation and Worker deployment from later migrations/fixtures, and requires API verification before frontend deployment. The protected execution job is now implemented; see the current first-execution instructions for the separate approval and exact SHA/operation gates.

1. Run `node staging/scripts/cloud.mjs check` using only the protected staging variables/token. It reads the staging Workers subdomain, Access app/policies and staging database inventory. It makes no writes and never queries production. Confirm the Access issuer/team separately and test actual challenge/denial after deployment.
2. When execution is authorized, run `STAGING_CHANGE_APPROVED=PR243-STAGING-ONLY node staging/scripts/cloud.mjs create-database`. It creates only the approved staging D1 name and prints its non-secret UUID. It refuses to replace an existing database. Set `CF_STAGING_D1_DATABASE_ID` to that returned value.
3. Complete local regression/config packaging checks, then run `node staging/scripts/configure.mjs`. This writes resolved `.build/api.json` and `.build/site.json`. No resource is changed.
4. The later gated command `STAGING_CHANGE_APPROVED=PR243-STAGING-ONLY node staging/scripts/cloud.mjs deploy` uses pinned Wrangler `4.156.0`, those explicit configs and the staging token only. It deploys the private API before the Access-verifying frontend and checks actual D1/service bindings, API exposure and schedules. It does not apply migrations, seed users, install secrets, enable features or invoke scans.
5. Validate Access denial for unauthenticated requests and allowed human/service-token access, with the application API still requiring its own synthetic session. Check the exact hostname and no production requests through a browser.
6. Apply the locally generated full bootstrap through 0027, then separately apply the checked-in 0028 and 0029 with checksum/ledger checks and staging-only target validation. This preparation emits SQL/manifests only; the remote migration/fixture runner will be finalized with the actual D1 UUID and a read-only inspection of the newly created empty database. Do not run bare `wrangler d1 migrations apply` against the repository's default config: that omits auxiliary bootstrap schemas and selects production.
7. Seed synthetic accounts/data, install only the independent staging MFA key if needed, and begin the approved validation matrix. Controlled source fixture adapters, authenticated browser timing, D1 density measurements and rollback evidence remain to be implemented/run in that phase. Do not treat this configuration preparation as a completed Task 2C performance validation.

The current workflow is new on a non-main branch. GitHub may not expose `workflow_dispatch` until the workflow exists on the default branch. **Do not merge PR #243 to unlock it.** Preparation checks run on branch/PR events without credentials. If manual dispatch is unavailable, the same read-only check can run on a separately approved staging runner with secrets supplied securely. Do not enable an automatic provisioning-on-push workaround. The final plan separately proposes an explicit operation/SHA gate and required environment review for a requested branch provisioning run; the implementation keeps the initial push disabled and requires a separately approved manual rerun or dispatch. Managed local execution would additionally need network access to `api.cloudflare.com`, the exact staging website and its actual Access team domain; no production or SMTP domains are required.

## 7. Validation and remaining limits

Local preparation checks cover signed/forged/expired/wrong-audience Access JWTs, unauthenticated rejection before assets/API, credential stripping, same-origin forwarding, rejected production targets, disabled mail and schedules, original account authentication, complete local schema integrity and absence of production origins in generated frontend code. Existing backend tests are also rerun.

Measured local preparation results: **8 staging test groups passed; 361 backend tests across 35 files passed; 122 Python tests passed.** The generated staging API smoke checks passed, and the full schema validated locally with **90 tables**. Both Worker configurations passed **Wrangler 4.156.0 `deploy --dry-run`**, using an explicitly synthetic database UUID and Access settings, without a deployment token. API package size was 618.85 KiB uncompressed / 153.26 KiB gzip; frontend Worker package was 6.04 KiB / 2.40 KiB gzip, with 75 static asset files. These are packaging measurements, not remote execution or performance results. See [machine-readable preparation evidence](cvie-evidence/staging-preparation.json).

Account/Access/service-token metadata has now been checked remotely using protected GitHub credentials, and management-token permissions/scope have been manually verified by the owner. Remote D1 compatibility, new database identity, deployed Workers/Access authentication, browser timing, migration performance, real storage/rows metrics and rollback remain **not validated remotely**. No Worker, D1 database, Access policy, GitHub environment secret or production setting has been created/modified by this preparation.

Production deployment workflows remain unchanged. The existing PR-only production diagnostic is explicitly disabled for #243, so preparation cannot silently read production using the old CI secret references. Existing Task 2B production baseline artifacts remain historical evidence only.

Refer to the full Task 2C plan for the 1/10/50-customer, ≤1,000-read evidence-page, <2-second browser and D1 density acceptance targets. Staging approval does not authorize merging or deploying production.
