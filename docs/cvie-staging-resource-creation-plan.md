> **Historical staging procedure.** The integrated permanent-staging implementation supersedes these commands and schema counts. Use [the permanent staging activation runbook](reviews/permanent-staging-activation.md). Earlier operation names, hashes and approvals do not authorize the new migration or deployment. This document remains as historical evidence.

# Task 2C: Final staging resource creation plan for approval

**Update: the owner approved this plan and protected workflow preparation, while reserving separate approval of actual execution. The workflow is now prepared; see the [implementation and first-execution instructions](cvie-staging-provisioning.md). No resources have been created.**

The account owner has personally verified all five token permissions and its exclusive staging-account scope in Cloudflare. That resolves the remaining pre-creation evidence gap. This is recorded as [manual owner verification](cvie-evidence/staging-owner-attestation.json), separately from the [automated preflight](cvie-staging-preflight.md). The historical HTTP 403 permission-metadata results and `ready_for_creation: false` in the raw automated output remain unchanged; they describe what the API could verify without the later owner attestation.

This plan concerns PR #243, branch `codex/cvie-core-phase012`, and **only account `9706b4d98ad72884e67fd1eb875c8a61`**. No resources, credentials, Access policies or GitHub environment settings have been changed to prepare this plan.

## 1. Exact approval scope

Approval would permit creation of one empty D1 database and the first deployments of two staging Workers, followed by read-only binding/Access checks. It also permits the small PR-only execution-workflow changes described below. The first deployment is how Cloudflare creates the Worker; there is no separate empty Worker creation step.

| Order | Resource | Configuration and bindings |
|---|---|---|
| 1 | D1 `cveharbor-accounts-staging` | New empty database in the approved staging account; Cloudflare generates its UUID |
| 2 | API Worker `cveharbor-accounts-staging` | `DB` → that verified new UUID; native `ASSIGNMENT_ACK_RATE_LIMITER`, namespace `24302`, 60 requests/60 seconds; no service binding to production |
| 3 | Frontend Worker `cveharbor-site-staging` | `ASSETS` → synthetic static build; `STAGING_API` → `cveharbor-accounts-staging`; existing staging Access issuer/AUD |

Frontend URL: **https://cveharbor-site-staging.cveharbor-staging.workers.dev**. Browser API requests use `/v1/*` on that same origin. The API has no public route, workers.dev URL or preview URL. Both Workers use compatibility date `2026-10-28`. Frontend assets always pass through the JWT-verifying Worker first.

**Excluded:** production changes, PR merge, D1 schema bootstrap/migrations including 0028/0029, synthetic account/CVE insertion, external ingestion, historical rescans, load tests, email delivery, schedules, new databases beyond the one named above, Queues, KV, additional hostnames, DNS changes and Access policy changes. Remote schema and full validation remain a later step.

## 2. GitHub configuration required

Use the existing **`cloudflare-cvie-staging`** environment. No token rotation, new deployment secret or broader Cloudflare permission is required on the basis of current evidence.

Retain these existing values:

- Secret `CF_STAGING_API_TOKEN`.
- Secrets `CF_STAGING_ACCESS_CLIENT_ID` and `CF_STAGING_ACCESS_CLIENT_SECRET`.
- `CF_STAGING_ACCOUNT_ID`, `CF_STAGING_ACCESS_ISSUER` and `CF_STAGING_ACCESS_AUD`, using their currently working environment variable/secret locations.
- Deployment branch restriction to `codex/cvie-core-phase012`, repository `Prat007ai/cveharbor`, and the environment's required-reviewer protection. If the environment lacks a required reviewer, enable an authorized reviewer before enabling resource-creation jobs. Do not bypass this protection or broaden allowed branches.

Additional **environment variables**, not secrets:

| Variable | When/value |
|---|---|
| `CF_STAGING_APPROVED_COMMIT` | Full 40-character SHA of the reviewed provisioning implementation on this PR; known after that implementation is prepared following approval |
| `CF_STAGING_PROVISION_ACTION` | `create-database` for the first execution, then `deploy-workers` for the second; unset after completion |
| `CF_STAGING_D1_DATABASE_ID` | Leave unset now. After database creation, enter the returned UUID; never reuse the production UUID |

The database UUID is not a credential. The creation job will output it in a sanitized artifact. The owner will enter it into the environment and switch the action for step two. No GitHub administration token or permission to edit environment variables is added to the runner. This intermediate configuration entry does not require reapproving the same plan in chat, but GitHub's environment-review gates still apply to each execution.

The management token is exposed only to the provisioning runner. It is never installed into either Worker. Access service-token credentials stay in the test runner; the frontend receives only issuer/AUD configuration. No mail/provider secrets are installed. `STAGING_TOTP_ENCRYPTION_KEY` is not needed for creation and remains reserved for later synthetic MFA fixtures.

## 3. Execution workflow to prepare after approval

At plan approval, `.github/workflows/cvie-staging.yml` had **no creation/deployment job**. The protected implementation is now described in the linked execution instructions; the numbered list below records the approved preparation design. The existing `staging/scripts/cloud.mjs` contains gated creation/deployment helpers, which at plan approval deployed both Workers before verifying their bindings. The preparation now implements the following changes on the same PR, with API verification before frontend upload:

1. Add a protected provisioning job using `cloudflare-cvie-staging`, with `contents: read` and concurrency group `cvie-staging-243`, `cancel-in-progress: false`.
2. Require the approved repository, exact branch, explicit operation request and equality between the run commit SHA and `CF_STAGING_APPROVED_COMMIT`. Fail before any cloud write if a variable is missing/mismatched or the operation is not one of the two allowed values.
3. Retain default preparation/read-only behavior. Ordinary pushes, PR events, schedules and the existing `[staging-preflight]` marker must never create resources.
4. Where `workflow_dispatch` is available for the branch workflow, use it. If GitHub still requires the file on main, do not merge to unlock it. Instead, manually rerun the preparation-only push run for the reviewed `[staging-provision]` commit to queue the protected job, gated by the exact approved SHA, operation variable and a fresh environment review. The initial push always skips provisioning. The subsequent `deploy-workers` execution can rerun that same reviewed job after the owner sets the new UUID/action. This is a proposed, explicitly gated execution path—not an automatic deployment-on-push fallback. If reviewer protection cannot be configured, stop rather than enabling an unattended workaround.
5. Separate API deployment and its post-deployment checks from frontend deployment: a failed API verification must prevent the frontend upload. Keep explicit generated staging config paths and pinned Wrangler `4.156.0`.
6. Add a read-only post-deployment Access probe with sanitized output and no account/fixture mutation. Failures cannot trigger policy weakening, new privileges, migrations or automatic resource deletion.

The run creates no environment secrets or variables itself. Capture the approved source SHA and build hashes in the deployment report. Local tests cover missing/mismatched SHA, wrong operation/account, missing D1 UUID, production bindings, failed API verification preventing frontend deployment, and exclusion of credentials from artifacts. The subsequent preparation adds the protected workflow, with the initial push unconditionally skipping provisioning; only a separately requested dispatch or rerun can queue execution.

## 4. Exact creation and deployment sequence

### Step A — refresh checks and create the empty database

1. Load only the existing staging environment credentials. Recheck the account ID/subdomain, active token, expected Access application/AUD, both named policies and service-token linkage. Inspect staging inventories for name collisions. Use the owner attestation for write-grant/scope evidence; do not attempt broader token-management access to eliminate the already understood 403.
2. Confirm that the database and two Worker names remain unused. Stop on an unexpected existing resource rather than replacing it. No production endpoint is probed.
3. In the protected runner, perform the existing bounded operation:

   ```sh
   STAGING_CHANGE_APPROVED=PR243-STAGING-ONLY node staging/scripts/cloud.mjs create-database
   ```

   Its only resource mutation is `POST /client/v4/accounts/9706b4d98ad72884e67fd1eb875c8a61/d1/database` with `{"name":"cveharbor-accounts-staging"}`. Record and validate the returned UUID/name/account. A timeout or ambiguous result requires a read-only inventory check before retrying; no blind create loop.
4. Produce a sanitized creation artifact with the resource name, UUID, account, source SHA and request outcome. **Stop this execution after creation.** No SQL is run and no Worker is deployed in this first execution.
5. Owner sets `CF_STAGING_D1_DATABASE_ID` to that UUID and changes `CF_STAGING_PROVISION_ACTION` to `deploy-workers`. Keep the same approved implementation SHA unless reviewed source changes are required.

### Step B — resolve configuration and package

1. Verify the supplied UUID belongs to `cveharbor-accounts-staging` in the approved account. Reject the production D1 UUID and any mismatch. The database is now expected to exist; do not rerun an empty-inventory assertion as though creation had not happened.
2. At the approved SHA, run the existing local safety tests, synthetic build and resolved-config generation:

   ```sh
   npm install --prefix staging --no-save --no-package-lock esbuild@0.25.12
   node --test staging/tests/*.test.mjs
   node staging/scripts/build.mjs
   node staging/scripts/check-build.mjs
   node staging/scripts/configure.mjs
   ```

3. Generate `.build/api.json` and `.build/site.json` from the separate staging templates. Validate account, names, UUID, private API exposure, service binding and flags. Dry-run both packages with pinned Wrangler before any upload. Do not use the repository's default production Wrangler configuration or deploy helpers.

### Step C — create/deploy and verify the private API Worker

1. Deploy the API package first, using `staging/.build/api.json`. This creates `cveharbor-accounts-staging` and binds `DB` to the verified new database.
2. Read back actual settings: exact D1 binding, native rate limiter, no unexpected runtime credentials or service bindings, no public workers.dev endpoint, no previews, routes or schedules.
3. Confirm the reviewed flags/guards: email disabled, all outbound provider calls blocked, scheduled handler disabled, registry and fast-evidence flags initially false. Retain remediation audit-compatible code.
4. **Only proceed to the frontend if API verification passes.** The API remains private while these checks run.

### Step D — create/deploy and verify the frontend Worker

1. Deploy the synthetic static assets and frontend Worker with `staging/.build/site.json`. Bind `STAGING_API` to the now-verified API Worker. No public API hostname or custom domain is created.
2. Read back the service binding, assets-first-gate setting, exact Access issuer/AUD, workers.dev hostname, disabled preview URLs and absence of D1/production bindings or schedules.
3. Use the existing Access application/policies. The Worker verifies JWT signature, issuer, audience and expiry even if edge routing is not yet functioning as expected. No request may bypass it to reach assets or `/v1/*`.

### Step E — read-only post-creation checks and stop

1. Request the staging site without Access credentials: confirm it returns an Access challenge or denial and exposes no application assets/API data. A login redirect is acceptable; a public application response is not.
2. Use the existing staging Access service token: confirm the protected static landing page is accessible. Confirm an Access-authenticated request to `/v1/me` **without an application session** returns 401, proving Access authentication does not replace tenant/account authentication.
3. Verify forged/expired JWTs cannot unlock the frontend and requests do not contact production. An interactive reviewer login can be checked by the owner; no email OTP is initiated by the automation.
4. Do not interpret `/v1/health`'s email-unavailable response as a broken deployment: SMTP is intentionally absent. The database is still empty and application onboarding is not operational yet. Avoid authenticated application actions that require schema or could write data.
5. Recheck account inventories/bindings/schedules and publish the creation report: actual UUID and Worker versions, source/build hashes, Access outcomes and pending migration/validation work. Clear the operation variable after completion. Stop here.

If Access does not protect the hostname or the service token is not accepted, stop and report the exact outcome. Do not disable JWT checks, broaden policies or introduce a public API to make the test pass.

## 5. Stop/recovery rules and next boundary

- A permission failure during an approved write stops that stage. The owner's confirmation is evidence of configured grants, not a guarantee of a successful future API write.
- If D1 creation succeeds but a later step fails, keep the empty staging database and record its UUID; do not delete/recreate it automatically.
- If only the API deploys, keep it private and leave the frontend undeployed until its verification passes.
- If the frontend deploys but Access checks fail, the JWT gate remains fail-closed. Do not weaken it. Report the failure; remediation stays within the approved staging target or returns for approval if broader changes are needed.
- Any unexpected existing resource, changed account scope, source mismatch or production binding aborts execution. There is no production fallback.
- No destructive rollback, database restore, migration ledger reset or permission escalation is part of this creation plan.

After this bounded step, the staging resources and Access routing can be assessed as deployed. The next separately reviewed stage is complete schema bootstrap through 0027, then 0028/0029, synthetic fixtures, browser/performance tests and rollback validation. This plan does not implicitly authorize that stage.

## Approval requested

Approve the limited provisioning-workflow preparation, creation of the single empty staging D1 database, API-first then frontend deployment, and read-only post-creation checks above, in account `9706b4d98ad72884e67fd1eb875c8a61` only. The owner supplies the returned UUID/operation settings in the existing GitHub environment and completes its protection reviews. No production changes or merge of PR #243 are included.

