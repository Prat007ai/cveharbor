# Task 2C: Protected provisioning preparation and execution instructions

**Prepared for review; resource execution is not approved yet.** The owner approved workflow preparation and reports that `cloudflare-cvie-staging` requires reviewer `Prat007ai`, disables administrator bypass, and restricts deployments to `codex/cvie-core-phase012`. Those GitHub settings are owner-confirmed, not independently inspected through an administration API. This update does not alter them.

No Cloudflare resource creation, deployment, remote SQL, migration, data import, email or schedule is executed by preparing/pushing this change. PR #243 remains draft and unmerged. The existing manual token attestation and raw remote preflight evidence remain intact.

## Implemented safeguards

- `.github/workflows/cvie-staging.yml`: adds `provision-staging` in the existing protected environment with `contents: read`, a 20-minute timeout and the existing serialized `cvie-staging-243` concurrency group. The **initial push always skips provisioning**, including a commit containing `[staging-provision]`. Pull requests, ordinary pushes, schedules and read-only preflight requests cannot provision.
- `staging/scripts/provision.mjs`: independently requires repository, exact branch, full approved SHA matching both the run and checkout, explicit operation and fixed staging account before any network request. A dispatch must request the same operation as the environment variable. A marked push must be manually rerun (`run_attempt > 1`); its original commit ID must match. No arbitrary command, SQL or account input is exposed.
- Fresh GET-only preflight must pass account, Access policies, service-token linkage and inventory checks. The known metadata 403 is accepted only with the committed owner attestation; readable conflicting permission/scope metadata or failed service linkage stops execution.
- `create-database` performs one POST to the fixed staging account, validates the returned name/UUID and stops. It never deploys Workers or executes SQL. Existing databases/Workers cause a stop instead of replacement or automatic recovery.
- `deploy-workers` requires the recorded staging UUID, reruns local packaging and dry-runs both packages, deploys/verifies the private API, then deploys/verifies the frontend. API verification failure prevents frontend upload. Actual bindings, disabled flags, rate limiter, public exposure, schedules, assets gate and initial deployment/version IDs are checked. Provider credentials are never installed.
- `staging/scripts/probe-access.mjs`: four fixed-host GETs check anonymous/forged-token denial, service-authenticated static content and `/v1/me` returning unauthenticated 401 without an application session. It follows no redirects and invokes no login flow or database-dependent authenticated action. Signed expired tokens remain covered by local cryptographic tests.
- Reports include sanitized preflight/operation/Access evidence only. No raw provider response bodies, subprocess output, JWTs, token values, policy emails or user data are exported. Failure reports do not claim that a timed-out write was rolled back.

## Exact targets and binding order

Account **`9706b4d98ad72884e67fd1eb875c8a61`** only:

1. Empty D1 **`cveharbor-accounts-staging`**.
2. Private API Worker **`cveharbor-accounts-staging`**, `DB` bound to that new UUID; native `ASSIGNMENT_ACK_RATE_LIMITER` namespace `24302`, 60/60 seconds. No public API route, workers.dev URL or preview URL.
3. Frontend Worker **`cveharbor-site-staging`**, `STAGING_API` bound to the staging API and `ASSETS` to the synthetic build. Existing Access issuer/AUD protect all paths. Website: https://cveharbor-site-staging.cveharbor-staging.workers.dev.

Cloudflare calls the default service-binding environment `production`; if that label appears in a staging Worker readback it denotes the default environment **inside the dedicated staging account**, not CVEHarbor's production account. The account and service name are fixed and checked independently.

## GitHub environment values

Environment: **`cloudflare-cvie-staging`**. No new secret, permission expansion or token rotation is needed.

| Setting | Value for the first execution |
|---|---|
| Variable `CF_STAGING_APPROVED_COMMIT` | Exact full 40-character implementation SHA supplied in the completion message/PR update; must equal the selected workflow run's SHA |
| Variable `CF_STAGING_PROVISION_ACTION` | Leave unset while reviewing. Set **`create-database`** only when separately approving the first execution |
| Variable `CF_STAGING_D1_DATABASE_ID` | **Unset** for creation; fill with the returned UUID afterward |
| `CF_STAGING_ACCOUNT_ID` | Existing `9706b4d98ad72884e67fd1eb875c8a61` |
| `CF_STAGING_ACCESS_ISSUER`, `CF_STAGING_ACCESS_AUD` | Existing staging values; current variable/secret storage remains supported |
| Secret `CF_STAGING_API_TOKEN` | Existing staging-only management token |
| Secrets `CF_STAGING_ACCESS_CLIENT_ID`, `CF_STAGING_ACCESS_CLIENT_SECRET` | Existing staging automation credentials |

Do not set generic `CLOUDFLARE_*` production variables or copy production secrets. The job installs no runtime secrets. The owner enters environment variables; the runner has no GitHub administration permission and cannot change them.

## Starting the first database creation — only after separate execution approval

1. Review the implementation diff and exact final SHA in PR #243. Verify its initial **push** preparation run passed and `provision-staging` was **skipped**. The initial push has no cloud credentials or mutation work.
2. Set the approved SHA and `create-database` operation in the protected environment; leave D1 UUID unset. Retain the existing account/Access credentials and environment protections.
3. Prefer **Actions → CVIE staging preparation (no automatic deployment) → Run workflow**, if GitHub exposes dispatch for this branch. Select `codex/cvie-core-phase012`, set `provision_action=create-database`, keep `check_credentials=false`, and verify the branch still points to the approved SHA.
4. If dispatch is unavailable because the workflow is not on main, **do not merge to unlock it**. Open the initial **push** run for the reviewed commit marked `[staging-provision]` and choose **Re-run all jobs**. This reruns the same SHA; it is an explicit execution request. Do not select the pull-request run or “Re-run failed jobs.” The initial attempt skipped provisioning; the explicit rerun can now queue it. The same source/operation gates still apply.
5. Wait for `prepare` to pass. Review the pending `cloudflare-cvie-staging` deployment request as `Prat007ai`, verify the exact commit and `create-database` variable, then approve. Do not bypass or change environment protection. If GitHub cannot queue/review this job as expected, stop and report that platform limitation.
6. The job repeats read-only checks, creates the one empty database and uploads `cvie-staging-provision-<SHA>-<attempt>`. Read `provision.json` for the account/name/UUID. No Worker, schema or data is created by this operation.
7. Clear `CF_STAGING_PROVISION_ACTION` immediately after the run. If successful, enter the returned UUID as `CF_STAGING_D1_DATABASE_ID`. Do **not** switch to `deploy-workers` until its execution is separately reviewed/approved.

Setting variables alone does not execute anything. Do not rerun the marked workflow for routine diagnostics while an operation is armed. For read-only checks use the separate preflight request. Exact SHA matching prevents a later unreviewed branch commit from using a previous approval.

If creation times out or fails, do not blindly rerun: inspect the sanitized artifact and staging inventory read-only first. A database may exist even if its response was lost. The runner deliberately refuses duplicate creation, replacement, deletion, migration or automatic recovery.

## Validation evidence and limits

Local validation for this preparation:

- **21 staging test groups passed** across cloud operations, isolation/JWT handling, read-only preflight and provisioning guards. All management requests and deployments in these tests are mocked; no cloud resources are touched.
- **actionlint 1.7.7 passed** for the staging workflow (shellcheck integration disabled; workflow shell blocks contain only fixed commands).
- The synthetic build and built-Worker smoke checks passed with **esbuild 0.25.12**; mail/providers are blocked, scheduled work is disabled and account authentication is retained.
- Complete schema validated in local SQLite: **90 tables**. This did not connect to D1 or apply a remote migration.
- Both packages passed **Wrangler 4.156.0 `deploy --dry-run`** using a synthetic D1 UUID/Access configuration and no management token. API: 618.79 KiB / gzip 153.22 KiB. Frontend: 5.91 KiB / gzip 2.37 KiB, 75 static files.
- Production application code, schemas, configurations and deployment workflows are unchanged. Backend/frontend regression totals from earlier reports are historical; this change reruns the relevant staging/build suite rather than claiming new full application test results.

The final SHA and initial GitHub preparation-run outcome will be supplied after committing/pushing the reviewed implementation. No provisioning rerun or dispatch will be started during preparation. Remote write capability, actual settings response shapes, Access-to-origin authentication and the protected provisioning review/rerun lifecycle remain **not exercised** until approved execution. Unexpected API metadata fails closed and may require a reviewed follow-up; local mocks are not remote validation.

Migrations 0028/0029, fixture imports, onboarding/performance tests, rollback drills, scheduled processing, email delivery and production rollout remain outside this first execution. An empty database and undeployed Workers are the expected state until their separate approved steps succeed.
