> **Historical staging procedure.** The integrated permanent-staging implementation supersedes these commands and schema counts. Use [the permanent staging activation runbook](reviews/permanent-staging-activation.md). Earlier operation names, hashes and approvals do not authorize the new migration or deployment. This document remains as historical evidence.

# Staging run 7, attempt 3: investigation in progress

Run: https://github.com/Prat007ai/cveharbor/actions/runs/41567480016/attempts/3

Reviewed source: `ec9a5fa3a1f2c72dc0f0c23e041a5412f6506c5e`.

## Confirmed JWKS root cause after approved run #13, attempt 3

The approved frontend-only diagnostic update at `654280b6478b67035c1ea85855131bce0fdeed57` completed and verified its configuration. The workflow subsequently failed its Access smoke checks, not its upload. `provision.json` confirms only the frontend was updated; API deployment `9cf2324d-14e9-4818-8760-185247090fbc` / version `6c39aeca-a26f-4c39-bfdf-b41d4fc33e1d` remained unchanged. Frontend deployment is `eaefc1f7-c114-453a-a4a9-ffded1ccee2d` / version `224bee88-e8b3-4429-b149-adacb7174b0b`. No migrations, schedules or email were enabled.

Every service-authenticated static probe returned the frontend's fixed **`jwks_fetch`** rejection category. The assertion was therefore present, parsed and passed algorithm/issuer/audience/time checks; execution failed in signing-key retrieval before key import/signature verification. Anonymous/forged requests still redirected to Access and the direct API URL remained 404. Signature validity itself could not yet be tested against the keys.

**Exact implementation defect:** `staging/access.mjs` used `fetch(..., { redirect: 'error' })` for its JWKS request. Workers/workerd supports only `follow` and `manual`; constructing this request throws a TypeError before network I/O. The verifier catches it and fails closed with `jwks_fetch`. Node implements `error`, so the earlier Node-only tests did not detect this runtime mismatch. This is confirmed by the [Workers Request contract](https://developers.cloudflare.com/workers/runtime-apis/request/) and [workerd implementation](https://github.com/cloudflare/workerd/blob/main/src/workerd/api/http.c%2B%2B). Missing cookies under strict Service Auth, Static Assets context propagation, issuer/audience mismatch and expiry are not the cause of this observed failure.

**Minimum correction prepared:** change only the JWKS request's redirect mode to `manual` and explicitly reject all 3xx responses before parsing any keys. This keeps redirects forbidden, retains the issuer-bound fixed JWKS URL, and preserves every JWT signature/claim/time check. No raw service headers, identity headers, cookies or `ctx.access` are trusted as a fallback. The `jwks_redirect` diagnostic is a fixed enum with no credential/claim data.

Regression coverage includes the existing signed human/service JWT and rejection tests, manual-mode assertions, every 3xx status class, network/HTTP fail-closed behavior, and a local native-workerd harness. The harness runs in the existing credential-free preparation job, reproduces the legacy TypeError/`jwks_fetch` failure as a negative control, verifies both corrected human and service assertions through the native runtime, and proves redirects are rejected without being followed. Its outbound service is an in-process synthetic JWKS Worker; no external network service or Cloudflare credential is configured. This adds no workflow, environment or cloud infrastructure.

The corrected frontend **has not been deployed**. The previous approval covered diagnostic commit `654280b...` only. After build/runtime checks pass, request a separate `deploy-frontend` approval at the exact corrected SHA. Reuse both Workers, D1, credentials and policies. Positive live static authentication, Worker-before-assets denials and the `/v1/me` application-session boundary must pass before declaring staging operational or seeking the separate migration/CVIE validation approval.

## Service Auth and Static Assets contract review

Cloudflare's [strict Service Auth behavior](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/) intentionally issues no response `CF_Authorization` cookie, requires service headers on subsequent requests, ignores Allow policies/cookies for requests presenting service headers, and returns 401/403 for failed service authentication rather than redirecting. New organizations created on/after 2026-10-05 cannot disable strict mode. **No proposal to disable it is made.** The preflight now describes cookie observation accurately instead of labeling absent cookies as unverified service-secret authentication. Positive origin boundary probes remain required.

The frontend already verifies `Cf-Access-Jwt-Assertion`, not the cookie. Therefore strict cookie suppression alone does **not** explain its current 403 and is not claimed as the origin failure's cause. Per [Cloudflare's assertion-validation contract](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), the origin must verify the signed assertion against its issuer keys and application audience. The current verifier checks signature/algorithm, issuer, audience, expiry, issued-at and not-before claims. It intentionally does not require a human email or nonempty subject: a Service Auth application token legitimately has an empty subject and a service `common_name` instead.

Per [Workers Access limitations](https://developers.cloudflare.com/workers/configuration/cloudflare-access/#ctxaccess-limitations), Static Assets execute behind an internal router that does not propagate `ctx.access` to the user Worker. Do not switch to that context as an authentication fallback, trust raw service/identity headers, accept a cookie merely because it exists, or bypass cryptographic verification. No such fallback is implemented.

New regression tests sign real synthetic RSA assertions for both human and service identities, exercise protected static/API paths with no response-cookie dependency, and reject absent/forged assertions, service headers alone, cookies alone, wrong account/issuer, wrong audience, expired/future assertions, forged signatures and forbidden origins. They also prove Access credentials are stripped before assets or API bindings and that an Access identity is not an application session. These are local tests, not a claim that live origin authentication is fixed.

**Exact live rejection is still unobserved:** run #11's old frontend returns the same 403 for missing assertion and every verifier rejection, with no reason header. Its evidence cannot establish header presence or identify issuer/audience/signature/expiry/key-fetch failure. The already prepared frontend-only diagnostic update below is required to make that distinction without exposing credentials. It has not been deployed. Further authentication behavior changes would be speculative until its fixed rejection category is observed.

## Confirmed result from approved run #11

Run: https://github.com/Prat007ai/cveharbor/actions/runs/41659896789

- **Asset validator defect confirmed.** The live `/settings` response has no `assets.config`. The exact version serving 100% of frontend traffic (`de17e0be-c74d-4519-b789-76fd7a7d1363`, deployment `6ec2b0ae-af64-42ca-944b-3ec1f18f9eae`) reports boolean `run_worker_first: true`, with no exclusions. The ASSETS binding matches. No asset-routing configuration change is indicated.
- **Existing resources verified.** Both Workers' configuration, bindings, exposure and schedules pass. The D1 database remains the approved UUID, empty (zero tables), 12,288 bytes. There are no unexpected resources. Deployed-mode preflight now passes with zero blockers. Token-permission metadata remains the previously documented 403 limitation covered separately by owner attestation.
- **Access fails closed but positive authentication is broken.** All sampled anonymous/forged-JWT HTML, CSS, JS, synthetic-data, SVG, nested-page and API requests redirected to the expected Access login. The direct private API hostname returned 404. Valid service credentials reached the frontend, which returned its own `Cloudflare Access authentication required` 403 on every static class. The no-session API check also returned 403 before reaching the application's expected 401. There is no evidence of asset bypass, but Task 2C readiness must not be claimed.
- **Remaining cause is not distinguishable from existing responses.** The current verifier intentionally collapses missing assertions, claim rejection, signing-key lookup/import and signature failure into the same denial. It emits no rejection logs. No specific JWT/edge configuration fault is claimed without observing which check fails. The earlier deployment's asset readback failure is separate from this remaining authentication blocker.

## Prepared frontend-only diagnostic deployment — NOT executed

PR #243 adds a fixed, credential-free rejection category to the existing 403 response (`X-Staging-Access-Error`). Categories distinguish missing/malformed token, issuer/audience/time/algorithm rejection, signing-key fetch/HTTP/parse/shape/match/import failures and invalid signature. All signature, issuer, audience, time, host/origin and fail-closed controls remain enforced. No JWT, decoded claim, email, key ID, credential, raw exception or provider response is emitted. Unknown categories are discarded. Read-only probes retain only allowlisted category values.

This is **diagnostic instrumentation**, not a claim that the unknown authentication fault is corrected. An approved deployment may still end with a failed Access probe; its sanitized category will allow the next correction to be precise. There is no automatic retry, rollback, policy relaxation or deletion.

A new explicitly gated `deploy-frontend` operation in the **existing** protected workflow:

1. Requires the exact approved repository/branch/run/checkout SHA, operation, dedicated staging account and existing D1 UUID, plus the unchanged GitHub environment review.
2. Requires exactly the existing two Workers and the approved database; reruns read-only inventory/configuration/asset checks before any upload. Unexpected resources or unsafe settings stop the operation.
3. Dry-runs both packages, verifies existing API bindings/flags/exposure/schedules and records its active deployment.
4. Uploads **only `cveharbor-site-staging`**, with its unchanged reviewed bindings/variables/asset protection and the diagnostic header change. No API upload occurs.
5. Verifies the frontend active asset routing/configuration and asserts the API deployment/version is unchanged; runs the GET-only Access probes and records their result even if authentication still fails.

It does not create/delete/recreate resources, write to D1, migrate, import, change Access policies/tokens, install secrets, enable scans/schedules/mail or access production. No new workflow, environment or infrastructure is introduced. Initial push always skips provisioning.

**Next approval:** one frontend-only diagnostic deployment at the exact final PR #243 commit, operation `deploy-frontend`. The owner must set the existing protected environment's `CF_STAGING_APPROVED_COMMIT` to that full SHA and `CF_STAGING_PROVISION_ACTION=deploy-frontend`, retaining all account/D1/Access values. After separate approval, Codex can request the marked run's rerun and the owner can release the protected provisioning job. Do not use `deploy-workers`, which is reserved for an initially empty Worker inventory. Do not rerun old failed deployment attempts. Clear the armed operation afterward.

After positive Access/static/session-boundary verification succeeds, prepare the separate staging migration and synthetic CVIE test approval. No migration or data load is part of this deployment approval.

## Current findings after run #8

Run #8's approved GET-only artifact confirms both Workers exist, the API D1/rate-limit/flag/exposure/schedule checks pass, the frontend service binding/flags/exposure/schedules pass, and the one D1 database has zero tables (12,288 bytes). No unexpected Workers or databases were reported. Preserve all three resources.

The frontend assertion was copied from **upload metadata** into a **readback** check: it expected `settings.assets.config.run_worker_first === true`. Cloudflare's [script/version settings response contract](https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/script_and_version_settings/methods/get/) exposes bindings but does not promise that assets property. The [Worker Version response](https://github.com/cloudflare/cloudflare-typescript/blob/main/src/resources/workers/beta/workers/versions.ts) exposes `assets.config.run_worker_first` and accepts Worker name as identifier. The old boolean-only artifact cannot distinguish missing metadata, alternate representation or actual unsafe routing. It must not be interpreted as proof of a bypass.

The corrected readback resolves the current single 100% active deployment, reads that exact version through the GET-only version endpoint and checks its assets configuration plus the ASSETS binding. Boolean true and the universal `['/*']` rule validate global Worker-first routing; exclusions/partial routing fail and missing/unreadable metadata remains unverified. Both post-upload verification and read-only diagnostics use the same helper. This is a validation-code change; no Worker/configuration update is requested yet.

The standalone preflight now explicitly selects **deployed** inventory mode and requires exactly the two approved staging Workers and the configured database. Initial creation/deployment preflight retains its empty-inventory requirement. Existing resources are never silently replaced or treated as new.

Fresh security evidence is still required: run #8 returned 403 for the service-authenticated origin probe and did not exercise static assets or the application session boundary. The enhanced GET-only probe covers HTML, CSS, JavaScript, synthetic data, SVG and nested HTML paths with anonymous, forged-JWT, valid-service and valid-service/forbidden-Origin requests. The forbidden-Origin response must be the Worker's exact denial with its security headers, proving Worker execution before sampled assets. It also checks `/v1/me` without an application cookie and the disabled direct API URL. No login, authenticated database action, scan or redirect following occurs. Global routing metadata and live boundary tests must both pass; sample probes alone are not universal routing proof.

The existing protected diagnostic job now retains inventory, policy preflight and access results even when one check fails. A fresh `[staging-preflight]` push requests only that job; provisioning remains skipped. GitHub's unchanged environment review still requires owner approval to release existing credentials. No new workflow, environment, token or infrastructure is introduced. PR #252 stays on hold.

Do not declare the existing staging frontend ready until the corrected metadata read and live probes pass. If they pass, no redeployment is needed for these validator fixes. If routing is actually unsafe or Access authentication remains broken, prepare a targeted correction for separate approval; do not delete/recreate resources, run migrations, seed data or change production.

## Confirmed evidence

- `prepare` passed. Provisioning passed exact SHA/operation/account gates, all 21 staging test groups, packaging and built-Worker safety checks.
- The execution step failed after approximately 33 seconds. Its catch block discarded the original exception. The artifact contains only `preflight.json` and `failure.json`; it contains neither a completed cloud-operation report nor Access probe results.
- Preflight at 2026-11-03 13:45 UTC identified the dedicated staging account, zero Workers and exactly the configured staging database, UUID `fac61562-fc31-426d-8032-550aba63b7f6`. Required checks passed. Management permission metadata was unavailable (403), as covered by the separate existing owner attestation. Service-token linkage passed; the origin returned 404 without a verified JWT.
- This preflight inventory precedes the failed operation. It does **not** establish current resource state or prove that neither Worker was subsequently uploaded.
- The original deployment failure's exact cause is **not yet established**. The known reporting defect hides the operation, API status and Wrangler failure category. No application/configuration fix is claimed without evidence.

## Diagnostic changes

- Management failures now identify the fixed staging operation, numeric HTTP status/API codes and a sanitized category. Network and invalid-JSON responses are distinguished. Wrangler errors identify API/site and dry-run/upload, with fixed categories and numeric exit status; raw subprocess output and provider messages are discarded.
- Provisioning preserves structured safe errors through the outer catch and records failures in tests and CLI execution. Arbitrary exceptions never contribute their message or properties to evidence.
- A separate GET-only diagnostic inspects the existing database's metadata and both named Workers, including D1/service/rate-limit bindings, disabled variables, exposure, schedules, assets gating and deployment presence. It records only expected names, booleans and numeric metadata; unrelated names, secrets and raw settings are excluded. It executes no SQL and imports no deployment helper.
- The existing protected read-only preflight job runs this diagnostic when a staging D1 UUID is configured, and uploads sanitized JSON even on failure. Preflight CLI now selects existing-database mode when the protected UUID is present. A partial Worker may still fail the initial-provisioning preflight; the diagnostic artifact is retained for investigation.
- This diagnostic commit uses `[staging-preflight]` only. Provisioning is skipped on its push and reruns; the old approved deployment SHA cannot authorize this new source. No environment protection is changed.

## Validation and next step

25 staging test groups passed locally, including GET-only absent/partial Worker inspection, credential redaction, management response failures, isolation, Access, inventory and provisioning gates. Cloud calls and Wrangler execution are mocked. No new remote dry-run, resource mutation, migration, import, schedule, email, production access or PR merge was performed.

The managed shell has no configured staging secrets, does not allow the Cloudflare API host and its configured Git proxy is unreachable. The GitHub connector remains usable. Existing protected GitHub environment credentials are therefore the available path to fresh staging evidence; they cannot be read back into this shell.

The automatic diagnostic architecture and PR #252 are on hold. Use the existing protected `check-staging-credentials` job in run #8, which is pinned to its original read-only diagnostic source and awaits owner environment approval. No new environment, token or infrastructure is needed for this investigation. PR #243 restores this diagnostic path and removes its deferred automatic-workflow files. The initial provisioning path remains explicitly approved and fixed-account only.

Credential-free Wrangler dry runs are now part of the existing preparation job. They use synthetic configuration, forward no Cloudflare/application token, always include `--dry-run`, and write only sanitized operation/category results. This exercises actual packaging before any separately approved upload. The local runner has no cached Wrangler/esbuild packages, so real packaging validation is performed by the existing GitHub preparation job; mocked isolation and safety tests run locally.

Root cause and current inventory remain unconfirmed until run #8 completes. Do not retry provisioning, delete/recreate resources, migrate or seed data in the meantime. After both Workers are separately approved, deployed and verified, the next controlled step is a reviewed staging-only migration/synthetic CVIE test plan. No migration or fixture execution is authorized by preparation.

