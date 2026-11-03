# Staging run 7, attempt 3: investigation in progress

Run: https://github.com/Prat007ai/cveharbor/actions/runs/41567480016/attempts/3

Reviewed source: `ec9a5fa3a1f2c72dc0f0c23e041a5412f6506c5e`.

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
