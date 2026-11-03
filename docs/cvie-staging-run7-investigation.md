# Staging run 7, attempt 3: investigation in progress

Run: https://github.com/Prat007ai/cveharbor/actions/runs/41567480016/attempts/3

Reviewed source: `ec9a5fa3a1f2c72dc0f0c23e041a5412f6506c5e`.

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

The original protected diagnostic job is superseded by the [trusted read-only environment setup](cvie-staging-readonly-setup.md). Do not approve/retry the old provisioning job. The new workflow uses only the restricted read token, a protected default-branch listener and immutable diagnostic code. Activation requires the documented one-time environment/token setup and reviewed workflow-only installation on the default branch. Once fresh evidence is available, Codex will determine partial-resource state, complete the targeted correction and prepare a separately approved deployment if needed. Existing staging resources must be preserved.
