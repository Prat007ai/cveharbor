# Cloudflare runtime connection

This release installs the previously verified Azure application credential into the existing `cveharbor-accounts` Worker and verifies Entra authentication and Azure model-list access from that deployed Worker. It enables no customer AI endpoint, inference request, UI, allowance, or dashboard. The owner authorized connecting the backend on November 10, 2026 and retains Azure administration. No Azure management credentials are needed.

## Exact scope

The live readiness endpoint was healthy and identified `d075a90fa2afd00deb5d500e0beb7129daf343d2deed0127bc94fa4f4f4b9f6e`. `azure_worker_package.py` reconstructs that serving CVIE-refresh/Team package from fixed history and adds only two Azure modules, a deployment-check route and four nonsecret Azure configuration values. `release/azure-worker-backend.txt` pins the result. It does not release unrelated main code. Storage, schemas, schedules, email and participant permissions retain their predecessor definitions.

The existing verified Web API client is shared between the GitHub verifier and Worker. The only new runtime route, `POST /v1/ops/azure-connection`, verifies a separate random 256-bit HMAC key, a 60-second timestamp, a nonce and the exact release identity. Its encrypted proof binding expires 15 minutes after creation. Empty-body requests on the exact production hostname and path are required. Invalid proofs, alternate hosts, prompt bodies, and expired checks return 404 without contacting Azure. The proof is a deployment capability, not a customer/platform-admin role. It cannot access customer records or inference. Signed-request replay during its 60-second validity may repeat metadata authentication, but cannot generate tokens, expose credentials, or perform customer operations. The existing origin and recovery admission controls still apply, including normal operational lease bookkeeping.

`CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET` is transferred directly from the protected GitHub environment into an encrypted Cloudflare Worker secret. A second encrypted binding, `CVEHARBOR_AZURE_CONNECTION_PROBE`, contains only the temporary proof key, creation/expiry times and release pin. The temporary local file is mode 0600, is removed in `finally`, and is never an artifact. Wrangler output is captured and not printed. Neither secret is sent to browser code or returned in the verification response. After expiry the check is unavailable even though the encrypted proof binding remains; the Azure application credential remains installed for the subsequent integration.

## Protected release

1. Review the diff and exact PR checks. The manual `Connect production Cloudflare backend to Azure AI` workflow is restricted to main, exact `reviewed_commit`, first attempt, and disabled automatic production releases. It reuses the application/security CI gate and protected `cloudflare-worker-production` environment with the shared production lock.
2. Verify owner Prat007ai remains the eligible reviewer, main is the only deployment branch, no tags, and administrator bypass is disabled. The workflow verifies these settings, owner approval, and merged PR provenance before accessing cloud credentials. Existing owner delegation covers routine release approval; credential installation is within the owner's requested backend connection. Do not substitute credentials or widen permissions if the Cloudflare token has expired.
3. Rebuild and test the exact production overlay. Read-only preflight verifies account/Worker/database identities, live schema and recovery state. Record the current Cloudflare version/deployment and confirm the prior version remains retrievable. Abort if Azure bindings already exist; reconcile an interrupted operation instead of blindly rerunning it.
4. Upload code and the two encrypted bindings together with pinned Wrangler `deploy --secrets-file`. This changes the accounts Worker only. No new Azure/Cloudflare resource or D1 migration is performed.
5. Check deployed release readiness, unchanged prior bindings and exact new bindings, 100% traffic to the new version, unsigned-check rejection, and one signed access-only request. Retain `azure-worker-verification.json`, containing version IDs, source/release identity and sanitized authentication/resource flags. No prompts, responses, credentials or customer records are retained. No model tokens are consumed.

Failure records identify the failed stage without publishing provider bodies. A failed/timeout deployment may have taken effect; inspect the live release and version before a new operation. No automatic retry or rollback occurs. The preceding version ID and deterministic source package provide rollback inputs, but rollback/removal of the new credential bindings requires explicit review of current traffic and authorization. The schema is unchanged and no database restore is needed for this change.

Updating the workflow credential policy refreshes its checksum in the existing recovery manifests and their regression pin. No recovery SQL, executor, target, production approval value or recovery authorization changes.

## Next releases

Before customer enablement, implement durable per-request attribution/usage in Cloudflare, shared US$20 monthly organization allowances with atomic reservation and hard stops, a platform-wide spending limit, and explicit platform-admin-only cost reporting. Organization membership must not grant platform-administrator rights. The current CA$20 Azure budget is an alert, not these enforcement controls. Inference testing and customer activation remain distinct from this access-only connection.

## Vendor references

- [Cloudflare encrypted secrets and simultaneous code/secret deployment](https://developers.cloudflare.com/workers/configuration/secrets/)
- [Microsoft Entra application authentication](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
# Release diagnostic follow-up

PR #333 merged at `b4ca4ec36cb295b5cb2b920b1ff69f8f96412b28`. Approved run [42946912204](https://github.com/Prat007ai/cveharbor/actions/runs/42946912204) passed package, exact-main checks and environment policy, then stopped at `production_preflight` before uploading any code or credential. The serving backend remained the reviewed predecessor. Azure was not contacted by that release.

The follow-up records only a fixed network-operation label and its HTTP status in the sanitized report. It never records request URLs, headers, bodies, provider errors or credentials. Runtime bytes, permissions, release identity and all deployment guards remain unchanged. Two diagnostic tests plus the 18 existing Azure tests pass locally. The workflow requires this follow-up's own merged PR for release provenance. A fresh first-attempt run is appropriate only while the live predecessor is unchanged; partial deployment still requires reconciliation.
