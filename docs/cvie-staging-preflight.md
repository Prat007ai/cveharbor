# Task 2C: Read-only staging preflight results

**Outcome: rerun completed; Access service-token linkage is now verified. Resource-creation readiness remains conditional on confirming the management token's write grants and staging-only scope. No Cloudflare resources were created or deployed.**

Latest remote check: **2 November 2026, 9:04:07 p.m. America/Toronto** (3 November 2026, 02:04:07 UTC). Reran the existing protected GitHub environment job in `cloudflare-cvie-staging`, attempt 2, using the unchanged stored token value after the owner added Access: Service Tokens Read. Diagnostic source commit: `0a67b71cd71c616a9881a2df7d72c46f2853fa27`.

[Latest workflow evidence](https://github.com/Prat007ai/cveharbor/actions/runs/41562186396/attempts/2) · [Updated machine-readable results](cvie-evidence/staging-preflight-rerun.json) · [Original preflight evidence](cvie-evidence/staging-preflight.json)

## Verified remotely

| Check | Result |
|---|---|
| Account identity | HTTP 200; ID `9706b4d98ad72884e67fd1eb875c8a61`, name matches CVEHarbor Staging |
| Management token validity | Active; account-token verification endpoint returned HTTP 200 |
| Workers subdomain | `cveharbor-staging`, as approved |
| Workers inventory | Zero Workers; both approved names available |
| D1 inventory | Zero databases; approved database name available |
| Production resource identifiers | Absent from the staging inventories; no production account/database endpoint was queried |
| Access application | Correct self-hosted app, exact staging hostname, configured AUD and expected name |
| Human policy | `CVEHarbor staging reviewers`: Allow, one explicit email rule; address excluded from evidence |
| Automation policy | `CVEHarbor staging automated tests`: Service Auth (`non_identity`), explicit service-token reference |
| Service-token linkage | **Now passed:** exactly one matching `cvie-staging-validation` token; its Client ID matches the protected GitHub secret and its ID matches the policy reference |
| Service-token status | Enabled and unexpired at check time |
| Policy exposure | Exactly the two expected policies; no Bypass, Everyone or additional allow policy |
| Access issuer | Signing-key endpoint reachable and returns RSA signing keys |
| GitHub credential availability | Management token and both Access service credential values were present in the protected job; no values were printed or exported |

No existing Worker bindings could be checked remotely because no Workers exist yet. Worker configuration, email/schedule guards, production-ID rejection and same-origin routing were verified locally, including the existing staging tests. These are preparation safeguards, not claims about a deployed environment.

## Remaining verification gaps

### 1. Management-token write grants and exact resource scope

Both account-token and user-token detail endpoints returned **HTTP 403**. The token is active and can read the selected staging account, Workers/D1 inventories and Access policies. That does **not** prove Workers Scripts Edit or D1 Edit, or reveal the complete resource-scope policy.

This is a metadata visibility gap, not evidence that the deployment permissions are missing. No create/update request was used as a permission probe, and no production-access probe was performed. The account verification endpoint alone is also not treated as independent proof of the token's ownership type.

**Owner action:** review the token in Cloudflare and confirm that Workers Scripts Edit/Write and D1 Edit/Write are granted, with account resources restricted exclusively to `9706b4d98ad72884e67fd1eb875c8a61`. Retain Account Settings Read and Access Apps and Policies Read. A confirmation or redacted permission/scope description is sufficient; do not share the token. Broad user-level token-administration permissions are not necessary simply to finish this review. Such a manual confirmation would be identified as owner-attested evidence, not an API measurement.

### Resolved: Access service-token metadata/linkage

After the permission update, the service-token listing returned HTTP 200 with **one visible record**. The record name matches `cvie-staging-validation`, its Client ID matches the configured GitHub environment secret, and its ID matches the Service Auth policy reference. The token is enabled and unexpired. No additional direct lookup was needed.

The earlier empty listing/direct-lookup 403 was a visibility limitation. The rerun resolves the linkage question without exposing any token value, Client ID, service-token identifier or policy email address.

**No further credential replacement is needed for this check.** The existing management token secret worked after its permission update. Service-token metadata linkage is distinct from proving the Client Secret works through a deployed origin; that end-to-end check remains deferred below.

The initial setup guide did not require Service Tokens Read. The owner has now supplied that read permission; no Access edit permission is requested.

### 3. End-to-end Access authentication is deferred

The authenticated GET to the approved staging URL returned **404**, without a verifiable Access JWT. With zero Workers deployed, this cannot validate or invalidate the service secret. Actual Access challenges, valid service-token access and denial of unauthorized requests must be tested after the first separately authorized Worker deployment. This deferred test is not, by itself, a reason to rotate credentials or change policies.

## Isolation and execution evidence

- All management requests were fixed to the staging account, except read-only introspection of the current token itself through Cloudflare's documented user-token endpoint. No production account or D1 queries were made.
- This rerun made **12 GET requests**. The three preceding passes made 11, 12 and 13 GET requests. There were **zero mutating Cloudflare requests** across all checks.
- No D1 SQL was executed; no migrations, fixture writes, historical scans or load tests ran. Database row-usage measurements were not part of this control-plane preflight.
- The credential-check job contains only the read-only diagnostic script. It imports neither a deployment executor nor a migration runner. It writes only sanitized local evidence and an Actions artifact.
- Secret values, JWTs, policy email addresses and service-token identifiers are excluded from the evidence. The service secret is sent only to the approved staging hostname; redirects are not followed.
- The existing production read-only baseline job remains excluded for PR #243. Production deployment jobs remain excluded from branch/PR execution. PR #243 remains draft and unmerged.
- A marked branch commit triggers the requested protected check because the new workflow is not merged into main for manual dispatch. It does not bypass GitHub environment protections. Ordinary unmarked pushes run preparation only, with no staging credential check.

The workflow is green because diagnostics executed successfully and the account/application checks passed. **That green result is not a resource-creation signoff:** the latest JSON still records `ready_for_creation: false` because management-token permission/scope metadata remains unreadable. The service-token linkage limitation has been removed.

## Readiness decision

The account, names, subdomain, Access policies and service-token linkage are ready. Full creation readiness remains **pending only management-token grant/scope confirmation**: Workers Scripts Edit/Write and D1 Edit/Write, with resources restricted to the staging account. The existing read permissions are proven by successful API calls, but successful reads cannot establish write permission. Owner confirmation from the token settings can resolve this without adding broad token-administration access. End-to-end Access authentication remains a post-deployment gate because no origin exists yet.

No resources will be created on the basis of this report. Record the remaining grant/scope confirmation and obtain the user's separate next-step authorization before any creation, migration or deployment instruction is executed.
