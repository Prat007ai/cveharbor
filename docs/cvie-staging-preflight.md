# Task 2C: Read-only staging preflight results

**Outcome: checks completed; resource-creation readiness is not yet fully verified. No Cloudflare resources were created or deployed.**

Latest remote check: **2 November 2026, 8:49:33 p.m. America/Toronto** (3 November 2026, 01:49:33 UTC). Executed in the protected GitHub environment `cloudflare-cvie-staging` on the existing PR #243 branch, at commit `0a67b71cd71c616a9881a2df7d72c46f2853fa27`.

[Latest workflow evidence](https://github.com/Prat007ai/cveharbor/actions/runs/41562186396) · [Sanitized machine-readable results](cvie-evidence/staging-preflight.json)

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
| Policy exposure | Exactly the two expected policies; no Bypass, Everyone or additional allow policy |
| Access issuer | Signing-key endpoint reachable and returns RSA signing keys |
| GitHub credential availability | Management token and both Access service credential values were present in the protected job; no values were printed or exported |

No existing Worker bindings could be checked remotely because no Workers exist yet. Worker configuration, email/schedule guards, production-ID rejection and same-origin routing were verified locally, including the existing staging tests. These are preparation safeguards, not claims about a deployed environment.

## Remaining verification gaps

### 1. Management-token write grants and exact resource scope

Both account-token and user-token detail endpoints returned **HTTP 403**. The token is active and can read the selected staging account, Workers/D1 inventories and Access policies. That does **not** prove Workers Scripts Edit or D1 Edit, or reveal the complete resource-scope policy.

This is a metadata visibility gap, not evidence that the deployment permissions are missing. No create/update request was used as a permission probe, and no production-access probe was performed. The account verification endpoint alone is also not treated as independent proof of the token's ownership type.

**Owner action:** review the token in Cloudflare and confirm that Workers Scripts Edit/Write and D1 Edit/Write are granted, with account resources restricted exclusively to `9706b4d98ad72884e67fd1eb875c8a61`. Retain Account Settings Read and Access Apps and Policies Read. A confirmation or redacted permission/scope description is sufficient; do not share the token. Broad user-level token-administration permissions are not necessary simply to finish this review. Such a manual confirmation would be identified as owner-attested evidence, not an API measurement.

### 2. Access service-token metadata/linkage

The service-token listing returned HTTP 200 but no visible entries. A bounded direct GET of the token referenced by the Service Auth policy returned **HTTP 403**. Consequently, the check cannot confirm that the GitHub Client ID belongs to `cvie-staging-validation`, that this token is the policy's referenced token, or that it remains enabled/unexpired.

**This is not a confirmed wrong Client ID, missing token or invalid secret.** The current credential cannot inspect the referenced record. The earlier initial result did not distinguish that limitation; the targeted follow-up does.

**Owner action:** add **Account → Access: Service Tokens → Read** to the staging management API token, keeping its account scope staging-only. This is distinct from Access Apps and Policies Read. If a new token value must be issued, update only `CF_STAGING_API_TOKEN` in the protected GitHub environment. Alternatively, the owner can verify the service-token name, selected policy and GitHub Client ID correspondence manually; no secret values should be supplied in chat. Cloudflare lists the required permission for the [service-token read endpoint](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/service_tokens/methods/get/).

The initial setup guide did not require Service Tokens Read; that additional read permission is needed for this deeper linkage verification. No Access edit permission is requested.

### 3. End-to-end Access authentication is deferred

The authenticated GET to the approved staging URL returned **404**, without a verifiable Access JWT. With zero Workers deployed, this cannot validate or invalidate the service secret. Actual Access challenges, valid service-token access and denial of unauthorized requests must be tested after the first separately authorized Worker deployment. This deferred test is not, by itself, a reason to rotate credentials or change policies.

## Isolation and execution evidence

- All management requests were fixed to the staging account, except read-only introspection of the current token itself through Cloudflare's documented user-token endpoint. No production account or D1 queries were made.
- The latest run made **13 GET requests**. Two earlier targeted passes made 11 and 12 GET requests respectively. There were **zero mutating Cloudflare requests** across these checks.
- No D1 SQL was executed; no migrations, fixture writes, historical scans or load tests ran. Database row-usage measurements were not part of this control-plane preflight.
- The credential-check job contains only the read-only diagnostic script. It imports neither a deployment executor nor a migration runner. It writes only sanitized local evidence and an Actions artifact.
- Secret values, JWTs, policy email addresses and service-token identifiers are excluded from the evidence. The service secret is sent only to the approved staging hostname; redirects are not followed.
- The existing production read-only baseline job remains excluded for PR #243. Production deployment jobs remain excluded from branch/PR execution. PR #243 remains draft and unmerged.
- A marked branch commit triggers the requested protected check because the new workflow is not merged into main for manual dispatch. It does not bypass GitHub environment protections. Ordinary unmarked pushes run preparation only, with no staging credential check.

The workflow is green because the diagnostics executed successfully and the account/application checks passed. **That green result is not a resource-creation signoff:** the JSON explicitly records `ready_for_creation: false`, with permission and service-token linkage limitations.

## Readiness decision

The account, names, subdomain and Access policy structure are ready. Full creation readiness remains **pending the token-grant/scope confirmation and service-token linkage verification above**. End-to-end Access authentication will remain a post-deployment gate because no origin exists yet.

No resources will be created on the basis of this report. Once those gaps are resolved, repeat the same read-only check and report its result before any creation, migration or deployment instruction is executed.
