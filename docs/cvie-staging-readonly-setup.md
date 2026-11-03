# Automatic staging diagnostics: setup and trust boundary

Implementation is prepared in PR #243. Cloudflare resources and GitHub administration settings have not been changed. Keep the PR draft and unmerged. Do not retry run #7 or approve its deployment while configuring diagnostics.

## Why a separate trusted workflow is required

An approval-free GitHub environment restricted to the development branch would expose its static secret to any workflow edited on that branch. Pinning a script inside an otherwise editable development workflow does not fix that. The environment's server-enforced branch restriction is essential.

`.github/workflows/cvie-staging-diagnostics.yml` must be installed on the protected default branch (`main`) through a separately reviewed, workflow-only change. GitHub loads a `workflow_run` listener from the default branch. It listens for completed staging preparation/provisioning runs on `codex/cvie-core-phase012`, checks repository/branch/path/event provenance, and also supports manual dispatch from `main`. It does not run on pull requests, forks, or development-branch dispatches. Source-run failures and cancellations still trigger inspection.

The job checks out only the immutable reviewed snapshot `d43139fdee1192a655e8103c85c14f1a892b2544`. This pins the diagnostic entrypoint and all imported scripts, target definitions and configuration templates. Checkout, Node setup and artifact upload actions are pinned to full SHAs. No source-run artifacts, caches, package installs, application builds, SQL, Wrangler, development files or input-provided commands execute in the credential-bearing job. The only secret is step-scoped `CF_STAGING_READONLY_API_TOKEN`, mapped to the pinned helper's existing token variable. No application sessions or Access service credentials are used.

Every management call is GET to the fixed dedicated staging account. Diagnostics inspect existing database metadata and the two exact Worker names, including bindings, flags, public exposure, schedules, assets gating and deployment presence. They record sanitized booleans/counts rather than raw settings. A completed inventory is evidence, not permission to deploy, and mismatches still need analysis. Diagnostics never create resources, run SQL, migrate, delete, alter configuration, upload Workers, send email or invoke scheduled work.

The development workflow no longer has a credential-check job using the write-capable environment. Its existing protected provisioning job, exact SHA/operation gates and account guards remain. Write serialization moves to that job using the same `cvie-staging-243` concurrency group. Credential-free preparation is no longer held up by an old environment approval. The read-only workflow has a separate concurrency group.

## One-time trusted activation

Perform these steps in order. Do not add the secret before the trust restrictions exist.

1. Require reviewed pull requests for **all** changes to `main`; prohibit direct/force pushes, deletion and unreviewed bypasses. Restrict administrative bypass to trusted account administrators. Require review of workflow changes and diagnostic pin updates. An unreviewed main-branch writer could otherwise create another workflow that consumes the environment secret. Repository administrators remain trusted principals.
2. Review and install **only** `.github/workflows/cvie-staging-diagnostics.yml` on `main` through a narrow change. Do not merge PR #243 or copy application/deployment changes onto `main`. Review any repository workflows that this narrow change would trigger before installing it. This activation has not been executed here. Until installed on the default branch, GitHub will not register the automatic listener.
3. Create GitHub environment **`cloudflare-cvie-staging-readonly`**. Set **Deployment branches and tags → Selected branches and tags → Branch `main` only**. Do not allow the development branch, PR refs, wildcards, or tags. Do not select “all branches” or “protected branches.” Keep required reviewers and wait timers disabled in this read-only environment.
4. Create and install the separate Cloudflare token as described below, as an **environment secret only**. Do not place it in repository/organization secrets, files, variables, workflow inputs, artifacts or chat. Do not copy the provisioning token into this environment.
5. Retain the existing `cloudflare-cvie-staging` environment's required reviewer, branch restrictions and no-bypass protections. Keep its write token and Access service credentials there. Do not remove approval from that environment.
6. Run **CVIE trusted staging diagnostics (read only)** via workflow dispatch on `main` for the initial check. Subsequent completed staging runs trigger it automatically. GitHub's environment UI may call this a deployment, but the job performs GET-only inspection. No deployment approval is needed for this new environment.
7. Review the `cvie-staging-readonly-<run-id>-<attempt>` artifact and confirm the staging account, expected database and Worker presence. Codex can then inspect logs/artifacts, determine partial creation and prepare the targeted fix. A later Worker upload still requires separate approval through the protected workflow.

The connected GitHub integration does not provide environment/secret administration. Its branch-protection read returned 403, so existing default-branch protections are **not independently verified**. An administrator must configure/confirm those controls and securely install the token. This is one-time security setup, not a recurring troubleshooting step. This implementation does not silently weaken protections or claim the environment already exists.

## Create the restricted Cloudflare token

In Cloudflare's API token settings, create a custom token named **`cvie-staging-diagnostics-readonly`**. Do not edit or reuse the deployment token.

Required account permissions for the pinned diagnostic:

| Permission | Access |
|---|---|
| Account Settings | Read |
| Workers Scripts | Read |
| D1 | Read |

**Account resources: Include → Specific account → CVEHarbor Staging**, ID `9706b4d98ad72884e67fd1eb875c8a61`. Apply this exact resource restriction to every permission policy. No other account, zone, “all accounts,” Write/Edit grant, API-token-management grant or production resource is permitted. Choose a suitable expiry and rotate through the same reviewed setup when necessary. Do not restrict client IPs to an unstable GitHub-hosted runner address.

The earlier proposed Access Apps and Policies Read and Access Service Tokens Read grants are not required by this pinned inventory helper; leave them off for least privilege. Adding future Access metadata checks requires a reviewed diagnostic snapshot and only the corresponding **Read** grants scoped to this same staging account. No extra Access service token or application-secret installation is needed for the current inventory.

Store the token value once as environment secret **`CF_STAGING_READONLY_API_TOKEN`** in `cloudflare-cvie-staging-readonly`. Manually verify its exact scope and absence of write permissions in Cloudflare; metadata reads may be forbidden. Never prove read-only access with a write attempt. GitHub does not allow stored secret values to be read back.

The workflow pins the non-secret staging account, database UUID `fac61562-fc31-426d-8032-550aba63b7f6`, existing Access issuer and application AUD. No additional GitHub variables are required, and it cannot substitute production targets through a dispatch input.

## Updating trusted diagnostics

Development-branch edits cannot update executable diagnostic code. After reviewing and testing a new diagnostic snapshot, update the full checkout SHA in the protected default-branch workflow through review. Do not replace it with a branch name, a triggering run's SHA or an environment variable. Changes to approved targets likewise require review. Keep production-read baseline suppression in PR #243 intact.

## Current deployment investigation

Run #7 attempt 3 discarded the underlying cloud-operation exception. Its historical preflight verified zero Workers and the existing configured database before provisioning; that does not establish current partial-resource state. PR #243 already contains sanitized operation/category reporting and mocked read-only inventory tests. The root cause remains unconfirmed pending fresh staging evidence. No Worker retry, migration, data import, resource change, email, scheduled scan or production access is authorized by this setup.
