# Protected staging activation: execution review contract

## Current approvals (in force)

Work owns delivery through [permanent staging](https://cveharborstage.com) and, for an implementation request, through verified production under the owner's standing authority. Honor an explicit scope limit. Select the supported workflow for each environment and verify all changes included in the release. Work supplies the manual candidate workflow's exact commit, operation pins and recovery evidence. GitHub still enforces its environment reviews.

Verified via GitHub on 2026-11-07: active main ruleset 26584475 requires a PR, resolved
threads and three GitHub Actions checks (application regression, workflow policy, `prepare`).
It blocks deletion and force-push, has no bypass actors, and requires **zero** approving
reviews. CI alone is not independent review. Staging allows only branch `main`, requires
review by **Prat007ai**, permits self-review, and disallows administrator bypass. Work
must not click using the owner's identity. Candidate mode is on; the older simple baseline
lane is off. The review snapshot showed one collaborator (the owner), no enabled routine
flag, and no independent reviewer identity we could verify. Protection settings can change:
inspect them before relying on this process.

Today Work sends the direct run link. The owner opens **Review deployments**, selects
**cloudflare-cvie-staging**, then **Approve and deploy**. This also applies to separately
dispatched protected status checks; use the preflight in the deploy job when appropriate.
Today's manual release and recovery paths remain available under their existing approvals.
The pinned production replica and the customer candidate are different artifacts.
[PR #276](https://github.com/Prat007ai/cveharbor/pull/276) separately addresses the inventory
block in [the last status check](https://github.com/Prat007ai/cveharbor/actions/runs/42402301955);
never bypass inventory or claim the catalogue has passed live based on a preparation run.

## Catalogue-only production releases

For a routine catalogue frontend fix, production can receive the first deployment. Build on the confirmed live site version, prove that only the reviewed assets changed, and run the signed-in save/reload browser tests against those production assets with fictional accounts. Verify the exact merged PR, readiness, prior live version, and protected environment. After publishing, confirm the live version and test the reported interaction through the production site. Keep the previous version for rollback. Staging may receive the same code later using its own bindings, credentials and test data.

For each release, pin its own candidate and production baseline. The publisher for PR #282 admits one changed production asset, `app.js`. Database, backend, security and infrastructure changes use their existing procedures. Copying production records into staging requires a separately reviewed data scope. Use synthetic fixtures for routine tests.

Use the protected catalogue publisher with owner review, main-only deployment and administrator bypass disabled. When the sole owner requests an identified catalogue-only deployment, Work may submit the owner's GitHub deployment approval after checking the run, commit and production scope. Record the delegation in the approval comment and respect any request for the owner to approve personally. Send the run link, monitor publication, verify the live assets and traffic, and record the result on the PR.

## Production website owner approval

The owner authorizes Work to approve reviewed frontend releases on the owner's behalf in the protected production site environment. GitHub permits the sole owner to start and approve the same run. Keep the named reviewer, main-only branch policy, administrator bypass disabled, exact release scope, required CI, live readiness and version verification. Record the delegation and link the run on the feature PR. PR #284 is the first cross-page website fix using this policy. Independent approvals for backend, database, recovery and other infrastructure use their existing protected environments.

## Proposed routine staging operation (inactive)

**Adoption is a separate owner decision after review and merge.** Only then may a repository
administrator set `ROUTINE_STAGING_DELIVERY_ENABLED=true`. Do not set it for this PR.
Leave the candidate mode enabled and simple baseline mode disabled. The first use requires
a separately approved, reconciled baseline deployment at the new procedure's starting
commit; this lane rejects bundled backlog. An expired artifact, rerun, moved main, or
prior partial deployment is not a reason to rebuild or change a pin automatically.

1. Work records the owner's requested outcome, permitted test actions and observable acceptance criteria on the task PR. This workflow handles only staging. After staging verification, follow the supported production procedure if the task includes production.

2. A trusted GitHub reviewer independent of the PR opener, commit authors, committers and the final branch pusher reviews the implementation, entire diff, release
   scope and tests. It submits a formal **Approve** review on the final head before merge
   with a line exactly `Routine staging: approved`, explaining why the change is routine
   and how each criterion will be verified. Work requests review directly on the PR;
   no copying a review between chats. An author comment, two chats using the author's
   login, a dismissed/stale review or a green test is insufficient. Missing GitHub attribution or an ambiguous final push blocks routine delivery. No available
   independent reviewer means **blocked**, not self-approved. Work checks the review and
   required checks before merging the exact reviewed head with a merge commit; update
   the branch and obtain a new review if the merged tree would differ.
3. Work waits for the **main push** runs, then dispatches existing **Permanent staging
   preparation and approved updates** on main with only `candidate_operation=routine-deploy`
   and `routine_pr=<task PR number>`. No per-release environment edits, copied hashes or
   migrations. The gate checks the reviewed merge tree, outstanding reviews, allowed files,
   and the exact three successful jobs from their expected main push workflows. It selects
   the unexpired first-attempt main artifact by ID. The run summary links the review
   and source build. Work gives the owner the direct run link for the single environment
   review described above. The dispatcher rechecks evidence after that click.
4. GitHub downloads the exact previously built package, checks its archive digest,
   source, manifest, schema and asset seal. It checks both Workers are serving the
   reviewed first parent, the permanent database already has the candidate schema, Access
   is intact, and no schedules or external mail are enabled. It deploys the two prebuilt
   Worker modules without rebundling, and the sealed assets, under the existing staging
   lock. It checks the backend, the custom-domain readiness, positive and negative Access,
   authenticated health, JavaScript/CSS bytes and catalogue controls. These last checks
   prove the delivered assets, not a successful signed-in catalogue save.
5. Work reads `customer-candidate-execution` and tests the task's acceptance criteria on
   staging where feasible using the agreed fictional account. Link the specific review,
   run, deployed commit, [staging site](https://cveharborstage.com), checks that passed,
   specific failure or untested criteria in one result on the task. An operator may need
   to complete an interactive Access/MFA step privately. **Keep the task open** until
   acceptance passes. For a failed or uncertain upload, record the failing step and any
   observed Worker versions, reconcile with read-only status, and do not retry or roll
   back automatically. A green deployment does not close the task.

The first routine lane admits only the application files named in
[`routine_review.py`](../../../staging/scripts/routine_review.py), related tests, review
evidence and the generated candidate profile. Unknown paths stop for separate review.
Use the dedicated migration or production workflow for any authorized work outside this staging operation. Obtain an owner decision for a broader release, destructive change, material new cost or change to protections. Keep the routine file allowlist intact.

**Removing the owner's Actions click:** enabling the routine flag does **not** remove it.
The smallest option under GitHub's existing required-reviewer design is for the owner
to explicitly delegate staging environment review to a named, trusted second reviewer.
That reviewer, not Work acting as the owner, would click. This changes who can approve
*every* operation using this environment, including recovery and migrations; do not grant
that broader access just to automate routine releases. To delegate **routine delivery only**,
separately approve a dedicated main-only staging environment with least-privilege deployment
credentials and an independent reviewer (or an enforceable independent deployment protection
rule). Keep today's environment/review on exceptional operations. Verify plan support,
credential scope, reviewer availability, and fail-closed rules before switching. No such
environment, reviewer, app, credentials or protection change is installed by this proposal.
There is no verified zero-click arrangement today.

## Historical candidate activation contract

Status at original review: prepared for review, not enabled or executed. No reset is included.
The build/schema profile and local readiness tests are implemented. The live
workflow adapter remains a review item; this document does not make ordinary
`release` capable of publishing the candidate.

Reuse `.github/workflows/cvie-staging.yml`, its protected
`cloudflare-cvie-staging` environment, existing staging concurrency lock and
existing secrets. No new infrastructure or secret is needed. A future adapter
must use explicit manual dispatch only, with separate migration and deployment
operations and no dispatch default that writes. Do not attach candidate execution
to push, PR, ordinary release, initialization or automatic post-merge execution.

## Fixed targets and artifact contract

- Use `TARGET` and `resources.v1.json`: existing backend
  `cveharbor-accounts-staging`, frontend `cveharbor-site-staging`, database
  `fac61562-fc31-426d-8032-550aba63b7f6`, private staging intelligence bucket and
  `https://cveharborstage.com`. Reject any production/disposable/different target.
- Require the final reviewed full commit SHA, protected-environment approval,
  matching `CF_STAGING_APPROVED_COMMIT`, and an artifact produced by successful
  no-credential CI for that exact revision. Branch names alone are insufficient.
- Verify the candidate-profile digest, source digests, migration checksum,
  exact schema hash, API artifact digest and a digest of the final frontend files.
  Reject stale or mixed artifacts. Rebuild after source changes, never substitute
  a candidate manifest into the ordinary baseline output folder.
- Keep candidate output isolated under `.build/customer-remediation-candidate/`.
  Existing baseline config validation rejects these paths/profile; add reviewed
  candidate-specific validation, rather than broadening the baseline allowlist.

## Required ordered gates

| Phase | Reuse / required evidence | Stop condition |
| --- | --- | --- |
| Read-only preflight | Existing `preflight`, inventory and Worker diagnosis; sanitized current versions, Access service-token policy checks, private R2 and domain ownership | Any unknown target, policy/configuration mismatch or credential scope failure |
| Migration approval | Exact SQL checksum, target DB, recovery evidence, approved write window and no active writes | Missing independent authorization, schema drift, partial objects or failed FK check |
| Migration operation | Apply only the approved additive SQL once; no initialization, reset, backfill or unrelated migration | Any unexpected write/schema result; no automatic retry of uncertain writes |
| Migration evidence | All 143 original app objects plus support schema unchanged, unchanged existing rows/counts/history, empty new tables, exact extended schema and FK check | Any mismatch; deployment remains blocked |
| Separate deployment approval | Exact candidate commit/profile and successful migration evidence | Approval for a different commit or SQL is insufficient |
| Both Worker dry runs | Candidate-specific configs validated against the same existing security/resource constraints | Any new binding, exposure, schedule or target |
| Backend upload and readiness | Upload once, inspect version/configuration, authenticated legacy frontend probe, exact release **and candidate profile**, full schema, R2, captured mail, MFA and monitoring | Fail immediately except existing bounded retry for healthy HTTP 200 with stale release identity |
| Frontend upload and final probes | Upload only after backend ready; inspect version; custom-domain runtime and existing Access negative/positive probes | Any failure; preserve failure stage/version evidence, no automatic redeploy/rollback |
| Acceptance | Fictional customers/assets, independent same-CVE records, refresh, assignment receipts, history, isolation, MFA | Capture only safe booleans/statuses in shared artifacts |

Never catch schema/readiness rejection and route through generic `migrate` or
`initialize`. Production-baseline readiness will reject an extended schema;
coordinate the separately approved migration/deployment window and prevent
ordinary baseline releases during it. Review an interrupted-activation recovery
plan before that window. After candidate writes, retain compatible readers and
prefer a forward fix; dropping scope/history tables is not a safe rollback.

The owner's next approval is review of this draft design/code and the protected
adapter implementation before it is enabled. That review is not authorization to
apply the migration or upload either Worker. Those remain separate later approvals.
