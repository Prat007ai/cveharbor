> Feed implementation update: see [intelligence-publication.md](intelligence-publication.md) for the implemented replacement, integration results and required staged cutover. Earlier cache/integration findings below are historical.

# Phase 1 security transition: continuity, administrator checklist and PR integration

Reviewed 2026-11-03. This document supersedes the rollout sequence in the earlier
[security configuration plan](phase1-security-configuration.md), which did not account for all feed consumers.

**Do not merge PR #253 in its current form.** Its default-off gate stops hourly collection as well as
publication. Removing the feed commits also leaves the deployed digest reader using stale data on `main`,
even after frontend publication is enabled. Keep both #251 and #253 draft until the feed handoff and
workflow integration described here are prepared, tested and approved. The running application and feeds
were not changed by this review.

## Verified evidence and limits

| Item | Observed result |
| --- | --- |
| Current production source examined | `main` at `710e1200d78a5eac4fdc2dc5f2ef742cca6286b4`. Since #253's baseline, only 16 public feed/export files changed. |
| Current feed activity | Scheduled run [41670067035](https://github.com/Prat007ai/cveharbor/actions/runs/41670067035) succeeded. Committed feed health reports `mode=live`, 5,000 indexed records, last successful collection `2026-11-03T16:03:01Z`. This is collection/run evidence, not an independent observation of every live endpoint. |
| GitHub schedule | The only `schedule` trigger in current main's workflows is `bootstrap.yml`, `17 * * * *` UTC. Actual starts can be delayed; the observed run started at 16:02 UTC. GitHub scheduling is not a precise hourly SLA. |
| PR revisions | #251: `d791cb8e84f85f980926dd1e1acfd0b369c64b46`; #253 reviewed: `7dd0e8a8633674065bd0a607240b04e66872090e`. Both are draft. |
| Main enforcement | `protected=false`, no repository rulesets. Enforced PR review/status checks are not currently established. |
| Plan | Public personal repository verified. The connected profile does **not** expose billing plan. Paid/free/legacy plan status is unverified. Public-repository availability is supported by GitHub's published documentation; actual configured enforcement still needs inspection. |
| Current secret locations | **Unknown.** This turn's environment, Actions-secret and workflow-permission metadata requests were rejected by the connector's endpoint allowlist. The managed CLI network policy still excludes GitHub API/Cloudflare API; no bypass was attempted. |
| Historical credential access | [Run 41343168193](https://github.com/Prat007ai/cveharbor/actions/runs/41343168193), Nov 1, succeeded at the remote 0022 migration and D1-query steps on a feature branch. Its [exact workflow](https://github.com/Prat007ai/cveharbor/blob/04cce7a3de622f078423bc74c0ffd536ac08bc63/.github/workflows/verify-cvie-d1.yml) references `secrets.CLOUDFLARE_API_TOKEN` with **no environment**. Production-capable access outside an environment is historical fact; current availability is not verified. In this personal repository this is strong evidence of a repository-level secret at that time, not proof it still exists today. |
| Staging evidence | Latest inspected [CVIE staging run 41670613461](https://github.com/Prat007ai/cveharbor/actions/runs/41670613461) passed preparation, but credential checking and provisioning were **skipped**. Earlier [run 41659896789](https://github.com/Prat007ai/cveharbor/actions/runs/41659896789) failed its credential/Access check; provisioning was skipped. Neither establishes live staging readiness. |

The prior source inventory covered 263 heads/146 workflow versions; it is a dated snapshot, not a claim
that no branch has changed since. The active CVIE staging branch has advanced since that inventory.
No full run logs, secret values, customer records or production database contents were needed for this review.

## 1. Exact operational impact of merging the current #253

| Process | Current operation | Current #253 after merge |
| --- | --- | --- |
| Public vulnerability collector | `bootstrap.yml/sync` runs `scripts/update.py`: GitHub advisories, PHP upstream, NVD, CISA KEV, MSRC, Fortinet, Ubuntu, Debian, Docker, Kubernetes, MariaDB, Red Hat and EPSS enrichment. | Entire job is skipped unless repository variable `PRODUCTION_DEPLOYMENTS_ENABLED=true`; with environment reviewers it waits for approval before collection starts. |
| Optional/retired adapters | Wordfence requires explicit `WORDFENCE_FETCH_ENABLED=true` and a daily rate limit; merely having a key does not activate it. OSV helper code exists but is not in the current active operation list. | No adapter should be newly enabled during security configuration. Preserve current opt-ins/rate limits. |
| Malware intelligence | Same job runs MalwareBazaar and CISA advisory collection. | Stops with `sync`. Existing published snapshot remains visible. |
| Threat/IP intelligence | Same job collects DShield, blocklist.de, GreenSnow, Feodo, ThreatFox, Spamhaus and geolocation enrichment; generates firewall exports and historical state. | Stops with `sync`; cache-only persistence changes how history survives runs and must not be treated as durable storage. |
| Lifecycle and patch notes | Same job generates `lifecycle.js` from endoflife.date and `patch-notes.js` from vendor releases/SQL updates. | Stops with `sync`. These two outputs are also **outside** the proposed 16-file checkpoint, which is saved before their generation. A complete new handoff must cover them. |
| Frontend/site Worker | Same job builds the site and deploys `cveharbor-site` with static assets, checks live pages and can retire the old Pages origin. | No new publication while gated/waiting. The existing Worker/site continues serving its last deployment; data freshness degrades. |
| Public feed commits | Hourly job directly pushes 16 generated files to `main`. | Replaced by cache/artifact; `main/data.js` and `main/data/feed-health.json` no longer advance. |
| Vulnerability digests and test-digest previews | `digest.js` reads those **raw GitHub main files**; `delivery.js` loads that feed before merging CVIE results. | Inputs become stale even if the site later publishes. `loadPublicFeed` rejects snapshots older than **8 hours**; enabled digests/test previews can fail. Continuing the Worker cron alone does not preserve this feature. |
| Lifecycle email | `lifecycle.js` reads site `/lifecycle.js` and `/patch-notes.js`. | Old frontend data can suppress delivery. Lifecycle snapshots older than **3 days** are rejected; stale vendor notes are discarded. Applies when runtime delivery flags/subscriptions enable it. |
| Backend deploys | `deploy-worker-code.yml` runs on backend-related main pushes or manual dispatch; `deploy-account-worker.yml` performs manually approved legacy migration/deploy operations. | Default-off gate and main/environment controls stop new deployments until approved. Currently deployed account APIs keep running. |
| Legacy activation workflows | `activate-confirmation-domain.yml` on selected main pushes; six other `activate-*` workflows manually apply schema changes. | Gated/main-only. No automatic feature activation or schema modification from this review. |
| Live diagnostic jobs | D1 checks, site gate and live UI tests run automatically on various branches/pushes. | Live checks move to manual main-only audit environment; local regression/provider checks remain. Losing an automatic diagnostic does not stop the runtime service it observes. |
| Test-email workflow | Feature-branch push could invoke `test-product-monitoring-email.yml`. | Becomes manual/protected/default-off. This does not disable normal runtime notification delivery. |
| Source restore/evidence commits | Restore and several verification jobs push source/evidence. | Artifacts for review replace pushes; source restore requires a reviewed PR. |
| Pages retirement | `retire-public-site-origin.yml` and the bootstrap retirement job can publish a notice. | Gated. Existing DNS/routes/Pages state are not changed by merging YAML alone. |

Cloudflare Worker schedules are separate from GitHub Actions. The checked-in account Worker declares:

- `* * * * *`: status email queue, progress/inactivity/FYI work, evidence dispatch, existing approved-test
  handler and conditionally product-monitor mail.
- `*/5 * * * *`: CVIE dispatch.
- `5 * * * *`: digest, lifecycle, product/plugin/website monitoring according to their runtime flags.

#253 does not deploy or change those handlers, cron bindings, SMTP runtime secrets or flags. Assignment
creation, acknowledgement/reviewer links, inventory, status updates, ticket references and stored history
remain on the existing API/database. This does **not** establish that every optional job is enabled in
production, nor eliminate the digest/lifecycle feed dependencies above. Do not rotate Worker signing/session
keys or apply a recovery hold as part of routine security configuration.

## 2. Maintaining feed updates during the transition

**Preparation period:** leave the currently working collection/publication path and its credentials intact.
Prepare unused environments, inspect metadata and validate staging. Do not yet enforce a rule that blocks
the old updater's direct push, require approvals on its existing environment, or delete its credentials.
Those actions would affect the active hourly job before its replacement exists. This is a temporary
continuity decision: current legacy credential exposure remains a risk until cutover; avoid operating
legacy production-capable feature workflows during this period.

**Recommended target:** separate routine public-data refresh from application deployment. The automatic
publisher should have access only to a dedicated public-feed store, not repository code, D1, Worker
deployment or DNS. A dedicated R2 bucket with a bucket-scoped object credential is one candidate, subject
to approval and verification of the actual Cloudflare token policy. Store validated JSON, not executable
HTML/JS; publish a versioned manifest/checksums atomically, retain the last good version and complete
historical state. The reviewed site/API readers must consume that feed while preserving current formats,
freshness limits, authentication boundaries and notification behavior. Application deployments still use
independent approvals; routine data writes use explicitly approved automation with a main-only environment.
Do not label the current full Worker deployment command a “data-only publisher.”

Prepare this compatibility work within the existing drafts, not another PR:

1. Inventory all consumers and outputs, including the two digest URLs, lifecycle/patch readers, malware,
   threat history, geolocation state and firewall exports. Choose the approved feed location and access model.
2. Implement a credential-free/local synthetic publisher/reader rehearsal, schema/size checks, atomic version
   selection and failure rollback. No public URLs, DNS, runtime credentials or production storage change yet.
3. With separate approval, establish the isolated target and dual-publish while the old committed/site feed
   remains authoritative. Verify at least two successive collection cycles and failure recovery. An Actions
   cache/artifact alone is not a replacement endpoint for an already deployed reader.
4. Deploy/activate compatible readers only with explicit approval; confirm published, digest and lifecycle
   timestamps advance from the intended source. Keep the old source current during the validation window.
5. Only then stop legacy main feed commits, activate main/environment restrictions, and retire old GitHub
   credential locations after verifying the new path. Normal code deployments can remain held while
   intelligence refresh continues. Recheck first automatic cycles after the cutover.

**Alternative temporary bridge:** a staffed, reviewed feed-only PR process could keep the existing `main`
URLs current, with CI and independent approvals for each update. This requires a reviewed automation identity
and operator coverage; it is not unattended and cannot guarantee unchanged cadence. Do not grant a broad
bot bypass or auto-approve its PRs. It is not the preferred solution to your no-interruption requirement.

There is currently no tested uninterrupted handoff in #253. Until it exists, the safe action is **no merge
and no disruptive security cutover**. Required per-run human approval and fully unattended hourly execution
cannot both apply to the same publishing job. The data/deployment separation resolves that conflict; removing
reviews from the current all-powerful site deployment job does not.

## 3. Administrator checklist — GitHub

The following are instructions for your authorized administrator session, not actions already performed.
Prepare settings first; activate production-affecting controls only at the approved cutover.

### G1 — Verify plan and current settings (read-only; do now)

- [ ] **Account avatar → Settings → Billing & licensing → Overview** (wording may be Billing and plans): record
  the plan name. Repository **Settings → General**: verify visibility remains public.
- [ ] Run the supplied GET-only metadata helper from an existing authenticated administrator checkout:

  ```sh
  python scripts/audit_github_security_metadata.py > github-security-metadata.json
  ```

  It lists secret **names/locations**, plan name if exposed, main protection, rulesets, environment reviewers,
  allowed refs and Actions permissions. It never reads decrypted values, dispatches jobs or modifies settings.
  Missing/403 data remains explicitly unknown. Do not export tokens or run `gh auth token` to share credentials.
  If the script is not yet in your local checkout, obtain it from the reviewed #253 revision.
- [ ] If CLI access is unavailable, inspect **Settings → Secrets and variables → Actions**, **Settings →
  Environments**, **Settings → Rules**, and **Settings → Actions → General** manually. Record names and controls,
  not values. The repository is personal; organization-secret inheritance is not presently applicable.

**Plan support, not an enforcement claim:** GitHub documents branch protection and branch/tag rulesets for
public repositories on Free and Pro. Environments, environment secrets, deployment branch restrictions and
required reviewers are available for public repositories on current plans; legacy Bronze/Silver/Gold plans
are excluded. Thus no paid upgrade is indicated solely by this repository being personal/public, but the
actual plan and visible controls must be verified. Do not assume organization-only controls are available:
classic “Restrict who can push” actor lists and organization rules/teams are not the personal-repository plan.
Full-SHA Action pinning is implemented in source/CI; do not assume an organization-level enforcement toggle exists.

### G2 — Establish independent review (prepare now)

- [ ] **Settings → Collaborators**: identify/invite a trusted independent human with write access for PR review.
  Personal repositories use individual collaborators, not organization teams.
- [ ] Both current PRs are authored as `Prat007ai`. GitHub will not let you approve your own PR. A second
  eligible reviewer is required to enforce one independent approval; upgrading a plan does not change this.
- [ ] Environment reviewers need at least read access; enabling **Prevent self-review** means the deployment
  initiator cannot approve that run. One of the listed reviewers can approve; the list is not a quorum.
- [ ] If you are the only eligible person, record this as a blocker. Do not silently set approvals to zero or
  use a second account controlled by the same person to represent independent review.

### G3 — Main ruleset (prepare; activate only after feed handoff)

- [ ] **Settings → Rules → Rulesets → New branch ruleset**, target **`main`** explicitly. Prepare it disabled;
  set enforcement to **Active** only at the approved cutover. Do not mistake a disabled rule for protection.
- [ ] Require PR; **1 independent approval**; dismiss stale approvals; require approval of the most recent
  reviewable push; resolve review conversations; require code-owner review after valid owners are configured.
- [ ] Require **`Security / workflow policy`** and **`CI / application regression`** from GitHub Actions;
  require up-to-date branches. These jobs have no path filters. Do not require a generic `verify`, a skipped
  deployment, or a production deployment to succeed before merging. Do not enable merge queue without
  adding/testing `merge_group` validation first.
- [ ] Block force pushes and deletion; no admin/updater bypass. Configure `.github/CODEOWNERS` by reviewed
  source change using actual eligible collaborators, covering workflows, deployment scripts, backend/schema,
  site gate and security tests. Keep API/admin authority distinct from an active rule's bypass permissions.
- [ ] **Settings → Actions → General**: choose read-only default workflow permissions; disable Actions
  creating/approving PRs unless an explicitly approved bridge needs it; review allowed Actions. Do not enable
  fork access to write tokens/secrets. The workflow's explicit permissions and external API token scopes
  still matter after setting the default to read-only.
- [ ] Expected result: API reports main protected and active applicable rules; an unapproved PR is blocked,
  required CI checks are identified unambiguously and no workflow identity can bypass review. Validate using
  an approved harmless test setup/negative check, not a direct push of application code to production main.

### G4 — Environments (new unused ones can be prepared; existing active ones require cutover timing)

For `cloudflare-worker-production`, `cloudflare-site-production`, `github-pages`,
`cloudflare-production-audit`, `cloudflare-notifications-production` and `cloudflare-phase1-staging`:

- [ ] **Settings → Environments → name → Deployment branches and tags**: selected **branch `main` only**;
  no tags, wildcards or `refs/pull/*/merge`. “Protected branches only” permits all branches when none is protected.
- [ ] Configure required independent reviewers, **Prevent self-review**, and **disallow administrator bypass**
  where the actual UI/plan supports it; then inspect saved metadata. Do not claim enforcement from YAML alone.
- [ ] Review run SHA, event and operation before approval. Reject historical reruns and stale commits. Branch
  restrictions match the run ref, not a later `checkout` ref; checking out a good SHA does not rescue an unsafe run.
- [ ] Keep `PRODUCTION_DEPLOYMENTS_ENABLED` and `PRODUCTION_EMAIL_TESTS_ENABLED` absent/false for this draft.
  Do not turn on the shared deployment flag to restore feeds; the current main Worker classifier still needs
  #251's fixes. Proposed future data refresh must use its own narrowly authorized path, not this flag.
- [ ] Do not apply blanket main-only rules to the independent existing CVIE staging environments without
  reviewing their branch-specific design. They must have staging-only credentials; preserve that experiment.

### G5 — Credential cutover (approval required; do not remove anything during inventory)

| Current referenced names | Current location | Proposed environment/name |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID` | Live metadata unknown; historical environment-free production use confirmed | Worker: `CVEHARBOR_PROD_WORKER_TOKEN`, `CVEHARBOR_PROD_ACCOUNT_ID`; audit uses its separate names below |
| `CLOUDFLARE_SITE_API_TOKEN` (or old backend-token fallback) | Unknown | Site: `CVEHARBOR_PROD_SITE_TOKEN`, `CVEHARBOR_PROD_ACCOUNT_ID` |
| `SITE_GATE_PASSWORD` | Unknown | Site, optional live audit and Pages checks: `CVEHARBOR_SITE_GATE_PASSWORD` in each required environment |
| `SMTP2GO_API_KEY`, `ALERT_SMTP2GO_API_KEY` in Actions | Unknown; do not confuse with deployed Worker secrets | Optional test-email environment: `CVEHARBOR_PROD_SMTP2GO_API_KEY`; leave test opt-in off |
| `CLOUDFLARE_AUDIT_API_TOKEN`, `CLOUDFLARE_AUDIT_ACCOUNT_ID` | Proposed; existence unverified | `cloudflare-production-audit`, fixed SELECT-only commands |
| `CLOUDFLARE_STAGING_API_TOKEN`, `CLOUDFLARE_STAGING_ACCOUNT_ID` | Proposed; existence unverified | `cloudflare-phase1-staging`, separate account only |
| `NVD_API_KEY`, `WORDFENCE_API_KEY`, `MALWAREBAZAAR_API_KEY`, `THREATFOX_AUTH_KEY` | Unknown | Keep current feed access working; map every caller before relocation. They are provider keys, not Cloudflare deployment credentials. Preserve Wordfence's disabled-by-default behavior. |
| `CF_STAGING_*` | Referenced by the independent CVIE staging project; live locations/scope unknown | Preserve separately; verify before considering account reuse. |

Safest sequence after the feed-compatible implementation is ready:

1. Record every secret location and consumer, including all old environment duplicates and queued/running
   workflows. New names do not revoke old credentials. GitHub's environment secret overrides a same-named
   repository secret only for jobs using that environment; other jobs can still use the repository copy.
2. With approval, populate unused protected environments from the original secure secret source. GitHub cannot
   reveal an existing value for copying. If it is unavailable, request separate approval to reissue/rotate;
   do not invent a replacement or ask for values in chat.
3. Check token account/resources/permissions through Cloudflare's secure UI. A site token without D1 permission
   is not automatically harmless: an account-wide Workers Scripts Edit token may still alter a Worker with a
   D1 binding. Verify the actual permission boundary; the future feed-only credential must lack Worker/D1/DNS access.
4. Test credential presence and permitted read-only metadata paths, then validate synthetic targets. Do not run
   a deployment, migration or real email merely to “test credentials.” D1 query access may require broader
   permission than metadata reads; a SELECT-only script does not make the token itself SELECT-only.
5. At the explicitly approved cutover, let an active legitimate publisher finish; prevent new legacy writers
   and review stale queued runs. Do not cancel a live migration blindly. Switch the validated publisher/readers,
   activate protections, and verify current feed consumers before retiring legacy secret locations.
6. Remove old repository/environment copies only after approval and verified replacement. Keep their original
   secure source for the approved recovery procedure; do not leave GitHub fallback copies accessible to old
   workflows. Never change Worker SMTP bindings, receipt/session/signing keys or account data in this operation.

## 4. Administrator checklist — Cloudflare staging

- [ ] Inspect the account referenced by the independent CVIE staging source:
  `9706b4d98ad72884e67fd1eb875c8a61`. Its configuration names `cveharbor-accounts-staging` and
  `cveharbor-site-staging`; a diagnostic configuration references D1 UUID
  `fac61562-fc31-426d-8032-550aba63b7f6`. These are public configuration identifiers, not verified live resources.
- [ ] In the authorized Cloudflare dashboard confirm account ownership/membership, separation from production,
  the existing database's purpose, bindings and current access. **Account reuse may be suitable; database reuse
  is not approved.** Do not alter the CVIE database, its Access application, routes, tokens or Workers.
- [ ] After authorization for staging resource creation: in that separate account, **Storage & databases →
  D1 → Create database**, name `cveharbor-phase1-staging` (or an approved suffixed variant). Use a new empty
  database, no production clone/customer data and no binding to a production Worker. Record UUID and name.
- [ ] In **My Profile → API Tokens → Create Custom Token**, scope D1 permissions to **only that staging account**;
  never All accounts. Use only permissions needed for synthetic schema/query writes. If per-database scoping
  is unavailable, the separate account is the security boundary. No production account, Workers, DNS or SMTP permissions.
- [ ] Configure GitHub **`cloudflare-phase1-staging`** with the two staging secrets listed above and environment
  variables `STAGING_DATABASE_ID`, `STAGING_DATABASE_NAME`, `STAGING_DISPOSABLE=true`, and
  `PRODUCTION_ACCOUNT_ID` (verified identifier used to reject same-account mistakes). No generic production-token fallback.
- [ ] Expected result: stage/prod account IDs differ; stage UUID differs from production
  `46710e51-7ca4-4571-b89c-921b9969de0b`; remote metadata name/UUID match; token policy excludes production;
  bootstrap sees an empty database. IDs alone do not prove token permissions.

The Phase 1 D1 harness does not require a hosted staging Worker, DNS, Cloudflare Access app or an SMTP key.
It invokes actual handlers with synthetic fixtures and intercepts advisory/email calls. The unrelated CVIE
staging Access-check failure is not a reason to modify that environment or add production credentials here.
No Cloudflare resource was created or changed during this review.

## 5. PR #251 / #253 integration findings and order

The [machine-readable rehearsal results](phase1-integration-rehearsal.json) record a local three-way merge using GitHub's common ancestor
`1cc762663b1fd176041f37b5512f8e802403b880`. No remote branches were merged/rebased.

| Overlap / additional file | Finding | Required resolution |
| --- | --- | --- |
| `verify-assignment-acknowledgement.yml` | Text conflict | Keep #251's Phase 1 tests/browser checks and #253's pinned Actions, token settings and job names. |
| `verify-cvie-d1.yml` | Two text conflicts | Keep #253's removal of production access from development checks. Do not restore old branch D1 operations just to retain #251's hold/guard steps. Hold/guard handling belongs in explicitly approved production release paths. |
| `deploy-worker-code.yml` | Text merges, but produces a **duplicate job `if` key** and old secret references in new steps | Combine conditions once; retain main/approval controls, safe manual release classification, 0031/0032 verification and migration order, backup/recovery point, guard installation, source identity and readiness checks. Map every added step to protected credentials. |
| Seven `activate-*` files and `deploy-account-worker.yml` | Text merges, but #251's added hold/guard steps still use old secret names | Preserve hold and guard refresh; apply #253 names/pins/main restrictions to every step. No repository fallback. |
| `bootstrap.yml` | Text merges and policy passes, but runtime continuity is not solved | Retain #251's backend/schema fingerprint and hold checks plus #253's security boundary. Separate feed refresh from frontend code publishing; remove direct pushes only after readers migrate. |
| #251 `audit-remediation-integrity.yml` and `validate-phase1-d1-staging.yml` | Additional entry points do not meet #253's policy and duplicate its readiness workflows | Consolidate behind one reviewed protected path, including main guards, pinned source/actions, separate-account validation and distinct secrets. Do not leave an older permissive workflow callable. |
| #251 `recovery-write-hold.yml` | Old secret names/actions and incomplete main/event guard | Preserve hold/status/freeze/resume with fresh approval, expected revision and reason. Recovery must remain reachable through an explicitly protected manual path when ordinary deployments are disabled; do not blindly gate emergency resume behind a disabled release switch. |

Twelve workflow files overlap: two have textual conflicts; of the ten that text-merge, eight violate
credential policy and one has invalid duplicate YAML. The remaining one still has feed/runtime concerns.
The three newly added #251 operational workflows also require security-policy integration. A GitHub “clean”
merge indicator is not evidence that the combined release process is safe.

Recommended sequence:

1. Keep both drafts. Finish metadata/plan verification, staging configuration and feed-continuity design.
2. Prepare the feed compatibility and security transition in #253. Rehearse its consumer freshness,
   checkpoints, failure recovery and exact protected-environment behavior; obtain separate cutover approval.
3. Only after the no-interruption path is demonstrated, merge #253 through the configured PR process and
   approved transition. Do not enable backend release just because the security PR merged.
4. Rebase/update #251 onto that reviewed security baseline; resolve the table above explicitly. Run the
   security policy over **all** combined workflows, especially newly added operational files, and rerun
   local preservation/hold tests and synthetic D1 rehearsal. Keep #251 draft until reviewed.
5. Review the final pinned release SHA. The approved eventual order remains: SELECT-only preflight → fresh
   recovery point/backup → intended 0031/0032 migration and guard verification → backend deploy → backend/schema/
   source readiness proof → frontend code publication. If any prerequisite fails, frontend code stays at the
   prior version; the independent feed path must keep its current approved consumers fresh.
6. Keep one non-cancelling production release/recovery concurrency boundary. Do not let old activation/manual
   jobs bypass holds. A genuine recovery freeze deliberately stops affected writes/scheduled database work;
   it is not part of the normal security transition and requires explicit approval.

The existing tests establish local preservation behavior, not current production consistency or a successful
combined release. No record cleanup, status reconciliation, linking, notification replay or schema change was
performed. The final integration must preserve original reviewer links, assignments, acknowledgements,
recipients, tickets and history; these remain acceptance criteria in the rehearsal.

## 6. What can run now, what was changed, and what needs approval

| Category | Tasks / exact expected result |
| --- | --- |
| **Manual GitHub configuration** | Complete G1/G2 now; prepare G3/G4 but time effective changes to the approved handoff; complete G5 only after explicit approval. Return metadata/control confirmation, never secret values. |
| **Manual Cloudflare configuration** | Inspect existing staging/account/token metadata; create/configure the new isolated target only with authorization. Confirm no production access, bindings or data. |
| **Safe changes within existing drafts** | In #253: this corrected impact/checklist, merge-rehearsal evidence, GET-only metadata helper plus tests, and clear merge blockers. Further source-only feed compatibility, CI and conflict resolutions can be prepared here/#251; no additional PR is necessary. This review did not rewrite working release automation or resolve the feed handoff by assumption. |
| **Validation without production modifications** | Source comparison; strict workflow/negative tests; mocked metadata checks; local application tests; authorized metadata reads; SELECT-only production preflight. Synthetic D1 bootstrap/rehearsal writes only the explicitly authorized separate staging database. No live mail or production mutation. |
| **Explicit approval required** | Activate/change security rules, environment permissions, reviewer policies or credentials; create/modify Cloudflare resources; change production feed store/readers/publication; merge either PR; deploy, migrate, take a write hold, cancel an active writer, or change customer data. No Phase 2. |

### Running remote validation without accidentally deploying

New workflow files on a draft branch cannot be assumed dispatchable from GitHub's default branch.
The current readiness jobs are main-only. **Configuring their environments alone does not make them runnable
before #253 merges.** Do not weaken production branch policies or merge either PR just to unlock a button.

Before a safe approved #253 merge, use an already authorized administrator runner with secure credential
injection and the reviewed #251 checkout (`d791cb8e84f85f980926dd1e1acfd0b369c64b46`):

```sh
# In an isolated checkout, with staging-only credentials securely injected:
node scripts/phase1_staging.mjs bootstrap
node scripts/phase1_staging.mjs validate
node scripts/phase1_staging.mjs validate

# In a separate authorized session with the production audit identity:
AUDIT_PHASE=preflight node scripts/audit_phase1.mjs
```

First run the separate-account configuration check from #253 and verify token scope through Cloudflare.
Do not mix staging and production credentials in one shell/session, bootstrap an existing database, or
use the release/migration workflow for an audit. If credentials exist only in GitHub environments and no
approved runner can use them, this execution path remains unavailable until the safe #253 merge or another
separately approved trusted execution arrangement; no secret extraction is authorized.

After the safe approved #253 merge and configured environments, the exact manual workflow names are:

```sh
gh workflow run security-phase1-staging.yml --repo Prat007ai/cveharbor --ref main -f operation=bootstrap
# Wait for approved bootstrap success, then run validate twice, waiting between runs:
gh workflow run security-phase1-staging.yml --repo Prat007ai/cveharbor --ref main -f operation=validate
gh workflow run security-phase1-audit.yml --repo Prat007ai/cveharbor --ref main
```

Require staging `passed=true`, original-link/history preservation, hold/drain/freeze/resume, no real emails,
zero integrity/foreign-key violations. Require production audit zero counts for duplicate findings, invalid
links, status drift, detached assets, invalid retirements, orphan history/assignments/notifications and
foreign-key violations, plus `rows_written=0`. Any inconsistency blocks release; do not auto-correct it.
Both remote Phase 1 checks remain **NOT RUN** here.

## GitHub documentation used to verify feature availability

- [Protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [Deployments and environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- Availability source checked in GitHub's docs repository: `data/reusables/gated-features/protected-branches.md`,
  `repo-rules.md`, and `environments.md`.

Published availability, current billing plan, saved policy configuration, and proven enforcement are four
different checks. Only public/personal repository status, published availability and current missing main
protection are verified here. The checklist intentionally leaves the other items open.
