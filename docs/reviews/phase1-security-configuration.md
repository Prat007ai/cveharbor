> Feed implementation update: see [intelligence-publication.md](intelligence-publication.md) for the implemented replacement, integration results and required staged cutover. Earlier cache/integration findings below are historical.

# Phase 1 GitHub security configuration and validation handoff

> **Superseded rollout advice:** Read [the continuity and integration checklist](phase1-transition-checklist.md)
> before applying this plan. The current draft stops hourly collection and removes committed snapshots still
> consumed by vulnerability digests. The deployed digest loader rejects snapshots older than eight hours.
> Do not merge #253, activate main rules that block the current updater, or remove its credentials until a
> validated feed handoff exists. The cache/artifact design below is an incomplete proposal, not a working
> replacement for the deployed feed readers. The newer checklist also records actual #251 merge conflicts.

Reviewed 2026-11-03. Source baseline: `147d2671d993e6297205cb5816aca53969cc71b7`.
Phase 1 PR #251 remains draft, unmerged and unchanged at
`d791cb8e84f85f980926dd1e1acfd0b369c64b46`.

**Decision: prepare and review security changes first; do not release Phase 1 yet.**
This security PR changes workflow configuration, adds local validation and instructions,
and provides manual readiness entry points. It changes no application handlers, schema,
customer records, assignments, receipt/reviewer links, notification logic, tickets or history.
No GitHub settings/secrets, Cloudflare resources or production services were modified.

## What was verified, and what remains unknown

| Check | Evidence / result |
| --- | --- |
| Main protection | GitHub reports `protected=false`, protection disabled, status-check enforcement off. Repository rulesets response is empty. |
| Repository | Public, personal-user-owned repository; default branch `main`. Connector reports administrator capability, but does not expose environment/secrets administration endpoints. |
| Branch inventory | All 263 current branch heads inspected, covering 38 workflow paths and 146 distinct workflow file versions, with no failed file reads. This includes retained older definitions on feature branches. |
| Cloudflare boundary | 49 branch heads contain at least one Cloudflare secret reference in a job without an environment. References show potential access, not proof of available or production-capable credentials. |
| Historical jobs | The last 100 runs include a waiting CVIE staging run, `41659896789`; it was not approved, rerun or cancelled. This is not a complete historical-run inventory. |
| Secret locations | **Unverified.** The connector cannot enumerate repository/environment secrets or environment protection rules. The previously attempted metadata-only CLI request was blocked by the configured network path. No secret value was requested or displayed. |
| Cloudflare resources | Live existence, permissions and token scope unverified. There is no configured Cloudflare credential/network path in this workspace. |
| Existing staging evidence | `codex/cvie-core-phase012` and `codex/trusted-staging-diagnostics` contain a separate CVIE staging configuration. These are useful leads, not proof that the resources/credentials are currently available. Do not overwrite that experiment's database or reuse its account token without checking scope. |

Inventory scope is current branch heads, including older retained workflows, not every deleted
branch or commit in GitHub history. An old run can still execute old workflow code. Credential
cutover, cancellation/review of queued runs and environment approval are necessary even after
this PR merges. A source-only fix cannot revoke credentials from old branches or historical runs.

## Findings and proposed corrections

| Workflow(s) | Existing risk | Prepared correction |
| --- | --- | --- |
| `verify-cvie-d1.yml` | A feature-branch push can run migration 0022 on production without an environment. This version appears on 34 branch heads, although its trigger matches only named branches. The query probe itself is read-only; the migration step is the write. | Remove the production migration and D1 credential steps from development verification. Retain local contracts/provider checks and artifact evidence. |
| `verify-catalogue-scope`, `verify-software-history`, `check-site-gate-hosting`, `check-cvie-runtime` | Live diagnostics use production credentials; some lack environments or permit feature refs. | Manual dispatch, main-only, protected `cloudflare-production-audit`, distinct audit secret names. No production mutations added. |
| `verify-cvie`, `verify-cvie-dotnet`, `verify-product-monitoring` | Development jobs combine local tests with production credentialed diagnostics. | Local/provider checks remain; production metadata moves to separate manual, main-only audit jobs. Product-monitoring visuals use the local build. |
| `verify-disclosure-trend`, `verify-malware-dialogs`, `verify-multipage`, `verify-remediation-ui` | Live UI checks use the site's access password without an environment. | Manual main-only audit environment with a newly named site-access secret. Local UI checks remain in CI. |
| `test-product-monitoring-email` | An older feature-branch push can use SMTP credentials based on a historical recipient approval. | Fresh manual main-only run, protected notifications environment, distinct SMTP secret and explicit email-test opt-in. Do not execute during readiness. |
| `activate-*`, `deploy-account-worker`, `deploy-worker-code`, `retire-public-site-origin` | Some manual jobs can use arbitrary refs; confirmation inputs are not independent approval. Production execution can start on a workflow change. | Main/repository guard and default-off release gate; pinned Actions and no persisted checkout token. Existing production operations remain disabled pending approval. |
| `bootstrap` | Workflow-wide write token; source restoration/direct hourly pushes bypass reviewed PRs; collection resets to newer unreviewed source mid-run; site deployment falls back to backend credential. | Read-only repository token, immutable event checkout, restoration artifact for a PR, public-feed checkpoint instead of direct push, no site/backend token fallback. Pages permissions limited to protected publishing jobs. |
| Other development evidence jobs | Automatic commits grant tests repository write access. | Artifacts replace commits in coverage, Hyper-V and attack-feed diagnostics. |
| Branch-only `cvie-phase012.yml` | Same-repository PR job can use Cloudflare credentials without an environment. | Documented as a legacy exposure. Its source branch was not rewritten; remove legacy credential availability after approval. Review/rebase that independent PR before merging it. |
| Branch-only `cvie-staging*` | Separate staging environments and credentials are referenced; live isolation and protections are unverified. | Preserve this independent work. Verify account/token scope and branch policies before reuse; never give those environments production secrets. |

All other workflow definitions were included in the inventory and checked for credentials,
environments, triggers and inline database/deployment operations. A shell script's name or
`contents: read` does not constrain the permissions of a Cloudflare token. Required reviews
must cover scripts invoked by privileged workflows as well as the YAML.

Additional changes:

- Actions are pinned to commit SHAs resolved from the existing action major versions.
- Checkouts do not persist their GitHub token. Development jobs have no repository-write permission.
- New always-running, credential-free checks: **`Security / workflow policy`** and
  **`CI / application regression`**. No path filters can leave these required checks pending.
- Policy checks reject missing environments, non-main privileged execution, OR bypasses,
  duplicate YAML keys, arbitrary checkout refs, mutable Actions, direct pushes, write tokens,
  staging/production credential crossover, and migration commands in audit jobs. Shell syntax
  is checked too. This is a regression aid, not an authorization boundary or full interpreter.
- Separate readiness workflows check out the reviewed Phase 1 SHA above. They accept no source-ref
  or arbitrary-SQL input. The production audit only runs `AUDIT_PHASE=preflight`; the staging
  harness accepts `bootstrap`/`validate` against a separate synthetic database.

## Approval boundaries and implementation order

1. Review this security PR and the environment/credential matrix below. No settings are applied by this PR.
2. **Obtain explicit approval for the configuration cutover.** Administrator changes to branch rules,
   environment approvals/branches, credentials, workflow enablement or deployment permissions require approval.
3. Inventory secret names/locations and current queued/running jobs. Confirm the new repository variable
   `PRODUCTION_DEPLOYMENTS_ENABLED` is absent or `false`; keep `PRODUCTION_EMAIL_TESTS_ENABLED` absent/false.
   These are repository-level variables because job selection runs before environment variables are loaded.
4. During the approved cutover, stop new production deployment jobs and resolve/cancel queued historical
   deployment jobs before changing credentials. Do not cancel a migration mid-execution; determine its state
   first. This affects deployment automation, not the running Worker's normal operations.
5. Configure independent reviewers and explicit main-only environment rules. Prepare environment-only
   credentials with the new names. Remove legacy repository/environment duplicates **only after** dependency
   review and explicit approval. Do not leave a production-capable repository secret as a fallback.
6. Configure main protection and code-owner review. Review/merge the security PR only after separate approval
   and green CI. It does not merge PR #251. Keep the deployment gate off.
7. Configure isolated staging, then execute the manual staging rehearsal and SELECT-only audit.
8. Reconcile PR #251 with the security PR, retain both sets of safeguards, rerun CI, and review the complete
   release procedure again. Update the readiness workflows' pinned SHA by reviewed PR if Phase 1 changes.
9. Only after the user approves the Phase 1 release may the release gate be enabled and deployment proceed.

The existing main Worker classifier and frontend ordering do not acquire PR #251's fixes through this
security PR. **Do not enable production deployment until those fixes are integrated and validated.**
Likewise, do not merge #251 over these workflow changes without reconciling secret names, gates, pins,
concurrency, read-only diagnostics and feed checkpoints. The policy check should fail on an unsafe rebase.

## GitHub: exact administrator setup

### A. Read metadata before making changes

From an authorized administrator machine with an existing authenticated `gh` session:

```sh
gh api --method GET repos/Prat007ai/cveharbor/branches/main
gh api --method GET repos/Prat007ai/cveharbor/rulesets
gh api --method GET repos/Prat007ai/cveharbor/environments --paginate
gh api --method GET repos/Prat007ai/cveharbor/actions/permissions/workflow
gh secret list --repo Prat007ai/cveharbor
gh variable list --repo Prat007ai/cveharbor
gh secret list --repo Prat007ai/cveharbor --env cloudflare-worker-production
gh secret list --repo Prat007ai/cveharbor --env cloudflare-site-production
gh secret list --repo Prat007ai/cveharbor --env github-pages
gh api --method GET 'repos/Prat007ai/cveharbor/actions/runs?status=waiting&per_page=100' --paginate
gh api --method GET 'repos/Prat007ai/cveharbor/actions/runs?status=queued&per_page=100' --paginate
gh api --method GET 'repos/Prat007ai/cveharbor/actions/runs?status=in_progress&per_page=100' --paginate
```

For each environment returned, also read:

```sh
gh api --method GET repos/Prat007ai/cveharbor/environments/ENVIRONMENT_NAME
gh api --method GET repos/Prat007ai/cveharbor/environments/ENVIRONMENT_NAME/deployment-branch-policies
gh secret list --repo Prat007ai/cveharbor --env ENVIRONMENT_NAME
```

Substitute a name from the actual environment list. A 404 can mean unavailable permissions; do not
interpret it alone as absence. These operations return metadata, never decrypted secret values.
This is a personal repository, so organization-secret inheritance is not currently applicable;
recheck if ownership changes. Do not paste tokens into chat or shell command arguments.

### B. Protect main

1. Open **Settings → Rules → Rulesets → New ruleset → New branch ruleset**.
2. Name it `Reviewed main changes`; enforcement **Active**; target branch **main** explicitly.
3. Require a pull request before merging and at least **one independent approval**. Enable dismissal
   of stale approvals, approval of the most recent reviewable push, code-owner review and resolution
   of review conversations. A second trusted maintainer is needed if the author is the only maintainer.
4. Require **`Security / workflow policy`** and **`CI / application regression`**, with GitHub Actions
   as the expected source where supported. Select them after they have run on this PR. Require the branch
   to be up to date. Do not select generic `verify` as a substitute for independent checks. Do not enable
   merge queue unless a corresponding `merge_group` validation trigger is added and tested.
5. Block force pushes and deletions. Leave the bypass list empty, including for admins and updater bots.
   Use the reviewed PR process for emergency fixes. If the plan cannot enforce required controls, resolve
   that limitation before claiming protection; do not silently weaken the rules.
6. Add `.github/CODEOWNERS` through a reviewed PR with actual independent maintainers/team names with write
   access. Cover `.github/`, `account-backend/`, `site-gate/`, `scripts/`, and the security tests/docs.
   Do not insert a placeholder team or appoint an unverified maintainer. Require those owners' approval.
7. Under **Settings → Actions → General**, set default workflow token permissions to **Read repository
   contents** and disable Actions creating/approving PRs unless separately needed. Restrict allowed Actions
   to reviewed publishers and require full-SHA pinning if available. The draft already pins all actions.
   These global settings do not restrict independent Cloudflare tokens, and explicit job permissions still
   need review. Disable write tokens/secrets for untrusted fork workflows; require approval for outside contributors.
8. Re-read ruleset/protection metadata. With no credentials, verify a direct test push to protected main is
   rejected only as part of an approved admin validation procedure; do not test by pushing application changes.

### C. Protected environments and credential migration

For each environment below: **Settings → Environments → environment → Deployment protection rules**:

1. Require an independent reviewer; enable **Prevent self-review** and disable administrator bypass where
   supported. GitHub's required-reviewer list generally requires one of the listed reviewers, not all of them.
2. Under **Deployment branches and tags**, choose selected branches/tags and allow the **branch `main` only**.
   Do not allow arbitrary tags, `*`, or development branches. “Protected branches only” is not sufficient
   while main is unprotected. Apply this to `github-pages` as well as Cloudflare environments.
3. Review the run SHA, workflow path, event, requested operation and environment before approval. Reject
   obsolete main revisions and historical reruns. A job/environment gate is not a workflow-name allowlist;
   main review and credential isolation are both required.

| Environment | Secret names required by proposed code | Permitted purpose |
| --- | --- | --- |
| `cloudflare-worker-production` | `CVEHARBOR_PROD_WORKER_TOKEN`, `CVEHARBOR_PROD_ACCOUNT_ID` | Reviewed backend deployment/migration only after release approval. |
| `cloudflare-site-production` | `CVEHARBOR_PROD_SITE_TOKEN`, `CVEHARBOR_PROD_ACCOUNT_ID`, `CVEHARBOR_SITE_GATE_PASSWORD` | Reviewed frontend publication. Dedicated site token; no backend token fallback or D1 health probe. |
| `github-pages` | `CVEHARBOR_SITE_GATE_PASSWORD` | Approved retired-origin check/publication; GitHub Pages permission is job-scoped. |
| `cloudflare-production-audit` | `CLOUDFLARE_AUDIT_API_TOKEN`, `CLOUDFLARE_AUDIT_ACCOUNT_ID`; `CVEHARBOR_SITE_GATE_PASSWORD` only for optional live site checks | Approved manual read-only diagnostics and Phase 1 aggregate audit. |
| `cloudflare-notifications-production` | `CVEHARBOR_PROD_SMTP2GO_API_KEY` | Separately approved manual email test, never part of staging/readiness. |
| `cloudflare-phase1-staging` | `CLOUDFLARE_STAGING_API_TOKEN`, `CLOUDFLARE_STAGING_ACCOUNT_ID` | Synthetic rehearsal in a different account/database. |

Production token permissions must be limited to the necessary production account/resources. The site token
must not receive D1 access merely for convenience. Review deployment helper API requirements before issuing
or changing scopes. D1's query API may require a broader permission than metadata reads; verify the current
Cloudflare permission model. Do not claim that an API token is SELECT-only merely because a script is. The
Phase 1 audit uses a fixed reviewed SELECT-only client and checks `rows_written`; no arbitrary SQL is accepted.
If a narrow read token cannot perform the audit, stop for approval of the credential scope—do not silently
substitute the Worker deployment token or grant broader permissions.

Legacy names to locate at repository level **and every existing environment**:
`CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_SITE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, `SITE_GATE_PASSWORD`,
`SMTP2GO_API_KEY`, `ALERT_SMTP2GO_API_KEY`. Account IDs are identifiers, not authentication secrets, but their
locations help map dependencies. New production names do not occur in any of the 146 reviewed old versions.

After explicit approval, populate new names only in the matching environments using the original secure
secret source. GitHub does not reveal existing secret values; if the original value is unavailable, obtain
separate approval for reissuance/rotation. Review external consumers before revocation. Remove obsolete
repository/environment duplicates only after the transition is reviewed. Leaving a repository copy makes
environment protection ineffective for older workflows. Do not change Worker runtime secrets, signing keys,
SMTP runtime bindings, receipt tokens or customer sessions as part of this GitHub credential relocation.

## Cloudflare staging: exact isolated setup

1. In Cloudflare, inspect the existing staging account referenced by the CVIE experiment, if accessible.
   Confirm it is different from the production account. It may be reused as an account if approved, but
   create a **new empty database** for Phase 1; never reuse/reset the existing CVIE database. Otherwise create
   a dedicated staging account through the normal authorized administrator process.
2. In that account, **Storage & databases → D1 → Create database**. Name it
   `cveharbor-phase1-staging` (or `cveharbor-phase1-staging-<suffix>`). Record its UUID privately in configuration.
   No customer exports, production restore, Worker binding, custom domain, scheduled production process or SMTP.
3. Create a dedicated token using **My Profile → API Tokens → Create Custom Token**. Scope account resources
   to **only the staging account**, with D1 permissions needed for synthetic schema/query writes. Do not select
   “All accounts”; do not give production account, DNS, Worker deployment or SMTP permissions. If Cloudflare
   cannot isolate individual D1 databases, account separation is the required boundary. Verify the policy in
   the UI/authorized metadata tooling; a different database name/UUID alone does not constrain a token.
4. Create/inspect GitHub environment **`cloudflare-phase1-staging`**, with independent review and main-only
   branch rules. Set the two staging secrets in the matrix above. There is no fallback to production names.
5. Add these **environment variables**:

| Variable | Value |
| --- | --- |
| `STAGING_DATABASE_ID` | UUID of the new empty database |
| `STAGING_DATABASE_NAME` | Its exact approved staging name |
| `STAGING_DISPOSABLE` | `true` |
| `PRODUCTION_ACCOUNT_ID` | Verified production account ID, an identifier only, used to reject same-account setup |

6. Review the token policy and ensure it grants no resource access in the production account. The local
   boundary check rejects same-account and production-UUID mistakes before network access; it cannot prove
   token scope. Do not use a shared all-accounts token even if the boundary check passes.

No account/resource/configuration was created in this review. The required Cloudflare access and secure
environment administration interface are unavailable here. Use existing secure administrator sessions;
there is no need to give the assistant production API tokens in conversation.

## Exact final validation, after the security PR and configuration are approved

These new workflow names become dispatchable only once their definitions are on the default branch.
Do not merge PR #251 just to register them. Each job requires the protected environment's approval.

1. Inspect the security PR's merged revision, environment rules, secret **names** and main protection.
   Confirm both new required CI checks are green and deployment/email opt-ins remain off.
2. Bootstrap the verified empty synthetic database once:

```sh
gh workflow run security-phase1-staging.yml --repo Prat007ai/cveharbor --ref main -f operation=bootstrap
```

3. Approve that staging run only after checking its target/account and pinned Phase 1 SHA. Wait for success.
   Then run `validate`, wait for success, and run it a second time:

```sh
gh workflow run security-phase1-staging.yml --repo Prat007ai/cveharbor --ref main -f operation=validate
```

   Expected: `passed=true`, repeated migrations preserve the synthetic snapshot, existing acknowledgement
   links work, assignment linking/status notifications are correct, hold/drain/freeze/resume passes, integrity
   counts and foreign-key violations are zero, `real_emails_sent=0`. SMTP is intercepted by the harness.
   A failed/partially bootstrapped database is investigated or replaced with another explicitly approved
   disposable database; do not add automatic cleanup/reset logic.
4. Execute the fixed SELECT-only production preflight:

```sh
gh workflow run security-phase1-audit.yml --repo Prat007ai/cveharbor --ref main
```

   Approve only the pinned audit job. It cannot deploy, apply a migration, run cleanup or send email.
   Capture the run URL/revision and aggregate output. The required zero counts are:
   `duplicate_findings`, `invalid_links`, `status_drift`, `detached_asset_records`, `invalid_retirements`,
   `orphan_status_history`, `orphan_assignments`, `orphan_notifications`, `foreign_key_violations`;
   `rows_written=0`. Nonzero counts stop release readiness and require review, not automatic repair.
   Queries are read-only but multiple requests are not one transactional snapshot; investigate/recheck any
   suspected concurrent-write inconsistency without silently taking a production write hold.
5. Retain sanitized logs and staging evidence. Both remote checks are **NOT RUN**, not passing, until those
   actual run results exist. No production database migrations belong in these readiness workflows.

Automatable now: local policy/negative tests, application regression, source/branch inspection, preparation
of draft PRs and instructions. Automatable after configured environments and run approvals: staging
bootstrap/rehearsal and the SELECT-only audit. Separate approval required: rules/settings changes, credential
relocation/removal/scope changes, workflow/permission changes, merges, deployments, recovery holds, production
migrations and any customer-data mutation. No real email test is required for this readiness assessment.

## Operational impact, recovery and remaining release risks

Local validation of this security draft passed: policy checks for all 34 workflow files; 18 policy/negative
tests (included in 136 passing Python tests); seven staging-boundary tests; 37 backend test files; site-gate
tests; public build/preflight and browser/customer-security/product-monitoring smoke checks. These tests use
local fixtures and do not send real emails or access production D1. GitHub environment enforcement and actual
main-scoped cache persistence still require the approved configuration/operational checks; local tests cannot
prove those provider settings. Remote staging and the production integrity audit remain unexecuted.

- **Now:** draft source changes only. The live application, its scheduled Worker jobs, acknowledgements,
  reviewer access and notification delivery are unchanged. Existing security gaps remain until settings
  and credential isolation are actually applied.
- **After an approved security merge with the release gate off:** currently deployed services continue,
  but new backend/frontend releases and hourly frontend feed publication are paused. The runtime Worker's
  scheduled jobs and emails are not paused. Do not describe this as entirely invisible to customers:
  public dashboard feed freshness will lag while publication is held.
- **After publication is approved:** each protected scheduled job still requires environment approval.
  Required reviewers and fully unattended hourly deployment conflict; do not remove reviews or add a bot
  bypass to restore unattended publishing. A separately reviewed data-only publication architecture can
  address that later without allowing arbitrary source deployment.
- Hourly generated public feed files move from commits to a main-scoped Actions cache plus 14-day artifact.
  Pull-request caches cannot be restored into main under GitHub's cache ref scoping. Only 16 explicit public
  feed/export paths are cached—no application source, credentials or customer data. Cache eviction falls back
  to checked-in public snapshots, which may be stale; preserve/export the latest checkpoint and validate
  incremental feed continuity before enabling publication. Actions caches are not durable backups. A longer
  retention/checkpoint recovery design needs separate review if GitHub retention is insufficient.
- Source restoration now produces an artifact; review it in a PR instead of automatically overwriting main.
  Live diagnostic and test-email runs become explicitly manual. These are intentional deployment-operations changes.
- No database rollback is needed for this security PR. If CI/configuration fails, leave release gates off,
  fix configuration or submit a reviewed correction/revert PR. Do not restore legacy repository-wide secrets,
  disable branch protection, or rerun an old deployment as a recovery shortcut. Already deployed services remain
  available. For a later Phase 1 database recovery, use the separately reviewed write-hold/drain/backup procedure;
  this security PR does not replace or activate it.

**Production release remains blocked** on approved settings/credential cutover, remote staging, the live
integrity audit, reconciliation with PR #251 and a fresh release approval. Phase 2 is not authorized.
