> Routine staging releases are superseded by [Simplified staging releases](simplified-staging-release.md) once reviewed and activated. This document remains applicable to historical/exception operations and unchanged production safeguards. Do not run the queued legacy continuation concurrently with simplified initialization.

> **Permanent staging update:** use [the consolidated activation runbook](permanent-staging-activation.md)
> for the current integrated #243 candidate. It supersedes earlier staging bootstrap,
> publisher and email-blocking instructions in this checklist. Production approval,
> audit, feed-transition and deployment controls below still apply. Both production
> drafts remain separate from the integrated staging application candidate.

# Phase 1 administrator configuration and release checklist

**Authoritative runbook for PR #253 + integrated PR #251.** Updated November 3, 2026.
Both PRs remain draft. This document is preparation, not authorization to create
resources, change credentials/security settings, merge, deploy or migrate. Phase 2
and UI redesign remain on hold. No such actions were performed in this review.

Use this checklist for configuration/order, [the release procedure](remediation-phase1-release.md)
for database recovery details, and [the R2 implementation report](intelligence-publication.md)
for architecture and source coverage. Use [the permanent staging architecture](permanent-staging-architecture.md)
for verified existing resources, reuse decisions and refresh requirements. Earlier review reports are historical evidence,
not alternative release instructions.

## 1. Establish the configuration worksheet

Record identifiers and evidence below; **never record credential values** in this
file, PRs, chat, screenshots or artifacts. Use your password manager/secure runner.

| Item | Required value/evidence | Current status |
|---|---|---|
| Repository | `Prat007ai/cveharbor`, personal/public; verify visibility and plan | Plan and saved administrator settings unverified |
| Integrated executable source | Reviewed PR #251 commit containing #253; initial code validation anchor `5a3a53a9a7c26fcdc59b7ee588df6597cd557a8a` | Local tests and GitHub CI passed at that code revision; recheck latest heads |
| Production Cloudflare account ID | Actual 32-character account ID from the dashboard | Administrator must confirm |
| Production D1 | `cveharbor-accounts`, UUID `46710e51-7ca4-4571-b89c-921b9969de0b` | Confirm against dashboard and Wrangler; never use for staging |
| Existing staging account | `9706b4d98ad72884e67fd1eb875c8a61` | Existing run verified identity; saved token scope remains owner-attested; reuse this account |
| Permanent staging D1 | `cveharbor-accounts-staging`, UUID `fac61562-fc31-426d-8032-550aba63b7f6` | Existing resource/binding verified; full schema and application data tests pending |
| Permanent staging Workers | `cveharbor-accounts-staging`, `cveharbor-site-staging` | Existing run verified bindings and 28 Access checks; reuse both |
| Permanent staging R2 | Proposed `cveharbor-intelligence-staging`; inspect existing buckets first | Live R2 inventory still requires verification; integration prepared in #243 |
| Disposable D1 | Fresh empty `cveharbor-phase1-staging-<suffix>` in the same staging account | Pending approval and inventory-guard integration; never use permanent D1 |
| Disposable R2 | Fresh empty `cveharbor-intelligence-staging-<suffix>` in the same staging account | Pending inventory/approval; required only for empty-bucket synthetic rehearsal |
| Production R2, later | Private `cveharbor-intelligence`, accessible in existing Workers' account | Requires separate resource/cost approval |
| Independent reviewer | Eligible collaborator other than PR author/deployment initiator | Administrator must confirm |
| Shadow publisher | Approved runner, reviewed SHA, operator, cadence, start/stop record | Must exist before retiring the old publisher |
| Evidence | Run SHA/time, target IDs, aggregate output, CI checks, approvals, recovery bookmark | Do not mark a checkbox complete without evidence |

The current managed development environment has no configured credentials/identities.
GitHub administrative secret/environment metadata is not exposed by the connected
GitHub tool. Existing resources are verified from the completed staging run and its
inspected artifacts, not inferred from source names. See the architecture document
for exact evidence/time and limits. No new Cloudflare request or staging mutation
was made in this review.

## 2. Cloudflare: reuse permanent staging; isolate disposable tests

### Permanent application environment — preserve existing resources

- [ ] Select the existing staging account above, separately from production. Inspect
  its D1, two Workers, Access application and R2 inventory read-only. Do not create
  a second account or replace the permanent database. The existing staging project
  uses GitHub environment **`cloudflare-cvie-staging`** and `CF_STAGING_*` credentials.
- [ ] Verify the permanent D1 UUID/schema and active Worker bindings. The last
  reported schema was empty; the latest frontend operation did not migrate it.
  Do not treat successful Access probes as complete application readiness.
- [ ] Follow [the integration gaps and configuration steps](permanent-staging-architecture.md).
  Before adding another D1, correct the existing one-database inventory guard through
  review. Before combining source, correct the staging schema builder's handling of
  0030–0032. Never reset the permanent database to satisfy a synthetic harness.
- [ ] Reuse an appropriate private R2 bucket if present; otherwise seek approval for
  permanent `cveharbor-intelligence-staging` in the same staging account. Standard
  storage, public access disabled, no production domain. The current staging wrapper,
  config validator and frontend now support the reviewed private R2 binding in #243; activation still needs approval.
- [ ] Keep real mail/provider egress and crons disabled. Prepare captured-email,
  provider-fixture and scheduler tests before enabling full synthetic feature testing.
  Sanitized production refresh needs a separate reviewed sanitizer/import plan and
  approval; it is not required to start Phase 1 validation.

### Disposable D1 — only for the Phase 1 regression harness

- [ ] After inventory-guard integration and explicit resource approval, use **Storage
  & databases → D1 SQL database → Create database** in the **same existing staging
  account**. Create `cveharbor-phase1-staging-<lowercase-suffix>`; record exact UUID.
  Leave it empty, with no customer import or permanent Worker binding. An existing
  candidate may be reused only after identity and empty-state verification and
  approval; do not clear a used database automatically.
- [ ] Use a distinct token: Account / D1 / Edit (API label `D1 Write`), resources
  **Include → this staging account only**. No Workers Scripts, DNS, SMTP or production
  permission. Account-level D1 permission can reach permanent staging too; the
  explicit name/UUID/synthetic-data guards remain essential. Do not reuse the more
  capable permanent staging management token merely for convenience.
- [ ] Store the approved token in `cloudflare-phase1-staging` as section 3 specifies.
  It is a job/credential boundary in the same Cloudflare account, not another stack.

### Disposable R2 — only for the empty-bucket publication rehearsal

- [ ] Inspect existing staging buckets first. After approval, create a fresh empty
  `cveharbor-intelligence-staging-<lowercase-suffix>` in **Standard** storage within
  that same account. Approve any billing enrollment first. Disable public `r2.dev`,
  custom domains and CORS; do not add automatic expiry to referenced objects.
  Do not point the permanent Workers/publisher at this bucket.
- [ ] **R2 → Manage R2 API Tokens → Create API token**: **Object Read & Write**, only
  this disposable bucket, never all buckets or Admin Read & Write. Store its S3
  Access Key ID/Secret Access Key securely. Endpoint:
  `https://<staging-account-id>.r2.cloudflarestorage.com`; SDK region `auto`.
  List/get/put are needed; the harness never deletes, even if the token permits it.
- [ ] The R2 harness requires an empty bucket and fixed root keys. A populated
  permanent bucket or a prefix within it is not a supported substitute. Retain
  evidence and request cleanup approval after the test; do not keep creating
  untracked test resources.

**No additional hosted Worker is required for either disposable rehearsal.** D1
invokes real handlers through its REST adapter with mail intercepted; R2 uses S3.
Full application checks use the existing permanent Workers after approved integration.
The R2 rehearsal has **no GitHub Actions workflow**. Use the CLI in an approved secure
runner; do not put staging keys in production `cloudflare-intelligence-data`.
GitHub environment secrets cannot be read back into a local runner.

## 3. GitHub: exact environment and credential configuration

Location: **Repository → Settings → Environments → New environment/name**.
Configure secrets/variables under that environment, not under repository secrets.
The table describes intended locations; it does not assert they already exist.

| Environment | Secrets | Variables | Protection / purpose |
|---|---|---|---|
| `cloudflare-cvie-staging` | Existing `CF_STAGING_API_TOKEN`, `CF_STAGING_ACCESS_CLIENT_ID`, `CF_STAGING_ACCESS_CLIENT_SECRET`; retain existing supported secret storage for account/Access IDs | `CF_STAGING_ACCOUNT_ID`, `CF_STAGING_D1_DATABASE_ID`, `CF_STAGING_ACCESS_ISSUER`, `CF_STAGING_ACCESS_AUD`, `CF_STAGING_APPROVED_COMMIT`, `CF_STAGING_PROVISION_ACTION` | Existing permanent staging; preserve reviewed `codex/cvie-core-phase012` restriction and current approval arrangement; details in architecture document |
| `cloudflare-phase1-staging` | `CLOUDFLARE_STAGING_API_TOKEN`, `CLOUDFLARE_STAGING_ACCOUNT_ID` | `STAGING_DATABASE_ID`, `STAGING_DATABASE_NAME`, `STAGING_DISPOSABLE=true`, `PRODUCTION_ACCOUNT_ID` | Main-only, independent approval; disposable synthetic D1 in the existing staging account |
| `cloudflare-production-audit` | `CLOUDFLARE_AUDIT_API_TOKEN`, `CLOUDFLARE_AUDIT_ACCOUNT_ID` | None for preflight | Main-only, independent approval; SELECT-only production audit |
| `cloudflare-worker-production` | `CVEHARBOR_PROD_WORKER_TOKEN`, `CVEHARBOR_PROD_ACCOUNT_ID` | None newly required for Phase 1 | Main-only, independent approval; backend migrations/deployment and recovery |
| `cloudflare-site-production` | `CVEHARBOR_PROD_SITE_TOKEN`, `CVEHARBOR_PROD_ACCOUNT_ID`, `CVEHARBOR_SITE_GATE_PASSWORD` | Existing site configuration only | Main-only, independent approval; application frontend deployment |
| `cloudflare-intelligence-data` | `FEED_R2_ACCESS_KEY_ID`, `FEED_R2_SECRET_ACCESS_KEY`; existing feed-provider keys as needed | `FEED_R2_ACCOUNT_ID`, `FEED_R2_BUCKET=cveharbor-intelligence` | Main-only, **no per-run human review/wait timer**; bucket-only hourly data publication |
| `github-pages` | `CVEHARBOR_SITE_GATE_PASSWORD` only where a reviewed check needs it | None | Main-only, independent approval; old-origin retirement only, not the application/feed host |
| `cloudflare-notifications-production` | `CVEHARBOR_PROD_SMTP2GO_API_KEY` | None | Main-only, independent approval; optional real-email diagnostic, leave disabled |

The last two environments are not new features to activate. Configure only the
callers needed for the approved release; never use a mail diagnostic to test setup.
`CVEHARBOR_SITE_GATE_PASSWORD` is optional in the audit environment only for separate
live site diagnostics, **not** for the D1 audit. Preserve the existing password.

**Repository → Settings → Secrets and variables → Actions → Variables:**

| Variable | Before approval | During approved cutover / afterwards |
|---|---|---|
| `PRODUCTION_DEPLOYMENTS_ENABLED` | Absent or `false` for the new workflows | `true` only for authorized code releases; environment review still required |
| `FEED_PUBLICATION_ENABLED` | Absent or `false` until new bucket is seeded and cutover approved | `true`; retain it independently of application release approvals |
| `PRODUCTION_EMAIL_TESTS_ENABLED` | Absent or `false` | Leave `false`; separate explicit approval for real test mail |

These are workflow flags, **not** Worker runtime variables. Do not change deployed
mail flags, `SITE_GATE_ENABLED`, session/signing/receipt secrets, acknowledgement
TTL, provider settings or `RECOVERY_CONTROL_REQUIRED` during security configuration.

Feed provider keys: `NVD_API_KEY`, `WORDFENCE_API_KEY`, `MALWAREBAZAAR_API_KEY`,
`THREATFOX_AUTH_KEY`; keep current consumers working while mapping their locations.
The publisher can use MalwareBazaar's key as the existing ThreatFox fallback.
`GITHUB_TOKEN` is provided by Actions; do not create a PAT for it. Wordfence stays
disabled by default; merely copying its key does not activate collection.

### Cloudflare permission matrix for production identities (prepare; changes need approval)

- **Audit:** Account / D1 / Read, restricted to the verified production account and
  narrowest available resources. Cloudflare's query and metadata endpoints list
  `D1 Read` as accepted. Start with Read; do not substitute a deployment token or
  grant Edit when a read-only check fails without diagnosing and obtaining approval.
  The audit also enforces single SELECT statements and zero rows written locally.
- **Backend release:** Account / Workers Scripts / Edit, Account / D1 / Edit;
  Account Settings / Read for Wrangler account discovery; any required Workers
  Routes / Edit + Zone / Read only on the intended zone for approved hostname
  operations. Do not add zone DNS Edit for convenience. Verify actual helper/API
  requirements for the chosen release operation and preserve existing routes.
- **Site release:** Account / Workers Scripts / Edit and Account Settings / Read;
  Zone / Zone / Read, DNS / Edit and Workers Routes / Edit restricted to
  `cveharbor.com`, because the current site helper reads and may change routing.
  No D1 permission. An account-wide Workers edit capability can still modify a
  D1-bound Worker; a separate secret name alone does not provide script-level isolation.
- **Data publisher:** R2 S3 Object Read & Write restricted to `cveharbor-intelligence`
  only. No Worker, D1, DNS or email permissions. Never reuse the site/backend token.

Source permissions are not proof of actual token scope. Review the saved policies
in Cloudflare; scope to an individual resource wherever the platform supports it.

### Safe credential transition

- [ ] Inventory **names and locations** at Settings → Secrets and variables → Actions
  and Settings → Environments. From an existing authenticated admin runner, use:
  `python scripts/audit_github_security_metadata.py > github-security-metadata.json`.
  It performs metadata GETs only and reports unavailable fields as unknown.
- [ ] Map legacy `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_SITE_API_TOKEN`,
  `CLOUDFLARE_ACCOUNT_ID`, `SITE_GATE_PASSWORD`, `SMTP2GO_API_KEY` and
  `ALERT_SMTP2GO_API_KEY` to their callers. Repository secrets remain accessible to
  older branch workflows even after new names/environments are introduced.
- [ ] After approval, populate protected environments from the original secure
  source. GitHub cannot reveal an existing value for copying. If that source is
  unavailable, stop for an approved reissue/rotation; do not request secrets in chat.
- [ ] Leave active legacy publisher credentials intact until the cutover replacement
  is verified. Then remove old repository/unprotected copies only with explicit
  approval and replacement/recovery evidence. Do not leave fallback copies for old
  workflows. No runtime SMTP/session/receipt signing keys are relocated by this plan.

## 4. GitHub: protect reviewed code without stopping hourly data

Prepare first; activate production-affecting restrictions only at section 7's
approved handoff. Main currently receives the legacy updater's direct feed commits.
Protecting main before replacing that writer would break its updates.

- [ ] **Account avatar → Settings → Billing & licensing**: verify the actual plan.
  Public repositories on current GitHub Free/Pro plans support branch protection,
  environments and relevant deployment protections; verify visible and saved controls.
  Legacy plans/private visibility can differ. No plan enforcement was verified here.
- [ ] **Repository Settings → Collaborators**: establish a trusted independent
  reviewer with write access. Both PRs are authored by `Prat007ai`; the author cannot
  approve their own PR. Environment reviewers need at least read access. With
  **Prevent self-review**, the initiating person cannot approve that deployment.
  If no independent person is available, record a blocker; do not substitute a bot
  or quietly lower the required approval count.
- [ ] **Settings → Rules → Rulesets → New branch ruleset**: name `CVEHarbor main`;
  target branch `main` explicitly. Prepare Disabled, then set **Active** only at the
  approved handoff. Require pull requests, **1 approval**, dismiss stale approvals,
  approval of the most recent reviewable push, and resolved review conversations.
- [ ] Require status checks **`Security / workflow policy`** and
  **`CI / application regression`**, expected source GitHub Actions; require the
  branch to be up to date. Do not require a generic `verify`, a skipped deployment
  or an actual production deployment before merge. No merge queue until its
  `merge_group` validation is implemented. Do not require linear history for this
  integrated branch without reviewing its merge-parent history.
- [ ] Block force pushes/deletion; no owner, administrator, Actions/updater or bot
  bypass. Do not use organization-only actor restrictions/teams in a personal repo.
  Code-owner review is optional until a reviewed valid CODEOWNERS file names real
  eligible collaborators; this change has not invented owners or added that file.
- [ ] **Settings → Actions → General → Workflow permissions**: Read repository
  contents/packages; turn off Actions creating/approving PRs. Review allowed
  actions; all used external Actions are pinned `actions/*` commits. Keep fork PR
  write-token/secret access disabled. Do not turn off Actions entirely.
- [ ] For **every environment in section 3 except existing `cloudflare-cvie-staging`**, choose **Deployment branches and tags
  → Selected branches and tags → branch `main` only**. No tag/wildcard/PR-ref rule.
  “Protected branches only” is not equivalent while no branch is protected.
- [ ] For all listed environments **except `cloudflare-intelligence-data` and existing
  `cloudflare-cvie-staging`**, require
  an independent reviewer, enable Prevent self-review, and disallow administrator
  bypass where supported. A reviewer list requires one listed approval, not all of
  them. Verify the saved controls, reject stale/old-SHA reruns, and review operation
  inputs before approving.
- [ ] For `cloudflare-intelligence-data`, deliberately leave per-run reviewers and
  wait timers unset. Its main-only job has read-only repository access and only
  bucket-scoped credentials; reviewed main code supplies the security boundary.
  Its hourly schedule is `17 * * * *` UTC. It has no dependency on application
  release approval, production deployment flags, D1 readiness or recovery holds.
- [ ] Preserve the existing permanent `cloudflare-cvie-staging` branch/review arrangement.
  Any future move to main needs coordinated review; do not apply blanket production
  rules to that branch-specific staging workflow.
  Verify the resulting settings by metadata/UI after saving; source YAML is not
  proof that repository/environment protections are enforced.

## 5. Remote validation: executable plan

**Before merge**, use the reviewed integrated #251 checkout in an already authorized
secure runner. Do not merge merely to make a new workflow visible, weaken main-only
rules to dispatch from a feature branch, or use #253's older pinned standalone
readiness harness. GitHub workflows must exist on the default branch to be
selectable; the integrated #251 versions use the run SHA after the approved merges.

Use separate clean sessions for each credential scope, shell tracing off, no secret
values on command lines. Secrets are injected by the secure runner/password manager.
The variables below describe mappings, not values to paste into a terminal/chat.
Use Python 3.12, Node 22+ and the pinned boto3 version shown. Required network access:
GitHub/package registries for dependencies; `api.cloudflare.com` for D1; the exact
staging account's R2 S3 endpoint for R2. Configure access through the supported
secure environment interface, without bypassing its network policy.

### A. R2 — writes synthetic objects only to an approved disposable bucket

Secure runner inputs (not production GitHub publisher secrets):

| Process variable | Value |
|---|---|
| `FEED_R2_ACCOUNT_ID` | Verified staging account ID |
| `FEED_R2_BUCKET` | Exact fresh staging bucket name |
| `FEED_R2_ACCESS_KEY_ID`, `FEED_R2_SECRET_ACCESS_KEY` | Staging bucket-only S3 pair |
| `PRODUCTION_ACCOUNT_ID` | Verified production ID for inequality guard; not a credential |
| `FEED_STAGING_DISPOSABLE` | `true` |

```sh
python -m pip install boto3==1.40.70
python scripts/rehearse_intelligence_r2.py
```

Pass: upload/readback; stale conditional write rejected with HTTP 412; prior
snapshot retained; pointer recovery; exact checkpoint/history restore. No emails,
D1 calls, Worker deploys, resource creation or deletion. Rerun only against a new
approved empty bucket; this harness refuses a nonempty one. Retain exact SHA,
bucket/account IDs, time and aggregate PASS output. Do not seed production with
these synthetic objects.

### B. D1 — disposable database only: bootstrap once, validate twice

In the secure staging session, inject `CLOUDFLARE_ACCOUNT_ID` and
`STAGING_ACCOUNT_ID` from the **staging** account identifier,
`CLOUDFLARE_API_TOKEN` from the **staging** token, and the four environment variables
`STAGING_DATABASE_ID`, `STAGING_DATABASE_NAME`, `STAGING_DISPOSABLE=true`,
`PRODUCTION_ACCOUNT_ID`. These process aliases do not rename GitHub secrets.

```sh
node scripts/check_phase1_staging_boundary.mjs
node scripts/phase1_staging.mjs bootstrap
node scripts/phase1_staging.mjs validate
node scripts/phase1_staging.mjs validate
```

Never set the target to permanent `cveharbor-accounts-staging`. Resolve the existing
staging inventory guard before provisioning a disposable database in its account.
Run each only after the preceding command succeeds. The boundary check must precede
any remote call. Pass: distinct accounts/UUID, exact remote database name, empty-only
bootstrap, synthetic identities, preserved rows/receipt links/history, repeatable
0031/0032/guards, status/assignment/notification and hold/freeze/resume checks,
`passed=true`, zero integrity/foreign-key violations and zero real emails.

After both PRs are approved and merged, the equivalent workflow is
**Phase 1 readiness - isolated synthetic D1 rehearsal**
(`security-phase1-staging.yml`), operation `bootstrap`, then `validate` twice on
main with the staging environment approval. No Worker deployment occurs.

### C. Production audit — SELECT only, separate session

Create/use the approved D1 Read identity in `cloudflare-production-audit`.
Secure runner maps `CLOUDFLARE_AUDIT_ACCOUNT_ID` → `CLOUDFLARE_ACCOUNT_ID` and
`CLOUDFLARE_AUDIT_API_TOKEN` → `CLOUDFLARE_API_TOKEN`. The database UUID is read
from the reviewed production Wrangler configuration. Verify that UUID first.

```sh
AUDIT_PHASE=preflight node scripts/audit_phase1.mjs
```

Pass: `ok=true`, `read_only=true`, `rows_written=0`, every integrity count zero,
`foreign_key_violations=0`. The API uses POST to submit SELECT; POST does not mean
this audit modifies data. It reports aggregate counts, never customer rows/tokens.
Stop on nonzero results or permission errors; no automatic linking, cleanup,
permission escalation, migrations or email replay is authorized.

After merge, **Phase 1 readiness - SELECT-only production audit**
(`security-phase1-audit.yml`) is manual/main-only and runs **preflight only**.
There is no `installed` UI input in that workflow. After an approved deployment,
`AUDIT_PHASE=installed node scripts/audit_phase1.mjs` is the secure-runner command
for additional guard/hold checks. Do not run installed mode before installation.

### Evidence gate

| Check | Result required | Status now |
|---|---|---|
| Local application/security/recovery tests | Passing on reviewed code | Prior code revision passed; documentation checks repeated in this review |
| Remote R2 synthetic rehearsal | PASS including conditional-write rejection/recovery | Pending approved disposable target/runner; existing permanent staging is reused separately |
| Remote D1 rehearsal | Bootstrap + two passing validations | Pending inventory-guard integration and approved disposable target/runner |
| Permanent staging foundation | Existing resources, Access/ASSETS gate, private API/session boundary | Completed run 41691571014 passed 28 GET checks; not an authenticated application test |
| Hosted Worker R2/full application integration | Complete schema/candidate code, R2 readers, captured notifications, scheduler and recovery tests | Pending integration/approval in existing permanent staging |
| Production preflight | All aggregate integrity counts zero, no writes | Pending approved read-only credentials/access |
| GitHub settings | Verified active rules, reviewers, main-only envs, scoped secret locations | Administrator verification pending |
| Shadow publication | At least two current cycles, parity checks and simulated failure recovery | Production shadow resources/runner approval pending |

No unavailable remote result is recorded as passed. Stop before merge/deployment
until required evidence and explicit approval are recorded.

## 6. Prepare production resources and recovery points (later, separate approval)

- [ ] Approve R2 billing/retention. Create the private Standard production bucket in
  the existing Workers' account, with public access disabled and bucket-only S3 keys.
  No D1 production resource needs recreation. Do not import staging fixtures.
- [ ] Obtain a consistent latest **19-path** public baseline: advisory data + matching
  health, workspace projection, malware, threat/IP/geolocation history and all
  exports, plus the lifecycle/patch files currently served by the site. The latter
  may not be committed on main. Do not seed from an incomplete old checkout.
- [ ] Validate freshness and file consistency, then seed once with the reviewed
  `feed_snapshot.py seed --root <baseline-directory>` command in an approved
  production-R2-only session. This is a production storage write needing approval.
- [ ] Prepare reviewed Wrangler edits for both existing Workers: binding
  `INTELLIGENCE_BUCKET` to `cveharbor-intelligence`, and `INTELLIGENCE_SOURCE=r2`
  at cutover. Defaults remain legacy until approved. Record the intended values
  in source, not solely Dashboard bindings that a later deploy can remove.
  The exact TOML/JSON additions are in `intelligence-publication.md`.
- [ ] Preserve all existing Worker runtime secrets/flags, D1 bindings, routes,
  scheduled triggers and reviewer/acknowledgement signing/session state.
- [ ] Record previous Worker versions, frontend version/artifact, deployment settings,
  D1 recovery bookmark/backup and current/prior R2 manifest IDs. Establish the
  tested fallback owner and freshness deadline before starting the window.

## 7. One coordinated production checklist — both PRs

**No step here is executed by this documentation review.** Do not merge #253 alone
and wait for approvals while raw-main digest data becomes stale. Application
release approval, scheduler handoff and reader switching need one staffed window.

1. [ ] Complete section 5 and resolve exceptions. Recheck current main, final-head
   CI and independent reviews. Confirm branch integration ancestry after any new
   edits. The merge order is **#253 first, then integrated #251**. Preserve the
   reviewed integration ancestry with a merge commit; if squash/rebase is required,
   re-integrate/retest #251 against that result before the second merge. Do not
   require linear history accidentally or resolve conflicts by restoring old YAML.
2. [ ] Obtain explicit approval covering resource/config/credential changes, both
   merges, the release mode, R2 reader/scheduler cutover and fallback. Keep existing
   services/publisher active until their replacement and approvals are ready.
3. [ ] Start the approved shadow **data-only** collector using the reviewed code,
   production-R2-only credentials and a trusted scheduler. Observe at least two
   cycles and failure recovery; compare source ages/status, IDs/revisions, history,
   exports, lifecycle/patch data and digest selections. Keep it running through
   application deployment, without manual approval each cycle. No live test email.
4. [ ] At the approved handoff, let the old full-deployment hourly job finish;
   prevent new/queued legacy writers from redeploying old code. Never cancel an
   active migration blindly. The shadow publisher now maintains fresh R2 data.
   Preserve a fresh legacy baseline and the pre-approved fallback; do not wait out
   the eight-hour digest limit on legacy readers.
5. [ ] Activate the reviewed main/environment protections and protected credential
   locations at this handoff, then merge #253 and #251 through reviewed PRs. Keep
   application deployment opt-in off until both are integrated. Authorize removal
   of legacy repository credential copies only after consumers/replacement are
   verified; otherwise older workflows retain access. Reject historical reruns.
6. [ ] Enable `FEED_PUBLICATION_ENABLED=true` for the configured data environment;
   start **Hourly vulnerability intelligence (data only)** (`publish-intelligence.yml`) on approved main.
   Confirm success and current source ages, then transfer scheduling ownership
   from the shadow runner. Conditional promotion protects against overlap, but
   investigate any race/failure. This job does not require application approval.
7. [ ] Run production preflight again immediately before release. Approve
   `deploy-worker-code.yml`, manual **`release_mode=phase1-integrity`** on the final
   reviewed main SHA. Do not use `cvie-maintenance` or the broad legacy
   `deploy-account-worker.yml`. The combined diff may intentionally fail automatic
   SQL classification; explicit Phase 1 mode is the reviewed route.
8. [ ] Backend release order: preflight → D1 recovery-point capture → additive
   **0031 → 0032 → recovery guard installation → integrity/recovery checks →
   compatible Worker deployment/build identity → backend verification**. Use the
   approved R2 binding/source configuration. Do not remove guards to bypass errors.
   No routine recovery hold is requested for a normal release; a recovery hold is
   an explicit maintenance action, with user-visible consequences.
9. [ ] Verify backend success and installed SELECT-only audit. Dispatch
   `bootstrap.yml` with **`deploy=true`** on the same compatible reviewed main.
   It checks backend identity/schema/hold state before frontend deployment.
   If it ran early, rerun after backend success; **there is no hourly frontend
   retry now**. Do not bypass readiness or enable another activation workflow.
10. [ ] Verify customer sign-in/access, existing reviewer/acknowledgement URLs,
    inventory/status/assignment flows, notification queues and preserved history
    using read-only observations or approved staging evidence. No production test
    customers/assignments/emails unless separately authorized. Inspect current R2
    versions/source age, digest and lifecycle selection, and the next scheduled
    data run. Provider acceptance is not proof of inbox delivery.
11. [ ] Confirm main protections and old credential retirement completed, retire
    the temporary shadow schedule after new ownership is proven, and retain
    rollback evidence. The hourly publisher stays enabled even when code releases
    are paused. Monitor missed/failed schedules and feed ages before limits expire.
    Phase 2 still needs separate user review and approval.

Normal R2 publication does not touch customer data or email delivery history.
The eight-hour digest and three-day lifecycle limits stay enforced. Upstream/R2/
GitHub outages can still delay notifications; do not hide them by extending limits.
A D1 recovery hold intentionally pauses account/reviewer access and scheduled mail;
it is not a no-interruption operation and must never be used as a setup test.

## 8. Recovery decision checklist (explicit approval required)

- [ ] **Data-only failure:** keep the last valid current pointer; inspect source age
  and collection status. Recollect or select a verified prior manifest using
  `feed_snapshot.py inspect`, then `rollback --manifest <prior-key>
  --expected-manifest <current-key>`. Use only the approved R2 identity. Never
  refresh old timestamps, delete referenced objects or reset mail delivery keys.
- [ ] **Reader/application failure:** keep the R2 publisher running. Prefer a
  compatible forward fix. Switching readers back to `legacy` is safe only if the
  old GitHub/site sources are actively updating and fresh; otherwise it restores
  the original stale-feed problem. Do not automatically rerun old deploy workflows.
- [ ] **Database recovery:** protected `recovery-write-hold.yml`, status → hold
  admission → drain to zero leases → freeze → approved compatible repair → clean
  installed audit/readiness → resume with current revision and reason. Follow
  [the detailed release/recovery procedure](remediation-phase1-release.md).
  Runtime/frontend availability is intentionally restricted during a hold. Do not
  infer that an old unleased Worker has drained from an empty lease table.
- [ ] A compatible `recovery-code-only` deployment leaves a frozen hold in place.
  Never deploy pre-Phase-1 code over retained canonical records or use an old
  schema-removal recipe. D1 time travel is separately approved disaster recovery:
  it may lose later writes/remove controls and requires reconciliation before resume.
- [ ] Preserve assignments, receipts, reviewer links, ticket references, history,
  queued/provider delivery evidence and normal expiration clocks. No automatic
  historical emails, data cleanup, reverse linking or token rotation is authorized.

## 9. Approval boundary and handback

You can now complete the **administrator worksheet and read-only inspection**.
Resource creation, token creation/relocation, security-setting enforcement, remote
staging writes and any production transition need their appropriate explicit
approval. Once approved resources/secure runner bindings exist, validation can run
without secrets in chat. Keep credentials for staging, audit and production
publication in separate sessions/environments.

This review changes documentation only. No new workflow, application feature,
resource, credential, GitHub security setting or production data was introduced.

References: [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches),
[GitHub environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments),
[Cloudflare D1 query permissions](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/),
[R2 tokens](https://developers.cloudflare.com/r2/api/tokens/),
[R2 pricing](https://developers.cloudflare.com/r2/pricing/).
