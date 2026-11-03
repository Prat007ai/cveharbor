# One permanent CVEHarbor staging environment

Reviewed November 3, 2026. This supplements the [administrator checklist](phase1-administrator-checklist.md)
and distinguishes the permanent application environment from disposable tests.
It authorizes no resource creation, deployment, import, migration or security change.
PRs #251 and #253 remain draft; the separate staging work in #243 is preserved.

## Decision

**Reuse the existing CVEHarbor Staging account, `cveharbor-accounts-staging` D1,
and both staging Workers. Do not create another staging account or permanent D1.**
They are a verified isolated foundation, not yet a complete production mirror.
Use synthetic data initially. Sanitized production refresh is a proposed later,
separately approved process, not an existing capability or prerequisite for Phase 1.

One staging account contains:

| Resource | Purpose and lifetime |
|---|---|
| Existing `cveharbor-accounts-staging` D1 | Permanent application database; complete reviewed schema, persistent test users/data; never a disposable harness target |
| Existing `cveharbor-accounts-staging` Worker | Private application backend, bound only to permanent staging D1 |
| Existing `cveharbor-site-staging` Worker | Access-protected frontend and same-origin API proxy; reuse its existing hostname |
| Proposed `cveharbor-intelligence-staging` R2 | Permanent private intelligence publication/history, bound to both staging readers after reviewed integration |
| `cveharbor-phase1-staging-<run>` D1, only when needed | Disposable synthetic migration/guard/regression tests; no permanent Worker binding |
| `cveharbor-intelligence-staging-<run>` R2, only when needed | Disposable empty-bucket publication/CAS/recovery rehearsal; no permanent reader binding |

The existing R2 harness writes fixed root keys and requires a fresh empty bucket.
It cannot safely share a populated permanent bucket via an arbitrary prefix.
A temporary bucket is therefore needed for that unchanged test, not another account
or application stack. Retain test evidence and request cleanup approval afterward;
the harness does not delete resources. Permanent storage retains referenced history;
do not apply blanket object expiry to immutable snapshots shared by manifests.

## Verified inventory and limits

Evidence: staging branch `codex/cvie-core-phase012`, commit
`01f5133f410053a733ba6c9e45df613114695ed6`, draft PR #243;
[run 41691571014, attempt 2](https://github.com/Prat007ai/cveharbor/actions/runs/41691571014)
and its downloaded, inspected
[artifact 13257996547](https://github.com/Prat007ai/cveharbor/actions/runs/41691571014/artifacts/13257996547).
Artifact ZIP SHA-256: `22795513d3f7238a5645af8a20f0b4cba21a7d5b733fabeaaec9707344aa744b`.
This review read the already completed run; it did not initiate or approve that deployment.

| Item | Available evidence | Remaining verification/configuration |
|---|---|---|
| Dedicated account | GET-only preflight at 18:21:32 UTC passed identity for `9706b4d98ad72884e67fd1eb875c8a61`; exactly two expected Workers and one expected D1 | Saved token account scope remains owner-attested: permission metadata returned 403. Confirm it excludes every production account in Cloudflare; successful calls alone do not prove scope |
| Permanent D1 | UUID `fac61562-fc31-426d-8032-550aba63b7f6`, expected name and Worker binding verified | Earlier staging diagnostics reported zero tables/12,288 bytes. Latest operation ran no migrations; its artifact does not include a fresh table count. Recheck schema read-only before any bootstrap; no full application schema is established by this evidence |
| API Worker | Deployment `9cf2324d-14e9-4818-8760-185247090fbc`, version `6c39aeca-a26f-4c39-bfdf-b41d4fc33e1d`; unchanged by latest frontend operation | Database-backed authenticated features and candidate #251/#253 code are not validated by the Access probe |
| Frontend Worker | Deployment `73fdd8bf-246c-4af0-9be9-3adfb805c624`, version `70dd01cb-56e2-4b23-bc66-5b59a4fc274e`; bindings verified | Complete application and R2 reader integration still needed |
| Access boundary | All 28 GET checks passed: six static asset classes, anonymous/forged denial, authenticated static 200, forbidden-Origin 403; `/v1/me` without application session 401; direct private API 404 | This is not a successful application login, acknowledgement, email or schema test. Preflight's missing response-cookie observation is not a failed post-deploy Service Auth test |
| GitHub environment | Workflow references `cloudflare-cvie-staging`; run used existing `CF_STAGING_*` values; protected operation completed | Reviewer/branch/bypass settings were owner-reported, not independently read through an admin API. Verify saved settings without changing them |
| Staging R2 | No R2 binding in reviewed staging configs; configuration validator explicitly rejects R2 | Bucket inventory was not queried. Absence of config is not proof that no bucket exists. Inspect/reuse a suitable existing private bucket before approving creation |
| Email/schedules | Artifact reports `email_enabled=false`, `schedules_enabled=false`; backend wrapper blocks outbound fetch, strips provider credentials and never invokes scheduled handler | Safe blocking exists, but no inspectable mail sink or full notification tests in hosted staging yet |
| Refresh tooling | Local schema builder and synthetic frontend builder exist | No reviewed production sanitization/import/refresh process established |

Source and artifact evidence are time-bounded. This workspace has no Cloudflare
credential binding and its network policy does not allow the Cloudflare API.
GitHub environment secrets cannot be retrieved into this shell. Direct live R2
inventory, current D1 schema and administrator settings remain unverified here.
Do not create replacements merely because this access is unavailable.

## Confirmed integration gaps to resolve before expanding staging

1. **Inventory guard assumes one D1.** At the reviewed #243 SHA,
   `staging/scripts/preflight.mjs` requires exactly one database and
   `diagnose.mjs` treats any additional database as unexpected. Adding the approved
   disposable D1 now would break the existing protected staging checks. First
   prepare/review an explicit inventory manifest: permanent name/UUID plus exact
   approved disposable name/UUID, with unknown resources still rejected. Do not
   remove the inventory guard or silently allow all databases with a name prefix.
2. **Bootstrap file misclassification on integration.** `staging/scripts/schema.py`
   sorts every migration, but excludes only 0028/0029 from
   `bootstrap-through-0027.sql`. The #243 source currently ends at 0029. Bringing
   #251's 0030–0032 into that tree unchanged would put them into the mislabeled
   baseline and could apply them before their intended prerequisites. Use an
   explicit checksummed baseline/migration manifest for the selected release;
   validate ordering locally before generating any remote script. A table count
   alone is not schema parity.
3. **R2 needs reviewed staging integration.** `configure.mjs` currently forbids
   `r2_buckets`; the backend wrapper does not forward `INTELLIGENCE_BUCKET` or
   `INTELLIGENCE_SOURCE`; the staging frontend is its own Access/ASSETS proxy,
   not the #253 production R2 reader. Adding dashboard bindings alone is insufficient
   and a later deploy can erase them. Integrate both readers behind existing Access,
   retain private API and same-origin rules, then test actual R2 requests.
4. **Blocked email is not interception with inspectable messages.** Existing flags
   and injected fetch stop delivery, but also prevent registration/OTP/email-based
   reviewer flows from being exercised normally. Prepare a staging-only capture
   transport using the same templates, recipient selection, payload and delivery
   bookkeeping, with synthetic provider responses and an authenticated message
   viewer/test interface. Cover direct fetch paths as well as common mail helpers.
   Do not add real SMTP credentials or simply turn delivery flags on.
5. **Full feature parity is not yet present.** All backend provider fetches are
   blocked, several monitoring features are disabled, and scheduled() is a no-op.
   Use recorded/synthetic provider adapters initially; selectively permit public
   intelligence collection only after egress review. Exercise the real scheduler
   against synthetic users with intercepted mail before enabling a staging cron.
6. **Permanent backend update path is missing.** The existing `deploy-workers`
   operation requires initially empty Worker inventory; `deploy-frontend` deliberately
   preserves the API. Neither is a routine full application release path for the
   existing permanent environment. Prepare a reviewed existing-resource release
   operation with fixed targets, schema gates, backend-before-frontend ordering,
   matching candidate SHAs and rollback verification. Do not rerun initial
   provisioning, delete/recreate Workers or loosen exact-SHA approval gates.

These are documented follow-up work, not implemented or deployed in this review.
They should be coordinated in the existing staging project and integrated draft
branches; do not merge #243 wholesale into #251/#253 without workflow/security and
schema-order review. No extra PR or automatic diagnostics project is required.

## Administrator configuration: reuse first

### Cloudflare

1. Select the existing account ID above. Inspect **Workers & Pages**, **D1**, **R2**
   and **Zero Trust → Access → Applications** read-only. Match exact D1 UUID, two
   Worker names, private API exposure, frontend service binding, Access issuer/AUD,
   active versions, schedule state and D1 schema. Save identifiers/aggregate evidence,
   never token values. Inspect R2 inventory before deciding anything must be created.
2. Keep `cveharbor-accounts-staging` permanent. After a separate migration approval,
   initialize it only if fresh inspection proves it empty, from the corrected full
   release-specific schema manifest. If nonempty, inventory/back up and migrate
   in place under an approved plan; do not reset it or use the disposable bootstrap.
   Include base SQL schemas, optional deployed features, indexes, foreign keys,
   triggers, migration ledger and Phase 1 recovery guards. Compare against a
   separately authorized production schema inventory, without copying customer rows.
3. Reuse a suitable private staging R2 bucket if present. Otherwise request approval
   for `cveharbor-intelligence-staging`, Standard storage, public access disabled,
   no production domains. Bind only staging readers after integration. Approve costs
   first; a bucket name does not itself isolate credentials.
4. Preserve existing staging management/Access credentials. Verify their saved scope
   names only: Workers Scripts Write, D1 Write, Account Settings Read, Access Apps
   and Policies Read, Access Service Tokens Read, restricted exclusively to this
   staging account. Do not expand scopes, rotate or replace credentials in this review.
5. For a later publisher, use bucket-scoped S3 Object Read & Write keys for the
   permanent staging bucket only. For disposable D1 use a distinct staging D1-only
   token; for disposable R2 use a token limited to that temporary bucket. D1 Edit
   may be account-wide, so it can reach permanent staging too: fixed UUID/name,
   synthetic marker, empty-target and operation guards are still required. No
   production credential belongs in any staging environment.
6. Request disposable resources only after the inventory manifest gap is fixed and
   the remote test window is approved. Keep permanent D1 UUID out of
   `STAGING_DATABASE_ID`, and never point permanent Workers at test databases.

### GitHub

Reuse **Settings → Environments → `cloudflare-cvie-staging`** for the permanent
application. Do not create a second permanent environment or rename working keys.

| Existing setting | Required value/source |
|---|---|
| Variable `CF_STAGING_ACCOUNT_ID` | `9706b4d98ad72884e67fd1eb875c8a61` (workflow also supports existing secret storage) |
| Variable `CF_STAGING_D1_DATABASE_ID` | `fac61562-fc31-426d-8032-550aba63b7f6` |
| `CF_STAGING_ACCESS_ISSUER`, `CF_STAGING_ACCESS_AUD` | Existing staging issuer/application values; existing variable/secret storage supported |
| Secret `CF_STAGING_API_TOKEN` | Existing staging-only management credential |
| Secrets `CF_STAGING_ACCESS_CLIENT_ID`, `CF_STAGING_ACCESS_CLIENT_SECRET` | Existing staging Access automation credentials |
| Variable `CF_STAGING_APPROVED_COMMIT` | Exact separately reviewed operation SHA; not permission for a later commit |
| Variable `CF_STAGING_PROVISION_ACTION` | Unset when idle. Do not arm or rerun any operation for this review |

Verify the existing selected branch `codex/cvie-core-phase012`, reviewer and disabled
administrator-bypass settings. Do not apply the production main-only/independent
reviewer checklist to this environment automatically: its current workflow and
owner-approved review arrangement differ. Any eventual move to reviewed main is an
explicit coordinated workflow/environment change. Do not approve historical reruns.

Keep `cloudflare-phase1-staging` as the **disposable job credential boundary**, not a
new Cloudflare account or permanent application. Its exact `CLOUDFLARE_STAGING_*`
secrets and `STAGING_*` variables remain in the administrator checklist. Both
environments identify the same staging account but different D1 UUIDs/operations.
Do not mechanically rename `CF_STAGING_*` to `CLOUDFLARE_STAGING_*`.

No permanent staging R2 publisher workflow/environment currently exists. When that
work is approved, a proposed `cloudflare-intelligence-staging-data` environment can
hold only `FEED_R2_ACCESS_KEY_ID`/`FEED_R2_SECRET_ACCESS_KEY` and variables
`FEED_R2_ACCOUNT_ID`/`FEED_R2_BUCKET=cveharbor-intelligence-staging`, with a reviewed
source branch restriction, read-only repository permission and no per-run approval.
It must not reuse `cloudflare-intelligence-data` (production) or have D1/Workers/mail
credentials. The existing disposable R2 CLI still uses a separately authorized
secure runner; creating an unused environment does not make it executable.

## Safe permanent staging refresh: design, not an executable runbook yet

Synthetic fixtures remain the default. A production-derived refresh needs explicit
approval of its dataset, sanitizer, runner, staging overwrite and recovery point.
Do not start with a raw production dump in staging or an Actions artifact.

1. Record production release/schema inventory and staging release/bindings. Approve
   a consistent read-only source export in a restricted runner with encrypted
   temporary storage and short retention. This is separate from the aggregate
   SELECT-only integrity audit; that audit is not authorization to export records.
2. Sanitize before import with a versioned, tested allowlist transformation. Remap
   tenant/customer/user/asset/record IDs consistently; preserve foreign keys,
   finding-to-remediation relationships, statuses, conflict cases, assignment and
   acknowledgement history, ticket relationships and event ordering. Replace
   names, domains, IPs, emails, URLs, free text, ticket values and attachments with
   synthetic equivalents; use `.invalid` recipients plus the no-egress mail sink.
3. Exclude production passwords/hashes, sessions, OTPs, MFA/encryption/signing/API
   secrets, live acknowledgement/reviewer bearer tokens, webhook/provider tokens
   and delivery identifiers. Retain historical acknowledgement outcomes as inert
   test history; issue fresh staging-only access links for active scenarios. No
   copied link/session may authenticate against either environment. Do not reset
   production data, secrets, expiry clocks or links.
4. Quarantine/remove pending mail/scan/retry work from the transformed dataset;
   retain synthetic historical delivery/dedup relationships without replay. Staging
   resets to verified email interception, disabled crons and staging-only endpoints.
   Test refresh idempotency and assert no production address, credential or URL
   survives. Include duplicate/link/conflict and ticket/history preservation checks.
5. Snapshot permanent staging; pause its writes/cron processing, drain in-flight
   tasks and apply the approved import plan only to the fixed permanent UUID.
   Preserve Access protections. Do not use Phase 1's production-pinned recovery CLI
   or the disposable harness for this operation. A staging-targeted refresh/recovery
   tool and table/load-order plan must be reviewed before execution.
6. Validate schema/checksums, foreign keys, integrity, expected transformed counts,
   account isolation, staging links and captured notifications; restore the prior
   staging snapshot on failure. Reapply intentional staging configuration and
   release writes only after checks pass. Record source bookmark, sanitizer version,
   target UUID, release SHA, approvals and aggregate results; securely delete the
   temporary raw export under the approved retention policy.

This process preserves representative behavior, not production authentication
material. Full production data is unnecessary for Phase 1 and would increase
cost/exposure. Preserve the permanent staging identity; approve any future refresh
that overwrites its test data rather than treating it as disposable.

## Remaining validation and recommended order

| Gate | Environment and evidence required | Current result |
|---|---|---|
| Foundation security | Existing staging Workers/Access, exact D1 binding and private API | Passed in inspected run, with token-scope/admin-setting limitations above |
| Inventory/schema integration | Exact permanent/disposable allowlist and corrected migration manifest; source parity review across #243/#251/#253 | Follow-up required before adding disposable D1 or using combined schema builder |
| #251 remote D1 | Disposable synthetic D1 in this same account; bootstrap once, validate twice; 0031/0032/guards, linking, duplicate prevention, history/receipt preservation, hold/resume | Not run by this review; permanent D1 must not replace it |
| #253 remote R2 | Disposable empty bucket; conditional write rejection, history, failure/rollback/restore | Not run by this review |
| Combined application | Permanent D1 + both staging Workers + permanent R2; corrected schema, full candidate code, synthetic users, mail sink | Pending integration and separately approved staging deployment/migrations |
| Production audit | Existing production DB; approved D1 Read identity; documented SELECT-only preflight | Separate pending gate; staging results cannot establish production integrity |

Recommended sequence: verify administrator metadata/inventory; prepare the six
integration gaps above in existing drafts; review those changes; approve only the
required staging resource/migration/deployment work; run disposable D1/R2 tests;
test the combined application on permanent staging; then run production preflight
and return to the existing #253 → #251 production approval checklist. No production
merge or feed-source change is needed to establish this architecture.

Permanent application acceptance must include customer sign-in and account isolation,
CVE Findings/Tracker linking and status synchronization, duplicate rejection,
assignment/acknowledgement/reviewer links, comments/tickets/history, receipt expiry,
digest eight-hour freshness and dedup, lifecycle freshness, reminders/FYI messages,
patch/malware/threat/history consumers, R2 outage recovery, scheduler replay protection
and write-hold recovery. Every email is captured in staging. Access success alone
does not satisfy these gates; staged workloads should exercise real templates and
handlers with synthetic identities and responses.

## Effect on customers and cost

This documentation-only alignment changes no production service, feed source,
customer record, assignment, acknowledgement, notification or security setting.
It removes the need for another staging account/permanent database. New cost is
limited to approved R2 storage/requests and actual staging Worker/D1 usage, plus
short-lived disposable tests; verify the account's current plan/quotas before adding
resources. No claim of zero cost or production readiness follows from this review.
