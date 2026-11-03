# Task 2C: CVIE Cloudflare Staging Environment and Validation Plan

**Status: resource names/account and repository preparation approved; configuration/scripts prepared on PR #243. Cloudflare resource creation, migrations and deployments remain paused pending secure credential setup.**

The owner supplied staging account `9706b4d98ad72884e67fd1eb875c8a61` (Workers Paid) and `cveharbor-staging.workers.dev`. The current [credential setup and preparation guide](cvie-staging-credentials.md) supersedes the original proposed Basic Auth gate, placeholder account/hostname and planned file paths below: Cloudflare Access now protects the frontend, initial provider calls are blocked, and implementation lives under `staging/`. The remainder records the full validation plan and original assessment baseline; remote results are still not available.

Prepared on 2 November 2026 for [PR #243](https://github.com/Prat007ai/cveharbor/pull/243), branch `codex/cvie-core-phase012`. Reviewed PR head: `41dc5b300b5de02e9733d78fe5566bd91c60e45a`; implementation measurements refer to `ea7fa077b3128ce024603f5e2abfd5afd9896d82`. The PR is open, draft and unmerged. This is the complete Task 2C plan, not a replacement for, or a link-only copy of, the [Task 2B implementation report](cvie-core-phase012.md).

## 1. Approval requested and scope

Approve implementation and validation of the staging arrangement below on the existing PR. Approval would authorize two staging Workers, one staging D1 database, staging-only configuration and credentials, and bounded synthetic tests. It would not authorize a main-branch merge, production changes, production data access, production load tests, live historical rescans, email delivery, automatic schedules, Queues or additional databases.

**Recommended security boundary: an owner-designated Cloudflare account containing no production resources.** Use a new staging deployment token restricted to that account. A different database in the production account isolates runtime bindings, but an account-scoped D1 deployment token may still be able to modify production databases. Naming and command checks alone cannot remove that credential-level risk. This plan therefore does not silently substitute the production account if a separate account is unavailable. Account creation or transfer of domains is not proposed here; the owner must provide an existing isolated account or arrange one and its billing separately.

The account and Workers subdomain are now supplied and pinned in the preparation. The database UUID will be assigned by Cloudflare after creation. Resource availability has not been verified remotely. Before deployment, record the returned UUID and validate it against the approved account and database name. Never infer it from production credentials.

### Exact proposed resource inventory

| Resource | Name / value | Bindings and exposure |
|---|---|---|
| API Worker | `cveharbor-accounts-staging` | `DB` → `cveharbor-accounts-staging`; no production binding; `workers_dev=false`, preview URLs disabled, no public route, no cron triggers |
| D1 database | `cveharbor-accounts-staging` | In the isolated staging account; UUID recorded after creation; only API Worker receives the runtime binding |
| Static frontend Worker | `cveharbor-site-staging` | `ASSETS` → synthetic staging build; `STAGING_API` service binding → `cveharbor-accounts-staging` |
| Frontend/browser origin | `https://cveharbor-site-staging.<STAGING_WORKERS_SUBDOMAIN>.workers.dev` | Exact hostname substituted from the owner-designated account; site gate protects all paths; no custom DNS needed |
| Browser API base | `/v1` on the frontend origin | Forwarded through `STAGING_API`; no public production API fallback |
| Native rate-limit binding | `ASSIGNMENT_ACK_RATE_LIMITER` | Staging account namespace `24302`, limit 60 / 60 seconds; first verify that the namespace is unused there |
| Protected GitHub environment | `cloudflare-cvie-staging` | Staging secrets only; required owner reviewer and branch restriction to `codex/cvie-core-phase012` |
| Deployment concurrency group | `cvie-staging-243` | Serialize deployment, migration, seeding and validation; do not cancel an in-flight migration |

There is no new Pages project, KV namespace, Queue, mail service, production route or production service binding. Two Workers mirror the repository's existing static-asset Worker plus account API Worker architecture. The same-origin service forwarding is a small staging routing addition and needs code/configuration work after approval; it is not present today.

## 2. Repository findings that shape the plan

Confirmed from the reviewed branch:

- `account-backend/wrangler.toml` targets the production API/database and includes hourly, five-minute and minute Cron Triggers. It is not a staging template that can be deployed unchanged.
- `site-gate/wrangler.json` and `site-gate/worker.mjs` serve the static build through an existing authenticated gate. Production routes target the main website. Reuse the implementation, not its routes, credentials or default config.
- No staging Wrangler configuration, staging workflow or staging secret set is present.
- Production API URLs occur in `accounts.js`, `cvie.js`, `inventory.js`, `customer-security.js`, `app.js`, `header-auth.js`, `command-center.js`, `account-security.js`, `account-page.js`, `workspace.js`, `workspace-page.js`, `workspace-dashboard.js`, `operations.js`, `product-monitoring.js`, `lifecycle-monitor.js`, `website-monitor-page.js` and `website-monitor-dashboard.js`.
- Fixed production origins also occur in backend authentication, CVIE, inventory, finding status, remediation, lifecycle, workspace summary, product monitoring, plugin sources/advisories, customer score and CVE lookup responses. Confirmation links and unsubscribe links have separate production host constants. Routing changes must cover the whole tested application, not only the CVIE page.
- Email login in `account-backend/src/index.js` calls SMTP2GO directly. Other sends use `delivery.js`, `monitor-mail.js`, lifecycle, assignment and report paths. No Cron Triggers plus disabled digest flags is insufficient proof of no outbound email.
- Saving a product can initiate bounded `waitUntil` discovery without a cron. That is distinct from scheduled processing and must use controlled fixture providers during these tests.
- Migrations `0028_cvie_source_efficiency.sql` and `0029_cvie_identity_registry.sql` are additive but install indexes/triggers which continue running when the serving flags are off.
- Existing production deployment workflows must not be dispatched or reused to choose staging targets. Newly added dispatch-only workflows may not be discoverable in GitHub's UI until present on the default branch; do not merge simply to make dispatch available.

The current managed environment has no configured Cloudflare credentials and permits package-manager networking, not Cloudflare API or staging-host access. No Cloudflare resource lookup has been performed. Those are execution prerequisites, not evidence that staging is unavailable in the owner's account.

## 3. Permissions, credentials and isolation controls

### Deployment permissions

Use a dedicated token with **Workers Scripts: Edit** and **D1: Edit**, restricted to the isolated staging account. Add **Workers Tail: Read** for protected diagnostic capture and **Account Analytics: Read** only if needed for aggregate D1 analytics. Verify Cloudflare's current permission names and prerequisites at provisioning; request any additional permission explicitly rather than falling back to a broader production token. The selected workers.dev/service-binding design requires no production zone, DNS or Workers Routes permission. No account membership administration is needed.

GitHub needs `contents:read` for the deployment job and a protected environment for secrets; ordinary evidence artifacts can use the Actions artifact service. It does not need permission to merge, publish GitHub Pages or write production environments. Documentation/source updates stay on PR #243.

### Proposed secret names and placement

| Secret / variable | Placement and purpose |
|---|---|
| `CF_STAGING_API_TOKEN` | Protected CI environment only; map temporarily to Wrangler's token variable in the staging job; never inject into a Worker |
| `CF_STAGING_ACCOUNT_ID` | Protected environment variable and validated target manifest; not a production account ID |
| `STAGING_SITE_GATE_PASSWORD` | New independent secret; installed as frontend `SITE_GATE_PASSWORD`; gate username `cveharbor-staging` |
| `STAGING_TOTP_ENCRYPTION_KEY` | New independent secret; installed as API `TOTP_ENCRYPTION_KEY` if MFA fixtures/enrollment are exercised |
| `STAGING_TEST_TOKEN` | Independent short-lived API test-control secret; only the staging build and authorized fixture driver use it |

Do not install SMTP2GO, production NVD, webhook, Web Risk, assignment, production gate or production MFA secrets. Test-control routes will exist only in the staging build, require the gate plus the independent test token, and expose a fixed set of bounded fixture operations—not arbitrary SQL, target URLs or application authentication bypasses. Ordinary `/v1` calls must still authenticate real synthetic sessions and enforce tenant ownership. Remove test-control access and expire synthetic sessions after the campaign.

### Mandatory safety checks

1. Resolve explicit staging configuration paths; disallow the default `account-backend/wrangler.toml` and `site-gate/wrangler.json` in every staging script.
2. Require an exact allowlist of staging account ID, database UUID/name, Worker names, service target and browser origin. Independently reject production names `cveharbor-accounts`, `cveharbor-site`, and production D1 UUID `46710e51-7ca4-4571-b89c-921b9969de0b`.
3. Validate the deployed bindings using the Cloudflare management API after deployment. A missing, extra or mismatched DB/service binding fails the release check.
4. API Worker has no deployment token, production service bindings, production routes or public workers.dev URL. D1 SQL cannot select another database without its binding or API credentials.
5. Site gate runs before assets, API forwarding and test controls. Strip gate Authorization headers before forwarding; preserve the session cookie, method, body and Origin for application authentication. Reject unapproved Host/Origin values.
6. Browser uses a host-only `cvh_session` cookie on the staging frontend, retaining Secure, HttpOnly and SameSite=Strict. Same-origin `/v1` avoids cross-site cookie problems between separate preview hostnames. Do not set a parent-domain cookie.
7. Build staging assets into `public-staging`, with synthetic intelligence JSON only. Never run a production deployment helper or a live feed collector to build them. Audit generated JS, links, service workers and CSP; fail if an executable API path falls back to production. Browser request interception additionally fails tests on any production host request. CSP `connect-src` restricts application requests to the staging origin.
8. Require an outbound-email hard stop before every transport call. Omitted credentials are defense in depth, not the sole control. Fixture-provider mode forbids live vulnerability, monitoring, webhook and mail calls; count denied/attempted calls without logging payloads.
9. Request network allowlisting only for `api.cloudflare.com` and the exact staging frontend hostname, plus existing package installation hosts. Do not request production or mail-provider access for this campaign.

A separate account plus absent runtime credentials/bindings protects production even if a staging fixture script is incorrect. Test fixtures and control credentials still require protection because anyone possessing staging deployment credentials could modify staging.

## 4. Configuration and deployment changes proposed after approval

These paths are planned, not files already implemented:

| Path | Intended change |
|---|---|
| `account-backend/wrangler.staging.toml` | Explicit API name/account/D1 UUID; compatibility date `2026-10-28`; `keep_vars=false`; no routes or schedules; staging flags/secrets only |
| `site-gate/wrangler.staging.json` | Explicit frontend name/account; `ASSETS` from `../public-staging`; gate enabled; staging API service binding; workers.dev enabled and preview URLs disabled |
| `scripts/cvie-staging-target.mjs` | Fail-closed target/config validation and deployment manifest checks |
| `scripts/cvie-staging-schema.mjs` | Ordered, checksummed bootstrap/migration manifest; staging-only SQL execution and schema verification |
| `scripts/cvie-staging-fixtures.mjs` | Deterministic synthetic fixtures, bounded reset and aggregate snapshots |
| `scripts/cvie-staging-validate.mjs` | Authenticated remote API, D1 and source-processing scenarios |
| `scripts/cvie-staging-browser.mjs` | Playwright save-to-visible-result timings and browser routing/tenant checks |
| `.github/workflows/cvie-staging.yml` | Protected, serialized staging build/deploy/validation workflow; no production credential references |
| `docs/cvie-staging-validation.md` and `docs/cvie-evidence/staging/` | Final results, manifests, redacted measurements and release blockers |

Supporting code will centralize trusted frontend API/origin selection, adjust the existing site gate to forward staging `/v1`, add complete email/schedule guards, and introduce a staging-only fixture/test-control entrypoint. Production defaults and public API contracts remain compatible. No runtime origin can be selected by an untrusted query string or user header. All browser-facing backend response helpers must use the trusted configured origin, not just the outer handler.

**Initial flags:** `CVIE_METRICS_ENABLED=true`, `CVIE_SHARED_SCANS_ENABLED=true`, `CVIE_REGISTRY_ENABLED=false`, `CVIE_FAST_EVIDENCE_ENABLED=false`, `REMEDIATION_WORKFLOW_ENABLED=true`. Keep acknowledgement/progress/FYI application semantics available for regression tests, but disable their transport using `ASSIGNMENT_EMAIL_ENABLED=false` and the global hard stop.

Explicitly set `ALERT_DELIVERY_ENABLED`, `LIFECYCLE_DELIVERY_ENABLED`, `PRODUCT_MONITOR_DELIVERY_ENABLED`, `PRODUCT_MONITOR_TEST_ENABLED`, `PRODUCT_MONITOR_CHECKS_ENABLED`, `PLUGIN_MONITOR_ENABLED`, `WEBSITE_MONITOR_ENABLED`, `WEBSITE_MONITOR_MANUAL_ENABLED` and `WEB_RISK_ALERT_TEST_ENABLED` to `false`. Proposed new staging controls are `OUTBOUND_EMAIL_DISABLED=true`, `SCHEDULED_JOBS_ENABLED=false`, `CVIE_PROVIDER_MODE=fixtures`, and `STAGING_MODE=true`. They require implementation/tests; setting unfamiliar environment variables alone does nothing today. Keep migration-0026-compatible remediation behavior enabled.

A manually authorized staging action can exercise bounded discovery with fixture sources. No schedule is enabled. Live-provider calls, external website scans and actual notification delivery remain outside this approval request.

### Workflow activation without merging

Prefer a protected staging job triggered by pushes to the existing branch and only designated staging implementation paths, with required environment approval before receiving credentials. It checks out a pinned commit and refuses any other branch/PR target. Add `workflow_dispatch` for later use, but do not depend on it appearing before merge. Documentation-only pushes must not trigger deployment. If repository policy prevents a protected branch workflow from running, use the same reviewed scripts from an approved staging runner; do not merge or alter production workflow triggers as a workaround.

## 5. Ordered deployment and schema plan

1. **Approval and prerequisites.** Confirm isolated account, workers.dev subdomain, account plan/quota, reviewer and token placement. Confirm resource names are unused. No overwriting an existing similarly named environment.
2. **Prepare PR changes locally.** Implement proposed configs/guards/fixtures, run existing backend/Python/frontend suites, validate configuration schema and dry-run both bundles. Negative tests deliberately substitute production targets and must fail before any cloud request.
3. **Create the approved D1 database.** Capture returned UUID/account/name in the target manifest. Create no other database. Register the two approved Worker names through their first staging deployments; API stays private and schedules absent.
4. **Bootstrap full pre-0028 schema.** Use `account-backend/schema.sql`, the applicable auxiliary SQL files and migrations `0016`–`0027`. Existing schema.sql already incorporates some auxiliary definitions; derive a dependency-ordered manifest and validate it on empty local D1 before remote application. Do not blindly replay every SQL file, mark unexecuted migrations complete, or treat the profiling script's minimal schema as the application schema. Include inventory/package/software history, TOTP, findings/tickets/history, remediation, alerts, customer score, plugin and lifecycle tables.
5. **Seed and measure baseline.** Load deterministic synthetic data and privacy snapshots; record schema hashes, source checkpoints, D1 storage and migration ledger. Run baseline cases before new indexes exist. Capture a staging-only export/recovery bookmark. The legacy baseline bundle uses the same staging safety/origin guards and a pinned pre-0028 implementation; never deploy an unguarded old production bundle.
6. **Apply 0028, then 0029.** Record exact migration checksums, returned per-statement D1 metadata, execution time, schema/index/trigger definitions, foreign-key checks and data invariants after each step. Existing earlier draft migrations require a separately reviewed forward patch; never reset the ledger and replay them. All remote commands explicitly select the staging config and UUID; the target validator runs before each operation.
7. **Deploy compatible optimized API/frontend.** Verify actual bindings, disabled schedules/mail and synthetic asset manifest. A health route reporting mail unavailable is expected; readiness checks must distinguish that from DB/application failure.
8. **Enable registry, then fast evidence.** Hydrate only already stored synthetic intelligence in bounded pages (at most 100 per work unit), with lease/checkpoint tests. Measure one-time hydration separately. No external historical rescan substitutes for index hydration.
9. **Run the matrix below and rollback drill.** Store complete raw numeric samples and redacted evidence. Leave the PR draft and provide the resulting report for review.

Bootstrap, migration and seed costs are reported separately from steady-state ingestion/serving. If dataset cases require reset, only deterministic synthetic namespaces in the allowlisted staging database may be reset, after preserving invariant fixtures and exporting evidence. No destructive schema rollback is planned.

## 6. Test data and validation matrix

Use 50 synthetic customer accounts and 5,000 assets distributed as 100 assets/account. Include independent owners, catalogues, private versions, watchlists, findings, tickets, audit history, accepted-risk decisions and mixed notification preferences. Addresses use `example.test`; domain/plugin links use non-routable test fixtures. Existing account inventory limits remain unchanged; this test does not certify 5,000 assets inside one MSP account.

Create valid expiring sessions and MFA state through the staging fixture driver using the same hashing/encryption formats as the application. Install cookies into isolated Playwright contexts. This tests actual authenticated application routes; it does not certify outbound-email login. Also test expired/invalid sessions and MFA enforcement. No production sessions or customer exports are used.

| Area | Cases and required evidence |
|---|---|
| Product identity | Microsoft .NET Framework vs .NET Runtime vs ASP.NET Core; WordPress Core vs named plugin; PHP, Python, Windows Server, SQL Server, MySQL, MariaDB, Ubuntu, Debian |
| Incomplete identity | `Durpal`/`WordPres` suggestions require explicit selection; `.NET`, `SQL`, `Linux`, missing vendors and missing versions request guidance; unresolved saves retain explicit missing-coverage status |
| Immediate CVEs | Preindexed products show stored CVEs with provider fixtures forced to fail/delay; record product relevance separately from installed-version applicability |
| Shared work | Simultaneous same-product saves at 1/10/50 accounts; one shared scope/job per normalized identity; duplicate saves do not duplicate private subscriptions; test cold scopes, expired leases and retry fencing |
| Coverage | Empty, partial, stale and failed provider responses never become “safe”; distinguish zero known records from complete coverage; source freshness reflects actual fixture processing |
| Source correctness | Unchanged/changed KEV, authoritative correction/removal, CNA reject/reinstate/withdrawal, malformed or incomplete input, 429, timeout and 503; accepted evidence survives provider outages |
| Read behavior | Suggestions, bounded status and evidence reads produce zero D1 writes; count authentication queries as part of total route cost |
| Cross-application parity | Explorer, inventory, customer dashboard, reports, lifecycle, remediation, alerts and notification preferences; verify permitted changes explicitly and all unrelated snapshots remain identical |
| Isolation | Cross-account product/evidence/finding requests fail; no private versions in shared identities; unauthenticated API rejected; gate credentials not forwarded; no production network request |
| Scheduling/email | No Cron Triggers; scheduled handler no-ops under staging guard; login, sample/report, alert, lifecycle, assignment and test-email paths cannot reach a provider; zero sent notifications |

Initial provider fixtures are small bundled synthetic responses; large CVE fixtures are seeded directly into staging D1. Test controls invoke existing ingestion functions through a narrow staging-only adapter, one bounded step at a time. They do not add general-purpose remote SQL or a public rescan endpoint. Live-source authentication, freshness under real rate limits and actual email delivery remain unverified by fixture tests and must be labeled as such.

### Real browser latency protocol

- Use current Chromium/Playwright in a recorded runner region, initially North America; record browser/runtime version, runner CPU/memory, network RTT and Cloudflare request/colo metadata. Do not call this a global latency guarantee.
- Run 1, 10 and 50 separate authenticated browser contexts, with coordinated save clicks. Login/fixture creation is outside the measured interval; page-ready timing is recorded separately.
- Start at the save click; stop only when the correct account/product's first CVE row is visible in the DOM, not when a save response arrives. Also record save acknowledgement, evidence response, first paint and background completion separately.
- For each concurrency level collect at least 200 operations: 200 single operations, 20 waves of 10 and four waves of 50. Separate warm known-product, cold scope and hydration scenarios; do not hide cold results inside warm percentiles. Repeat failed or borderline scenarios only with a stated reason and retained original samples.
- Capture p50/p95/p99/max, errors, timeouts and first-page result correctness. Resource-saturated load generators invalidate a run and must be identified. A 50-context test may require multiple runner processes/hosts; all must stay within the approved aggregate 50-customer concurrency.
- Store redacted traces/screenshots with synthetic names. Never upload cookies, Authorization headers, TOTP secrets, raw session tokens or credential-bearing HAR files.

### Remote D1 protocol

Test 10,000 and 100,000 synthetic CVEs at 0%, 10% and 100% mapped-product density, plus bounded multi-product fan-out at 1, 5 and 20 relationships/CVE on a 10,000-CVE subset. This distinguishes the fraction of mapped records from relationships per record. Report exact generated relationship counts and retained evidence rows, not just CVE totals.

Compare equivalent inputs across pre-0028 baseline, optimized flags-on and optimized flags-off. Run the baseline dataset matrix before migration, retain results, then repeat on the migrated database; do not remove indexes just to recreate a baseline. Record cache/warm-up conditions. Benchmark 100-result pages, repeated unchanged ingestion, changed relationships, onboarding, hydration and mixed ingestion-plus-serving. The baseline matrix may use a pinned legacy bundle in the same isolated environment; synthetic rejection/parity checks apply to the optimized and rollback builds.

Collect every D1 result's `meta.rows_read`, `meta.rows_written`, duration and available execution/location/retry metadata; keep Worker wall time separate from engine time. Aggregate batches without double-counting. Trace per-operation groups using non-identifying run IDs, never SQL parameter values or customer records. Reconcile with database/account analytics for the isolated time window when available. Explain missing metadata rather than estimating it as measured.

Measure database storage before/after schemas, indexes, hydration and each fixture size using D1 management metadata and supported SQLite page metrics. Validate availability of per-object statistics such as `dbstat`; if unsupported, report controlled whole-database deltas rather than invented per-index byte counts. Reuse can leave free pages allocated, so distinguish allocated size, live data and reclaimable pages where measurable. Report migration/index creation writes as well as ongoing trigger/index maintenance with serving flags disabled.

**Proposed bounded campaign:** at most 100,000 CVEs resident per primary dataset, 50 concurrent users, 5,000 assets, 50 million cumulative D1 rows read and 10 million written, and 1 GB staging database storage. These are stop limits, not predicted usage or a pricing quote. Check metadata between bounded batches, allowing for the in-flight batch, and stop before the remaining budget is insufficient. Confirm account allowances and any additional account subscription cost before creation. If limits prevent completing a case, report it and seek an explicit budget revision; never continue silently. No open-ended load or background loop is authorized.

## 7. Acceptance criteria and comparison baseline

The numbers below are **previous local results**, not staging measurements.

| Metric | Previous local result | Staging gate |
|---|---|---|
| Save + stored first-page API sequence p95, 1 / 10 / 50 customers | 25 / 148 / 263 ms; excludes browser/network | Real save-to-visible-CVE p95 **under 2 seconds** in each measured concurrency cohort |
| 100-result evidence page | 409 reads, zero writes at 10k/100k CVEs | p95 **≤1,000 reads**, zero writes; bounded retrieval and ordered-index query plan |
| Unchanged 1,766-entry KEV | 11 reads; 2 source-state writes; zero KEV content writes | Zero vulnerability/relationship rewrites; source bookkeeping counted separately |
| 10%-mapped ingestion | 53,000 legacy → 58,000 optimized writes; reviewed implementation was 70,000 | Equivalent remote cost and attribution; investigate deviations >10% after accounting for fixture/schema differences |
| 100%-mapped ingestion | 80,000 legacy → 130,000 optimized writes | Explicitly report retained overhead; do not apply the 9.4% sparse-case claim to dense data |
| Representative mixed subset | 617,869 → 201,351 reads; 73,080 → 61,080 writes | Report the same mixed workload and density sensitivity; no claim that every workload improves |
| Shared discovery/hydration | One scope/job under concurrent repeated selections | One active shared work item per identity; no duplicate private subscriptions or concurrent duplicate provider work |
| Safety and parity | Local regression coverage passed | Zero unauthorized tenant access, production requests, emails, unrelated private-data changes or resurrected rejections |

At each density, report total ingestion, serving, hydration and index storage costs, including a break-even lookup frequency if ingestion becomes more expensive. “Unacceptable overhead” has no universal approved numerical threshold yet; a dense write-heavy workload that worsens total cost must remain a disclosed release decision, not be marked passed because reads are fast. A failed latency/read gate blocks production readiness; no full Phase 4 rewrite is authorized as an implicit workaround.

All representative identity fixtures must produce their specified outcomes. These cases do not establish broad precision/recall, complete installed-version evaluation, distribution backport correctness or sustained real-provider freshness. Potential relevance remains `requires_version_review`; missing information never certifies an asset as unaffected.

## 8. Rollback drill and recovery

1. Stop new test admission and let bounded in-flight work settle. Record migration checksums, fixture/private-data hashes, source watermarks, queue observations, leases and hydration cursors.
2. Disable `CVIE_FAST_EVIDENCE_ENABLED`, then `CVIE_REGISTRY_ENABLED`. Retain the compatible ingestion code, rejection handling and `REMEDIATION_WORKFLOW_ENABLED=true`. Do not roll back to a writer that replaces all KEV rows or revives rejected CVEs.
3. Verify legacy reads and explicit incomplete-coverage messaging. Expect legacy query costs to return; record them. Confirm findings, decisions, history, preferences and subscriptions remain unchanged except the deliberate test mutations.
4. With both flags off, ingest a small valid correction, KEV removal and rejection fixture. Check source and projection indexes/triggers remain correct and measure their writes. Feature flags do not disable this database overhead.
5. Re-enable the registry and fast path, resume existing bounded cursors, verify corrections and absence of duplicates, and compare snapshots. No full historical rescan is allowed.
6. Exercise a controlled lease interruption and restart, plus migration failure/retry behavior locally before remote use. Use staging exports/bookmarks for recovery only after stopping the campaign and verifying the target; a whole-database restore is not a safe production rollback over newer customer activity.

No table/index/trigger deletion or migration-ledger reset forms part of rollback. If schema application or source integrity fails, stop, preserve evidence and propose a forward fix. The final report must distinguish a tested **remote staging** flag rollback from the existing local rollback test.

## 9. Deliverables, effort and release decision

The final staging report will contain exact deployed commits/config hashes, approved resource IDs/bindings (no secrets), migration ledger and checksums, fixture manifests, browser sample counts/percentiles, D1 operation totals and storage deltas, index/trigger attribution, flags-off results, no-email/no-production checks, tenant/parity evidence, rollback results and remaining blockers. Attach machine-readable numeric results and sanitized browser evidence. Every result is labeled local, remote staging, fixture simulation or not run.

Estimated work after prerequisites and approval:

| Work | Estimate |
|---|---|
| Isolated configuration, trusted origins/service routing and fail-closed guards | 1–2 engineering days |
| Complete schema bootstrap, synthetic fixtures and deployment workflow | 1–2 days |
| Remote/browser/D1 instrumentation and first bounded campaign | 2–3 days |
| Rollback/parity checks, analysis and report | 1–2 days |

Total: approximately **5–9 engineering days**, excluding account setup, owner approvals and fixing newly discovered defects. These are planning estimates, not measured execution times.

### Current release blockers

1. Approval of the [final resource creation plan](cvie-staging-resource-creation-plan.md). Credential/Access setup and remote metadata checks are complete; the owner has manually confirmed the five management-token permissions and exclusive staging scope.
2. Prepare the protected provisioning job and approval/SHA gates described in that plan. The existing protected environment has successfully run read-only checks; no creation/deployment job is enabled yet.
3. Remote bootstrap/fixture preparation and validation. Staging routing, email/schedule guards and local schema/build checks are prepared; full authenticated performance fixtures remain subsequent work.
4. Successful remote migration, browser latency, D1 density, tenant/parity and rollback results.
5. Separate production review and approval after the staging report. No merge or production rollout follows automatically from passing staging.

**Current outcome:** ready to request bounded resource-creation approval, combining remote preflight results with manual owner verification. See the [updated readiness assessment](cvie-staging-preflight.md) and final creation plan. Staging configuration and local safety/build helpers are prepared. Remote application/performance validation has not run and no Cloudflare resources have been created or deployed. The original implementation/validation sequence above remains the scope for subsequent work, with Access and the approved account replacing earlier placeholders.
