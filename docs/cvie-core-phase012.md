# Task 2B: CVIE Core Improvements — Phases 0–2 Implementation and Deployment Report

Date: 2 November 2026. Status: **implemented on a dedicated branch; validation incomplete; NOT approved for production rollout.**

- Draft pull request: [#243](https://github.com/Prat007ai/cveharbor/pull/243).
- Branch: `codex/cvie-core-phase012`.
- Initial main baseline: `3b9dfce`; integrated main through `1abc7cddc9e4ea5c4f3f6bf84792dac31393bb01`, including PR #242.
- Task 2 assessment baseline: `4004859b66a37942fa606b7d8fbaeddd4c674c8f`.
- Implementation reference: [full approved Task 2 design](https://chatgpt.com/space/page_0a2d074c11588191a26655dd7767980b), especially sections 10 and 11. This document contains the full Task 2B implementation report, rather than a link-only placeholder or Task 1 report.

## 1. Outcome and release decision

The branch implements opt-in canonical product identification, bounded immediate access to stored CVEs, shared discovery reuse, differential KEV ingestion, rejection/withdrawal corrections, and operation-level D1 telemetry. It adds the minimum indexed serving path requested for Phase 2; it does not implement the complete Phase 4 architecture.

The measured evidence-read target passes in local Miniflare D1: **409 rows read, zero rows written per 100-result page at p95**, with both 10,000 and 100,000 synthetic CVEs. An unchanged 1,766-entry KEV snapshot produces **zero KEV content rewrites** and two source-state writes, versus 5,300 total writes in the baseline fixture.

These results do **not** establish production readiness. Fifty-account local concurrency deduplicates work correctly but shows approximately **6.7 seconds p95 service orchestration latency**, above the save/first-page targets. Remote staging, end-to-end browser latency, a representative held-out accuracy corpus, and full 5,000-asset account validation remain outstanding. New indexes also increase measured ingestion writes; their production cost has not been approved.

No production deployment, migration, configuration change, historical rescan, or load test was performed. Production access was limited to fixed read-only aggregate diagnostics. No customer names, asset details, versions, emails, or credentials are included in the evidence artifacts.

## 2. Repository review and overlapping work

Implementation uses a dedicated worktree and branch; the original checkout and unrelated generated files were not committed. Main was reviewed against the assessment baseline before editing. PRs #239–241 added confirmation-domain, reviewer-progress and live-probe changes; later main changes from PR #242 were merged without conflicts. CVIE core files had not changed from the assessment baseline during that review.

Migration `0027` already belongs to assignment progress. This branch uses additive `0028` and `0029`. Recheck numbering immediately before merging because other development sessions can add migrations. Existing open PRs #92/#93 overlap Linux/public advisory collection; their older feed changes need explicit reconciliation with `scripts/update.py`, not a blind merge.

The branch preserves existing private product IDs, customer selections, subscriptions, installed versions, finding decisions, remediation history, notification preferences, and report API shapes. It introduces no automatic finding reopening/closing and no new notification sends. This preservation is verified in local regression fixtures; a remote staging snapshot comparison is still required.

## 3. Implemented behavior

### Phase 0: measurable operations

`account-backend/src/cvie-metrics.js` wraps D1 statements and batches when `CVIE_METRICS_ENABLED=true`. It records a random trace ID, a fixed operation name, statement count, duration, D1 rows read/written, metadata completeness, and success. Ingestion can add bounded processed/failed and KEV differential counters.

Logs exclude SQL, bindings, private account/product identifiers, customer content, credentials and raw provider exceptions. Missing D1 metadata is reported as unknown, not zero. The public source cache retains the original DB binding as its key so instrumentation does not create a new cache namespace per request or retain failed promises.

The new read-only diagnostic script collects aggregate source/queue state and a synthetic public PHP lookup through the existing reconciliation query. The SQL guard rejects mutation and stacked statements; every returned query metric must report zero writes. It does not read billing analytics or change production records.

Migration `0028` records enqueue and first-attempt timestamps for newly observed queue entries. Existing queue ages remain unknown; no fabricated historical timestamps are backfilled. Sustained processing rate requires repeated observations or enabled telemetry. One snapshot cannot prove throughput.

### Phase 1: source correctness and write reduction

**CISA KEV:** ingestion validates and hashes normalized content. Identical content skips all KEV record mutations. Changed snapshots update only changed/new entries and remove entries no longer in the accepted authoritative snapshot. Same-date content corrections are retained. Malformed responses, provider failures and suspicious large catalogue reductions preserve the previous accepted intelligence. Source check/lease state still changes on successful checks.

**Original disclosures:** content hashes include affected-product assertions. An identical retry acknowledges queue work without rewriting the CVE and its family links. Changed assertions update only the relevant rows, including corrections with an unchanged revision label. Queue insertion avoids requeuing an identical revision and priority. Claims recheck due time to reduce stale selection races.

**Rejected and withdrawn records:** the public collector keeps source observations separately. Withdrawal of one advisory no longer erases independent valid evidence. Global CVE rejection creates a tombstone that prevents resurrection from another feed; a subsequent valid authoritative revision can restore the CVE. Current KEV membership is no longer sticky after removal. Historical records whose independent payloads cannot be recovered are explicitly marked for review rather than reconstructed from guesses.

**Read behavior and outages:** ordinary CVIE GETs no longer perform coverage repair. Repair is explicit through synchronization/background processing. Stored evidence survives provider outages. Fast responses state that the index is partial and that missing results do not establish safety. Legacy completeness limitations and the public advisory cap are not removed by this branch.

### Phase 2: identity and immediate stored evidence

The compact reviewed registry starts with **19 identities**, including separate .NET Framework, .NET Runtime, ASP.NET Core, SDK and a NuGet package example; WordPress Core and a plugin example; PHP, Python, Windows Server group/releases, SQL Server, MySQL, MariaDB, Ubuntu, Debian and Drupal. It is an extensible starting set, not a claim to cover every product or plugin.

Verified aliases, vendor constraints, CPEs, package identifiers, lifecycle keys and version schemes remain distinct. Exact verified identifiers can bind automatically. Fuzzy matches produce suggestions requiring customer selection. Ambiguous names such as `.NET`, `SQL` and `Linux` remain unresolved until the exact component/vendor/release is identified. A typo such as `Durpal CMS` is suggested as Drupal, not silently corrected.

A confirmed provider CPE may create a public registry identity using provider-derived names and identifiers. Customer-entered aliases, installed versions, inventory and remediation decisions are never copied into the shared registry. Private identity bindings retain the original product name/vendor/CPE snapshot; changed private inputs cannot continue using an obsolete binding silently.

Customers can save unresolved products. Responses explain `identity_required`, `package_sources_required`, or `indexed_partial`; none means unaffected. Broad Windows Server groups require a concrete release/component. Packages without a supported CPE serving path retain their package identity and explicit incomplete coverage guidance. Ubuntu/Debian vendor backports and unsupported version comparators remain unknown pending later matching work.

Catalogue and inventory saves register the product before acknowledging the save when registry mode is enabled; external provider discovery remains background work. Existing lifecycle monitoring receives verified identity metadata while retaining its own release, consent and notification workflows. Existing private product/subscription IDs remain stable. A same-account concurrent subscription race was corrected by selecting the persisted product ID instead of using a losing generated UUID.

### Minimum indexed lookup, not full Phase 4

`cvie_identity_evidence` is a compact shared association/projection pointing to the existing NVD/CNA/KEV records. It does not replace those source stores or duplicate complete source records. A compound index on `(identity_id, sort_date DESC, cve_id DESC)` selects at most 101 rows for a 100-result page; subsequent joins use source primary keys. Keyset pagination avoids an unbounded offset or full result download. Current KEV evidence can remain visible outside the ordinary history window.

Raw NVD configuration trees and CNA affected assertions are retained. Returned evidence is a product-level candidate, explicitly `requires_version_review`; it is not a new assertion that a customer's installed version is affected. Negative assertions and rejected records are respected, with a bounded negative-assertion list and explicit truncation status.

Stored results appear before background discovery finishes. The client renders the first page and exposes explicit pagination; it does not fetch every page before rendering. Partial results cannot generate a misleading complete customer security score or overwrite score history. The standalone customer report route retains its legacy complete-fetch contract and its existing limitations.

Existing shared scopes deduplicate external discovery. A separate public-only, unique-per-identity index job hydrates stored associations in bounded pages, with a durable cursor, lease token and fenced commits. New identity priming handles up to three initial empty pages before yielding; subsequent work is bounded in the existing minute dispatcher. This is local indexing, not an external historical rescan. Large or newly recognized families can therefore remain partial until stored associations are hydrated.

## 4. API, data flow and compatibility

```text
Catalogue / inventory / lifecycle selection
  -> exact registry identity or explicit unresolved private product
  -> stable private product + subscription + identity snapshot
  -> existing shared scope / deduplicated local index work
  -> indexed stored evidence page -> immediate CVIE presentation
  -> existing bounded provider dispatcher for missing/stale coverage
  -> changed source records -> association triggers -> later evidence pages
```

| Contract | Behavior |
|---|---|
| `GET /v1/cvie/directory` | Read-only, bounded exact/prefix/typo suggestions; no fuzzy auto-selection. |
| Existing catalogue/inventory save routes | Additive identity metadata; existing private IDs and compatible payloads retained. |
| `POST /v1/cvie/sync` | Explicit registration/coverage repair; unchanged saves do not create additional shared scopes. |
| `GET /v1/cvie?view=bounded` | Lightweight progress/source shape when both serving flags are enabled; avoids the legacy full reconciliation/count path. |
| `GET /v1/cvie/products/:id/evidence` | Authorized product/scope lookup, bounded page, source evidence, uncertainty and cursor. |
| Existing `/v1/cvie`, `/v1/cvie/advisories`, identity-option routes | Legacy compatibility retained; validated provider choices can join the registry. |

Existing authentication and ownership checks apply before private routes. Evidence authorization checks the account, product and active subscription scope. Sign-out clears private client state; stale account/history-window responses cannot be applied to a new session. Public registry and source cache keys contain no tenant-specific asset or version information.

## 5. Actual baseline and performance measurements

### 5.1 Production: read-only baseline, not an after-deployment result

Evidence: [production-baseline.json](cvie-evidence/production-baseline.json), captured **2026-11-02 20:00:19 UTC** through the existing CI credentials. The diagnostic workflow ran only fixed read-only queries and reported zero writes for every statement.

| Observation | Measured result |
|---|---:|
| Existing public PHP reconciliation lookup | 5 returned CVEs; 2 statements; **336,509 rows read**, **0 written**; 621.10 ms elapsed |
| KEV records | 1,766 |
| Original disclosure records | 7,838 |
| Rejected disclosures | 4 |
| Pending disclosure queue | 97 |
| Queue breakdown | 96 priority-1 unattempted; 1 priority-2 retrying, maximum 9 attempts |
| Shared NVD records | 201 |
| Shared scan states | 8 ready, 1 scanning |
| KEV and CVE Program source status | Both `ok` in stored status; no stored error flag at observation |

The 97 pending records are the current baseline, not the earlier screenshot count of 2,276. Their reduction is **not attributed to this branch**, which has not been deployed. The retry cause, actual enqueue age of legacy items, sustained processing rate, and end-to-end source completeness were not established by these aggregate queries. A successful source status alone does not establish complete history.

The checked-in artifact retains exact attempt/success/publisher/checkpoint timestamps. Publisher age is not queue age. Daily billing analytics, table/index bytes, peak write contributors and production onboarding/browser p95 remain unavailable. This report does not attribute the prior 100,000-write incident to CVIE without operational evidence.

### 5.2 Equivalent local D1 workloads

These measurements use **Miniflare 4.20260730.0 D1 metadata**, not hand-counted SQL, ordinary SQLite estimates, remote staging metrics, or Cloudflare billing. Twenty equivalent page/identical-save samples were taken per dataset. Data is synthetic and public, with 10% relevant CVEs, 50 synthetic accounts and 5,000 minimal synthetic inventory rows. The latter are not a certification of complete inventory API pagination or package-heavy assets.

The baseline uses the existing legacy reconciliation query and feature-disabled save path; the old KEV refresh implementation is loaded from `3b9dfce`. Helper imports use compatible current modules. These are operation benchmarks, not a byte-for-byte deployment of the entire old Worker. Durations include local Node/Miniflare RPC overhead and exclude browser/network rendering.

| Equivalent workload | Before | After | Assessment |
|---|---:|---:|---|
| 100-result page, 10,000 CVEs: p95 reads | 45,254 | **409** | 99.10% fewer reads; zero writes both paths. |
| Same page: p95 duration | 102.44 ms | 71.42 ms | Local service duration only. |
| 100-result page, 100,000 CVEs: p95 reads | 450,254 | **409** | 99.91% fewer reads; zero writes both paths. |
| Same page: p95 duration | 246.88 ms | 71.71 ms | Fixed page cost remained stable at 10× evidence. |
| Unchanged 1,766-record KEV snapshot: reads | 10,610 | 11 | No repeated catalogue scan in new path. |
| Same snapshot: total writes | 5,300 | **2** | Two source-state writes; **zero KEV content writes**. |
| Cold identity save, 10,000-CVE fixture: reads/writes | 35 / 14 | 37 / 17 | Identity binding adds cost; not a write reduction. |
| Same single cold save: duration | 178.84 ms | 193.27 ms | One sample, not p95. |
| Identical save, 10,000-CVE fixture: p95 reads/writes | 9 / 0 | 11 / 0 | No duplicate subscription or discovery scope. |
| Same identical save: p95 duration | 59.85 ms | 90.20 ms | Local overhead increased; report explicitly. |
| Synthetic 10,000-CVE ingestion: index-inclusive writes | 53,000 | 70,000 | **32.1% increase** for indexing/projection. |
| Synthetic 100,000-CVE ingestion: index-inclusive writes | 530,000 | 700,000 | Same proportional write increase. |

First KEV import also costs more when projected associations exist: 3,534 baseline total writes versus 5,536 in the 10,000-CVE new fixture and 7,068 in the 100,000-CVE new fixture. Membership changes maintain the serving index. Do not extrapolate unchanged-refresh savings to initial imports or changed source batches without measuring their mix.

The production PHP result and synthetic benchmark are different corpora. They must not be combined into a claimed production before/after percentage. No production after-measurement exists.

Artifacts: [10,000-CVE measurements](cvie-evidence/local-d1-10k.json), [100,000-CVE measurements](cvie-evidence/local-d1-100k.json). `evidence_read_target_met_local` refers only to the bounded evidence read/write target, not overall readiness.

### 5.3 Query plans and concurrency

The new query plan seeks `cvie_identity_evidence_page` by identity/date/cursor and then performs primary-key lookups on shared NVD advisories, disclosures, KEV and pending work. The plan's `SCAN p` scans the bounded materialized page, not the complete CVE store. Detailed plans are included in both local artifacts. The old reconciliation path retains family/JSON reconciliation and scales from 45,254 to 450,254 reads in the fixed-page fixtures; it remains available for legacy consumers.

The concurrency fixture first saves one account, then runs 49 new account saves in parallel for the same identity. It ends with **one shared scope**, not 50 scans. Measured service orchestration p95 is **6,678.78 ms** at 10,000 CVEs and **6,707.62 ms** at 100,000 CVEs. Functional tests also exercise 50-account sharing, identical saves and stale lease fencing.

Deduplication passes locally. The ≤1-second server save and ≤2-second user-visible targets do **not** pass this concurrent local harness. It is not a browser test or remote 50-session soak; emulator serialization can contribute, but that is not evidence that production meets the target. Profile statement round trips, batch sizes and contention in isolated staging before rollout. Do not mask this with full reconciliation or additional unapproved infrastructure.

## 6. Tests and acceptance gates

Final local backend result: **351 tests in 34 files, zero failures**; [machine-readable results](cvie-evidence/backend-tests.json). Full Python discovery: **122 tests passed**. Focused public-feed suite: 78 tests passed. Read-only SQL guard test passed.

Browser/JSDOM smoke checks passed for legacy CVIE client behavior, lightweight polling, new fast onboarding, customer security (including upgrade/finding/report isolation and catalogue paths), product monitoring, and workspace. Existing backend suites cover account isolation, inventory, lifecycle, finding/remediation decisions, delivery/digests and notification behavior. These are automated regressions, not remote delivery or live provider certification.

Representative fixtures cover .NET Framework/Runtime/ASP.NET Core/SDK/package separation, WordPress Core versus plugins, PHP, Python, Windows Server, SQL Server, MySQL versus MariaDB, Ubuntu and Debian; typo suggestions, ambiguity, conflicting/missing vendors, missing versions, exact package identifiers and unsupported comparisons. Additional fixtures cover tenant authorization, 100-row pagination, older KEV retention/removal, rejection, unaffected assertions, provider outages, unchanged CNA payloads, dynamic identity hydration, resumable index pages, cache invalidation and stale claim fencing.

| Required target | Result | Evidence or remaining gate |
|---|---|---|
| ≤1,000 D1 reads p95 per 100-result page | **Pass locally** | 409 at both dataset sizes, zero writes; remote staging confirmation missing. |
| Zero KEV content writes for unchanged snapshot | **Pass locally** | 1,766 unchanged entries; two total source-state writes remain. |
| Suggestion/status/evidence GETs cause no D1 writes | **Pass in regression fixtures** | GET repair removed; directory, status and evidence assertions. Whole production request telemetry still needed. |
| Identical saves create no duplicate subscriptions/scans | **Pass locally** | Zero-write repeated saves and one shared scope across accounts. |
| First stored results do not wait for provider/full download | **Pass functionally** | Fast-path smoke test and provider-outage fixtures. End-to-end ≤2-second p95 unmeasured. |
| Save ≤1 second server / ≤2 seconds click-to-saved | **Not met in concurrency harness** | Approximately 6.7-second local p95; remote profiling required. |
| Suggestions ≤300 ms API / ≤500 ms UI | **Unverified latency gate** | Functional and zero-write checks pass; no agreed-network p95. |
| Unresolved products remain visible and not “safe” | **Pass in fixtures** | Identity/package/coverage guidance, no fuzzy auto-bind. |
| ≥99% identity precision; matching precision/recall targets | **Unverified** | Requested examples pass; no independently labeled 500-example held-out corpus. |
| Full configuration/backport/version truth evaluation | **Deferred, explicit unknown** | Raw evidence preserved; Phase 5 semantic engines not implemented. |
| Actual sustained disclosure rate / queue age | **Incomplete baseline** | Current count/status known; legacy age unknown, throughput requires observations. |
| Freshness/backlog/history completion targets | **Unverified / later phase** | Existing scheduler retained; five-record disclosure batch limit remains, not the design's ≥30/minute target. |
| Index write amplification acceptable | **Measured, not approved** | 32.1% fixture increase; source mix/storage headroom need staging measurement. |
| 50 sessions / 5,000 assets | **Not certified** | Local dedupe and synthetic rows only; full staged soak pending. Existing 3,000-row per-account inventory cap remains. |
| Existing decisions/history/email consent preserved | **Pass local regression; remote comparison pending** | Additive schema, stable private IDs, no new sends. |
| Staging migrations and remote rollback | **Blocked** | No staging Worker/D1 target or credentials supplied. |
| Production release | **Blocked** | Do not deploy automatically. |

CI verification before the final report: [CVIE verification](https://github.com/Prat007ai/cveharbor/actions/runs/41515136867), [repository checks](https://github.com/Prat007ai/cveharbor/actions/runs/41515136991), and [product monitoring](https://github.com/Prat007ai/cveharbor/actions/runs/41515136818) passed for implementation commit `070cd63035622ef726c5f6cd442ea1dc2fc8f859`. The latest PR checks must also be green before merging; the local 351-test result includes the subsequent package-identity fixture.

## 7. Migrations, flags and staging runbook

### Additive migrations

1. `account-backend/migrations/0028_cvie_source_efficiency.sql`: source content hashes, disclosure state index and queue observation timestamps/triggers. No deletion or replacement of accepted intelligence.
2. `account-backend/migrations/0029_cvie_identity_registry.sql`: public registry/aliases/identifiers/members/families; private binding snapshots; compact identity evidence; indexed page lookup; source-change projection triggers; bounded backfill checkpoints; per-identity leased hydration jobs and indexes.

Apply in order after existing migrations through `0027`. Neither migration updates customer decisions or automatically sends notifications. Existing stored source rows require a bounded association backfill; creating tables alone is not evidence of complete index coverage.

`backfillEvidenceIndex(env, 'nvd'|'cna', limit)` accepts pages of at most 100 source records and persists checkpoints. Run it only against an explicitly selected staging binding first. It reads existing stored intelligence and does not fetch upstream providers. The helper is not an unauthenticated HTTP route and is never invoked by GETs. The global migration backfill should have one operator; per-identity runtime jobs use a lease token to fence stale commits.

Migration and backfill fixture tests pass, including resumed work and preserved source rows. No remote migration or remote rollback has run.

### Feature flags

| Flag | Purpose and dependency |
|---|---|
| `CVIE_METRICS_ENABLED=true` | Redacted operation metrics; default off. |
| `CVIE_REGISTRY_ENABLED=true` | Registry-first binding and bounded local index work; requires `0028`/`0029`. |
| `CVIE_FAST_EVIDENCE_ENABLED=true` | New immediate evidence serving/client contract; requires registry flag and hydrated associations. |

No `wrangler.toml` or production flag changes are included. Existing Worker/D1 architecture, shared scans, Cron scheduling and source credentials are retained. No new database, Queue, KV namespace or other infrastructure was created. Phase 1 source correctness changes are backend behavior changes, not all guarded by the new serving flags; review them separately in deployment/rollback.

### Required staging sequence before production approval

1. Identify an existing isolated staging Worker and D1, confirm bindings explicitly, and use synthetic/sanitized data. No staging target is currently available. Do not use the production binding as a substitute.
2. Capture schema versions, row counts and hashes of private subscriptions/decisions/preferences before migration. Record actual D1 storage/index bytes and source table sizes.
3. Apply `0028`, then `0029`. Deploy branch code to staging only. Enable telemetry first, then registry, then bounded serving after stored associations are hydrated. Keep external providers stubbed initially.
4. Run bounded stored-data backfill; stop/resume it and compare canonical CVE IDs, provenance, rejection and negative assertions with the legacy path. Classify intentional differences. Do not run a provider historical rescan as an indexing shortcut.
5. Verify exact/ambiguous/unresolved onboarding through catalogue, inventory and lifecycle UI; missing versions remain unknown. Test first page while providers time out and while later pages exist.
6. Replay unchanged/changed KEV and CNA fixtures and inspect actual remote D1 metadata. Include removals, same-date corrections, rejected/reinstated CVEs and independent withdrawn advisories.
7. Run the approved isolated 50-session workload and both 5,000-asset account layouts. Measure p50/p95/p99 latency, failure rate, rows read/written, projection ingestion overhead and source lag. The existing 3,000 per-account cap must be explicitly resolved in its approved later-phase scope before claiming the single-account capacity target.
8. Verify subscription/finding/remediation/report/notification parity from before/after snapshots. Test account isolation, sign-out, frozen report behavior and duplicate-notification prevention without sending real customer emails.
9. Exercise the rollback below, confirm existing records remain readable, and attach remote results. Production rollout requires a separate review and approval after blockers are resolved.

## 8. Rollback and recovery

- Turn off `CVIE_FAST_EVIDENCE_ENABLED` to restore the compatible legacy serving contract. The existing API/storage remains available; legacy query costs return and should be monitored.
- Turn off `CVIE_REGISTRY_ENABLED` to stop registry-first onboarding and new local index job processing. Preserve identity tables, cursors, source evidence and private bindings for investigation. New identities without a legacy mapping must stay visible as unresolved, not disappear.
- Disable metrics independently if their overhead is material. Preserve redaction and captured aggregate evidence.
- Do **not** drop the additive tables/indexes or restore a whole database snapshot over newer customer changes as an ordinary rollback. The source projection triggers remain until a separately reviewed migration changes them; disabling serving flags does not remove their write overhead.
- Do **not** roll back rejection tombstones, authoritative KEV removals or independent withdrawal handling to resurrect invalid records. If a Phase 1 refresh regresses, pause that refresh through an approved operational change and forward-fix it. Blind deployment of old ingestion code can reintroduce full KEV rewrites and is not the recommended rollback.
- Index hydration resumes from durable cursors; runtime stale owners cannot commit after a newer lease token. Existing provider recovery limits are unchanged. No claim is made that all Phase 3 crash/outage recovery cases are solved.

Local feature-disabled compatibility, migration/backfill resume and private-state regression tests pass. Remote staging rollback and restored latency have **not** been validated.

## 9. Remaining limitations and dependencies

**Immediate release blockers:** no remote staging environment; concurrent local save latency above target; no remote index-inclusive cost/storage validation; no held-out identity accuracy corpus; no full account-layout capacity and decision/report parity exercise. These are not waived by green unit tests.

**Phase 3:** full incremental NVD modification synchronization, weighted/fair source scheduling, durable provider gap recovery, disclosure quarantine/backlog throughput and comprehensive failure boundaries remain deferred. NVD historical generations can still rewrite returned records. The new local index job does not replace the existing provider scheduler.

**Phase 4:** full shared canonical serving/materialization, revision-only client refresh, complete legacy report/query conversion and broad cross-product projections remain deferred. This branch implements only the minimal identity page index. Legacy reports and other full reconciliation consumers can still be expensive. The public advisory archive cap is unchanged.

**Phase 5:** configuration truth evaluation, ecosystem-specific version comparators, Debian/Ubuntu vendor backports, Microsoft build exceptions and complete inventory/package pagination remain deferred. Current candidate results preserve uncertainty; they do not certify installed-version vulnerability or safety. The per-account 3,000 inventory cap prevents claiming 5,000 assets in one MSP account.

**Phase 6:** incremental tenant assessments, report snapshots/manifests, complete exports and revision-based notification policy remain deferred. Existing customer decisions remain authoritative. Partial bounded pages do not update complete security scores.

**Phase 7:** remote 50-session/5,000-asset soak, failure recovery matrix, storage growth, migration rollback and approved production observation remain deferred until staging is available and release blockers are resolved.

Queues, archives or separate D1 databases are conditional later proposals requiring separate approval. No such infrastructure was introduced. Daily D1 savings remain workload-dependent; local index-inclusive measurements cannot establish monthly billing or attribute the earlier write-limit incident.

## 10. Exact changed files

The following files comprise this branch relative to integrated main. Paths are repository-relative; generated `public/`, caches and local dependencies are excluded.

- [`.github/workflows/cvie-phase012.yml`](../.github/workflows/cvie-phase012.yml)
- [`account-backend/data/cvie-identities.json`](../account-backend/data/cvie-identities.json)
- [`account-backend/migrations/0028_cvie_source_efficiency.sql`](../account-backend/migrations/0028_cvie_source_efficiency.sql)
- [`account-backend/migrations/0029_cvie_identity_registry.sql`](../account-backend/migrations/0029_cvie_identity_registry.sql)
- [`account-backend/src/cvie-evidence.js`](../account-backend/src/cvie-evidence.js)
- [`account-backend/src/cvie-index-maintenance.js`](../account-backend/src/cvie-index-maintenance.js)
- [`account-backend/src/cvie-metrics.js`](../account-backend/src/cvie-metrics.js)
- [`account-backend/src/cvie-onboarding.js`](../account-backend/src/cvie-onboarding.js)
- [`account-backend/src/cvie-records.js`](../account-backend/src/cvie-records.js)
- [`account-backend/src/cvie.js`](../account-backend/src/cvie.js)
- [`account-backend/src/index.js`](../account-backend/src/index.js)
- [`account-backend/src/monitor-directory.js`](../account-backend/src/monitor-directory.js)
- [`account-backend/src/product-registry.js`](../account-backend/src/product-registry.js)
- [`account-backend/src/public-source-status-cache.js`](../account-backend/src/public-source-status-cache.js)
- [`account-backend/src/shared-scopes.js`](../account-backend/src/shared-scopes.js)
- [`account-backend/tests/cvie-core-phase012.test.mjs`](../account-backend/tests/cvie-core-phase012.test.mjs)
- [`account-backend/tests/cvie-coverage.test.mjs`](../account-backend/tests/cvie-coverage.test.mjs)
- [`account-backend/tests/cvie-dotnet.test.mjs`](../account-backend/tests/cvie-dotnet.test.mjs)
- [`account-backend/tests/cvie-hyperv.test.mjs`](../account-backend/tests/cvie-hyperv.test.mjs)
- [`app.js`](../app.js)
- [`customer-security.js`](../customer-security.js)
- [`cvie.css`](../cvie.css)
- [`cvie.js`](../cvie.js)
- [`docs/cvie-core-phase012.md`](../docs/cvie-core-phase012.md)
- [`docs/cvie-evidence/backend-tests.json`](../docs/cvie-evidence/backend-tests.json)
- [`docs/cvie-evidence/local-d1-100k.json`](../docs/cvie-evidence/local-d1-100k.json)
- [`docs/cvie-evidence/local-d1-10k.json`](../docs/cvie-evidence/local-d1-10k.json)
- [`docs/cvie-evidence/production-baseline.json`](../docs/cvie-evidence/production-baseline.json)
- [`scripts/cvie-local-benchmark.mjs`](../scripts/cvie-local-benchmark.mjs)
- [`scripts/cvie-readonly-baseline.mjs`](../scripts/cvie-readonly-baseline.mjs)
- [`scripts/cvie_fast_onboarding_smoke.mjs`](../scripts/cvie_fast_onboarding_smoke.mjs)
- [`scripts/cvie_readonly_sql.mjs`](../scripts/cvie_readonly_sql.mjs)
- [`scripts/cvie_readonly_sql.test.mjs`](../scripts/cvie_readonly_sql.test.mjs)
- [`scripts/update.py`](../scripts/update.py)
- [`tests/test_update.py`](../tests/test_update.py)
