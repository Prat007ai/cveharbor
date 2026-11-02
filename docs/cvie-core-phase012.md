# Task 2B: CVIE Core Improvements — Implementation and Readiness Follow-up

Updated 2 November 2026 (America/Toronto). **Local optimization and regression validation completed; ready for isolated staging review, not approved for production.**

- Existing draft PR: [#243](https://github.com/Prat007ai/cveharbor/pull/243).
- Existing branch: `codex/cvie-core-phase012`. No merge into main or production deployment.
- Follow-up comparison baseline: `a2e4597`, the previously reviewed Task 2B implementation.
- Main integrated through `b080025`, including the subsequent remediation UI work. No overlapping CVIE backend changes were found. Integration occurred into this development branch only.
- Original main baseline: `3b9dfce`; assessment baseline: `4004859b66a37942fa606b7d8fbaeddd4c674c8f`.
- Reference: [full approved Task 2 design](https://chatgpt.com/space/page_0a2d074c11588191a26655dd7767980b). This is the complete updated Task 2B report, not a Task 1 document or link-only placeholder.

## 1. Current readiness decision

The follow-up addresses the measured local bottlenecks without starting Task 3 or implementing the broader Phases 3–7 architecture.

**Measured local results:** the authenticated Worker save-to-first-evidence API sequence has p95 latency of **25 ms, 148 ms and 263 ms** at 1, 10 and 50 concurrent customers. The 100-result evidence lookup still reads **409 D1 rows and writes zero** at both 10,000 and 100,000 synthetic CVEs. An unchanged 1,766-entry KEV snapshot still writes **zero KEV records** and two source-state rows.

The original 10%-mapped ingestion fixture now writes **58,000 rows instead of 70,000**, versus 53,000 in the legacy schema. Thus its additional write overhead falls from **32.1% to 9.4%**. This is workload-dependent: a separate all-mapped fixture still has 62.5% more writes than legacy storage because every CVE needs maintained serving associations. Those costs and the feature-off behavior are explicit below.

The earlier 6.7-second result was a Node-to-Miniflare per-statement orchestration measurement, not a deployed Worker request. The same host harness still takes approximately 5.3 seconds after optimization; changing the measurement environment alone must not be represented as a code speedup. The new comparison runs both reviewed and optimized application code inside the same local Worker runtime.

**Remote readiness remains unverified.** No isolated staging Worker/D1, staging credentials or approved frontend/API origin routing were available. Local Worker tests exclude real client-network latency and browser rendering, so they do not certify the production click-to-render target. No production deployment, migration, rescan, load test, resource creation or Cloudflare configuration change was performed. Current tests use synthetic identities and records; the earlier read-only production baseline remains historical evidence only.

## 2. Follow-up changes and profiling findings

| Finding | Implemented improvement | Integrity safeguard |
|---|---|---|
| Three sequential reads of a customer's product/subscription state | One D1 read batch and consistent snapshot | Account/origin predicates retained; the separate mutation batch remains atomic. |
| Every new subscription downloads the entire KEV catalogue from D1 | Public-only, 30-second per-binding cache with concurrent miss coalescing | No private matches, aliases, versions or account data cached; failures evict; accepted KEV refresh invalidates; other isolates expire within 30 seconds. |
| A verified KEV match invalidated source status even when queue insertion changed nothing | Invalidate status only when the queue actually changes | Relevant missing work is still queued; existing verified records do not trigger redundant status aggregation. |
| Every save reprocessed valid private registry bindings | Select only missing/stale bindings using input snapshots and registry revision | Changed name/vendor/CPE invalidates the old binding; unresolved records remain visible. |
| Shared-scope lease cleanup scanned the complete private product table | Restrict cleanup to changed products, donor products and newly promoted indexed scope memberships | Existing leases for unrelated accounts are untouched; donor/scope commit checks remain. |
| State index covered every disclosure although the global lookup only needs rejected records | Partial `cvie_disclosure_state` index for `state='REJECTED'` | Rejection query plan still uses the index; primary-key CVE joins and page indexes remain. |
| New evidence associations were inserted and immediately updated to set their page key | Calculate the initial key in the source insert; skip irrelevant CNA trigger work and unchanged state/date updates | Rejection, unaffected assertions, KEV add/remove and publication-date correction tests remain green. |
| A previously selected hydration job could be claimed after another worker advanced its cursor | Compare cursor, due time and completion state during lease acquisition | Existing lease-token fencing remains; stale claims cannot rewind checkpoints. |

The warm benchmark performs authentication, catalogue validation/revision handling, durable product registration, shared-scope reconciliation, progress/source reads, and the first stored evidence page through the actual Worker handlers. It reports D1 engine time, binding calls/batches and route-stage elapsed time separately. Warm cases do not run index hydration or call providers. Separate cold-scope and long-tail hydration measurements cover those operations.

No new database, Queue, KV namespace or other infrastructure was introduced. No existing customer decision or notification policy was changed.

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

## 5. Updated measurements

### 5.1 Method and the original latency discrepancy

All follow-up performance values are **local measurements using Miniflare 4.20260730.0 and real emulator D1 metadata**, not remote D1 billing or production measurements. The Worker harness is bundled with esbuild 0.25.12. Its supported compatibility date is `2026-08-06`; production's configured date is `2026-10-28`, another reason to validate remotely before release.

`scripts/cvie-followup-profile.mjs` invokes the actual authenticated catalogue PUT, bounded progress GET and evidence GET in sequence within a local Worker benchmark request. It seeds valid synthetic sessions rather than bypassing the application's ownership checks. There are 20 single-customer samples, five waves of 10 customers and three waves of 50 customers. The fixture has 10,000 CVEs, 1,000 related records and 1,766 KEV entries, including ten related already-verified KEVs. Source scopes are fresh and indexed.

The benchmark omits the browser, three real browser-to-server network trips and login/email enrollment. It includes source-status reads and any background service work started by the route. Providers are intercepted locally, and the warm benchmark asserts **zero external requests**. Account fixture creation and initial fixture seeding are excluded from onboarding timing.

The old harness executes application code in Node and bridges each statement into Miniflare, accumulating serialization/RPC overhead under concurrency. Its original 50-account p95 was 6,678.78 ms; the follow-up equivalent is 5,273.56 ms at 10,000 CVEs and 4,774.38 ms at 100,000. These are useful harness measurements, but cannot be treated as server or browser latency. The new Worker-based comparison is the relevant local server-path evidence.

### 5.2 Authenticated save to first stored page

| Concurrent customers | Samples | Reviewed p50 / p95 | Optimized p50 / p95 | Reviewed / optimized p95 D1 reads for the complete sequence |
|---|---:|---:|---:|---:|
| 1 | 20 | 30 / 38 ms | **21 / 25 ms** | 2,404 / **616** |
| 10 | 50 | 169 / 215 ms | **132 / 148 ms** | 2,447 / **616** |
| 50 | 150 | 702 / 984 ms | **232 / 263 ms** | 2,595 / **616** |

Every new-account sequence writes 14 D1 rows in this fixture both before and after; optimization does not eliminate necessary private account/subscription records. A cold public cache miss costs more: the maximum optimized sequence reads 2,387 rows because it loads the 1,766-row KEV catalogue once. The 616-read figure is therefore not a universal cold-isolate guarantee. Concurrent requests share the cache load in one isolate; separate isolates may each load it.

At 50 customers, optimized p95 route times are 125 ms for catalogue save, 78 ms for progress/source status, and 110 ms for evidence. Quantiles are not additive. The p95 sum of D1-reported statement execution time is only 4 ms, while the complete sequence is 263 ms; the remaining time includes binding transport, runtime scheduling, JavaScript and contention. It is not valid to attribute that difference entirely to D1 query execution.

The complete sequence drops from up to 33 binding calls/batches to 27 at p95. Batching reduces round trips, not the number of SQL statements or required transactional writes. The full profile artifacts include per-stage and grouped query counts, read/write totals and elapsed time:

- [Reviewed Worker profile](cvie-evidence/followup-worker-before.json)
- [Optimized Worker profile](cvie-evidence/followup-worker-after.json)

### 5.3 Evidence retrieval, repeated saves and KEV refresh

| Equivalent local workload | Legacy / previously reviewed | Optimized follow-up |
|---|---:|---:|
| 100-result page at 10,000 CVEs: p95 reads | Legacy 45,254; reviewed 409 | **409**, zero writes |
| 100-result page at 100,000 CVEs: p95 reads | Legacy 450,254; reviewed 409 | **409**, zero writes |
| Unchanged 1,766-entry KEV snapshot: reads | Legacy 10,610; reviewed 11 | **11** |
| Same snapshot: total writes | Legacy 5,300; reviewed 2 | **2**, zero KEV content writes |
| Repeated identical product save | Previously zero writes | Still **zero writes**, no additional subscription/scope |

The page index and primary-key source joins were retained. New plans continue to seek `cvie_identity_evidence_page` and join bounded source rows, without a complete CVE table scan or JSON-family reconciliation per page. `SCAN p` in the plan scans only the materialized bounded page.

Artifacts: [10,000-CVE follow-up](cvie-evidence/followup-d1-10k.json), [100,000-CVE follow-up](cvie-evidence/followup-d1-100k.json). Their page timings use the host harness and should not be substituted for the Worker latency table.

### 5.4 Exact ingestion write attribution

For 10,000 incoming disclosures, 10,000 affected-family rows, and 1,000 mapped/shared NVD rows:

| Source operation, including triggered/index writes | Legacy | Reviewed Task 2B | Optimized |
|---|---:|---:|---:|
| Insert disclosure rows | 20,000 | 30,000 | **20,000** |
| Insert affected relationships and derived serving links | 30,000 | 36,000 | **34,000** |
| Insert shared NVD rows/update source pointers | 3,000 | 4,000 | **4,000** |
| **Total** | **53,000** | **70,000** | **58,000** |

Of the original 17,000 additional writes, 10,000 came from indexing all disclosure states; 2,000 were avoidable follow-up sort-key updates. The remaining 5,000 maintain 1,000 serving associations and their source pointers. Essential primary, reverse-CVE and ordered-page indexes remain.

At 100,000 disclosures with the same 10% mapping density, the corresponding totals are **530,000 → 700,000 → 580,000**. The optimized ingestion path is 17.1% cheaper in writes than the reviewed implementation, with 9.4% overhead versus legacy storage in this fixture. In the main profile, ingestion reads also fall from **69,090 to 64,090**.

Other schema costs are separate: `cvie_scope_cpe` adds index maintenance when creating/changing shared scopes; registry reverse indexes apply when identities/aliases/families change; private binding rows are maintained only for changed bindings. Queue observation rows add enqueue/first-attempt/deletion accounting for actual queue work. Hydration jobs have their own unique/due indexes and lease/checkpoint writes. Logging itself adds no D1 writes.

### 5.5 Density, total consumption and flags disabled

An additional schema experiment varies the percentage of incoming CVEs that map to the registry. Each case has 10,000 disclosures and 10,000 affected relationships; corresponding NVD rows are inserted for the mapped subset. It verifies all 30,000 disclosure/relationship rows across the three cases are retained in each database.

| Mapped CVEs | Legacy reads / writes | Reviewed reads / writes | Optimized reads / writes | Optimized write overhead vs legacy |
|---|---:|---:|---:|---:|
| 0% | 20,002 / 50,000 | 40,003 / 60,000 | **30,003 / 50,000** | 0% |
| 10% | 21,002 / 53,000 | 60,002 / 70,000 | **55,002 / 58,000** | 9.4% |
| 100% | 30,001 / 80,000 | 240,001 / 160,000 | **280,001 / 130,000** | 62.5% |

The dense case exposes a real tradeoff: computing correct initial page keys reduces writes but increases ingestion reads versus the reviewed implementation when all CVEs map. The optimized dense case reads 16.7% more than the reviewed case, while writing 18.75% less. Lookup-heavy workloads benefit, but this is not a claim that every ingestion workload becomes cheaper in every dimension. Multiple identities per CVE can add more associations. Actual staging density and ingestion-to-lookup ratio must be measured before billing conclusions.

For the **measured combined profile subset**—10,000-record ingestion plus 220 authenticated new-account save/first-page sequences—the reviewed implementation totals **617,869 reads / 73,080 writes**, versus **201,351 reads / 61,080 writes** optimized. This excludes account/session fixture setup, initial KEV fixture import, additional exports and unrelated application activity. It is an observed defined workload, not a monthly cost projection.

**Flags disabled:** SQL indexes and triggers cannot read Worker environment flags. The optimized schema experiment produces exactly the same ingestion read/write totals with serving conceptually disabled, and the runtime rollback regression confirms source inserts still maintain the projection while both serving flags are false. Disabling flags stops new serving/registry job behavior; it does not remove database index or trigger overhead. Initial backfill and source changes continue to have real costs.

Artifact and reproducible experiment: [density/flag behavior](cvie-evidence/followup-ingestion-density.json), `scripts/cvie-ingestion-cost.mjs`. No essential retrieval index was removed to obtain these results.

### 5.6 Cold shared scope and dynamic identity hydration

A separate local Worker service test creates the first shared scope from 50 simultaneous customer subscriptions. Both implementations produce **one scope**, with 605 total writes. Reviewed reads are 3,396 versus **1,770** optimized; statement counts are 739 versus 654. This single-wave p95 is 90 ms reviewed and 248 ms optimized: it remains under target but is **not** evidence of a latency improvement for that particular cold sample. Scheduling variation and the read-batch transaction warrant remote confirmation.

For a newly verified long-tail CPE with 105 stored original disclosures, the 1-, 10- and 50-request hydration cases each create **one public job**, index the first **100 records**, preserve the cursor for the remaining records and make **zero provider calls**. Optimized p95 service times are 9, 7 and 7 ms; each cohort writes 620 rows in total, not 620 per customer. Initial bounded hydration still uses the fallback sort-key trigger and has greater per-association cost than steady-state source inserts. It is one shared resumable operation, not a full rescan or per-customer history copy.

Artifacts: [reviewed cold operations](cvie-evidence/followup-hydration-before.json), [optimized cold operations](cvie-evidence/followup-hydration-after.json). These are single-cohort service samples, not authentication/browser latency distributions. The concurrency regression additionally verifies stale claims cannot rewind completed or advanced hydration checkpoints.

### 5.7 Earlier production baseline remains historical

The original read-only diagnostic at **3:00:19 p.m. Toronto time on 2 November 2026** measured 336,509 rows read and zero written for five PHP CVEs through the existing reconciliation path. It observed 1,766 KEVs, 7,838 disclosures, four rejected records, 97 queued disclosures (96 unattempted and one retrying with nine attempts), eight ready shared scopes and one scanning scope.

This is the [earlier baseline artifact](cvie-evidence/production-baseline.json), not an after-deployment result. No backlog reduction is attributed to this undeployed branch. Actual historical queue ages, sustained processing rate, daily billing/write contributors and production browser latency were not established. Existing PR checks may repeat their fixed read-only diagnostic; they do not apply migrations or run scans. No new production benchmark was initiated for this follow-up.

## 6. Coverage, correctness and regression results

**361 backend tests across 35 files passed locally.** Full Python discovery passed **122 tests**. Twelve targeted JS/DOM/release checks passed, covering CVIE client/polling/fast onboarding, catalogue scope, customer security, security scores, finding details, software upgrades, product monitoring, workspace, Worker release behavior and the read-only SQL guard. The public site build and general interaction smoke check were also repeated after the final cache refinement.

The backend suite retains inventory, tenant isolation, finding status, remediation workflow/history, assignment, lifecycle, digest and email regression coverage. New follow-up tests verify:

- Fifty callers share one public KEV cache read; expiration, separate DB bindings, refresh invalidation and failure recovery work.
- A queue check that changes nothing does not invalidate public source status.
- Product/subscription mutation batches roll back together if a later statement fails.
- Valid private identity bindings are reused; unrelated account leases are preserved.
- An initial projected association has its correct sort key without an extra update.
- Rejection and reinstatement still change visibility correctly through the selective index.
- Serving-flag rollback retains private subscriptions, catalogue state and source checkpoints; subsequent source updates maintain the index; rejected CVEs stay excluded after re-enabling.
- Actual authenticated save and evidence handlers return stored CVEs while an external discovery promise is still unresolved.
- Vendor-conflicting, ambiguous, misspelled and private unknown names create no speculative shared history scope.
- A stale hydration selection cannot reclaim an advanced/completed checkpoint.

The existing representative-product tests cover .NET Framework, Runtime, ASP.NET Core, SDK/package separation, WordPress Core versus plugins, PHP, Python, Windows Server, SQL Server, MySQL, MariaDB, Ubuntu and Debian. Suggestions require confirmation. Missing vendors/components can remain unresolved; missing versions do not prevent candidate evidence but do prevent a confirmed installed-version verdict. All fast candidates retain `requires_version_review` and `indexed_partial`; lack of evidence never becomes a safe status.

No customer finding is automatically reopened or closed; no remediation owner, note, decision or notification preference is rewritten. Dedicated reports retain their existing compatible path. Partial pages still cannot overwrite a complete customer security score. These assertions have local regression evidence; live remote account/report/email delivery behavior has not been certified.

Artifacts: [backend results](cvie-evidence/followup-backend-tests.json), [targeted frontend/release checks](cvie-evidence/followup-smoke-tests.json). The current PR checks must also pass before any merge consideration.

## 7. Migration review and exact staging requirements

### 7.1 Migration status and impact

`0028_cvie_source_efficiency.sql` and `0029_cvie_identity_registry.sql` are **unreleased migrations in this draft PR**. No remote application of either was performed in this work. Their definitions were refined in place: the state index is selective, and the source projection triggers avoid redundant initial updates. Existing table/customer layouts are not replaced.

If an operator has already applied the earlier versions in another environment, **do not rerun or mark these edited files as newly applied**. Compare `sqlite_schema` and the migration ledger first; that environment needs a reviewed forward schema patch for the changed index/triggers. No such remote patch was executed. A fresh isolated staging database or pre-0028 sanitized staging schema is the intended validation starting point.

| Schema object | Purpose | Active when serving flags are off? |
|---|---|---|
| `cvie_source_snapshots` | Accepted source content hashes | Yes, source ingestion uses it. |
| Partial `cvie_disclosure_state` | Indexed global rejection listing | Yes; only rejected entries are indexed. Building it still reads existing disclosures once. |
| `cvie_queue_observations` and insert/attempt triggers | New queue enqueue/first-attempt timestamps | Yes, when queue work changes. Legacy ages remain unknown. |
| Registry/alias/identifier/member/family tables and reverse indexes | Shared public identities | Stored data/indexes remain; ordinary source ingestion does not continually rewrite registry rows. |
| `cvie_product_identities` | Private snapshot binding | New binding work is gated; existing rows remain. |
| Evidence primary, page and reverse-CVE indexes | Bounded lookup and correction routing | Yes, source changes maintain them. |
| `cvie_fast_nvd_*`, `cvie_fast_cna_*`, `cvie_fast_sort_*` triggers | Atomic source/association/page-key consistency | **Yes.** Flags do not disable SQL triggers. |
| `cvie_index_state` | Explicit bounded migration backfill checkpoints | Retained; helper is never a GET side effect. |
| `cvie_identity_index_jobs` and due index | Shared bounded identity hydration | New processing is registry-gated; jobs/checkpoints remain. |
| `cvie_scope_cpe` | Indexed scope lookup for hydration | Yes, shared-scope writes maintain the index. |

Trigger changes remain within the source transaction; they cannot commit partial evidence separately from the source row. The existing batch rollback tests and new failed-subscription-batch test pass. Existing private IDs and accepted source checkpoints are retained.

### 7.2 What the repository can reuse

The repository has **one account Worker production configuration** in `account-backend/wrangler.toml`, with the `DB` binding pointing to `cveharbor-accounts`. There is no `[env.staging]` section, isolated staging D1 binding, staging account deployment workflow or supplied staging secret set. `site-gate/wrangler.json` belongs to another purpose and is not an account/CVIE staging substitute.

Reusable pieces are the Worker entrypoint, existing schema SQL and migration chain, backend/DOM tests, local Miniflare profiling scripts, fixture builders and release checks. Existing deploy/read-only verification workflows target production; do not repurpose or dispatch them as staging deployments. In particular, merging backend code into main can trigger the production deployment workflow, so this PR remains a draft.

The current managed environment has no Cloudflare runtime credentials or outbound identity configured, and its network policy does not currently permit the Cloudflare API/staging endpoints. Existing production CI secrets are not a staging credential set and must not be used to select the production DB as a substitute.

### 7.3 Information and approval needed from the owner

| Requirement | Exact information/setup needed |
|---|---|
| Isolated Worker | Approved staging Worker name, account, HTTPS URL and intended runtime compatibility date. It must be a different deployment from the production account Worker. |
| Isolated D1 | Approved staging database name and ID, bound as `DB`, with no production/customer data. Creating it requires separate approval; none was created here. |
| Staging configuration | An explicitly reviewed separate Wrangler configuration or environment block with those exact bindings. Never rely on the repository's default production binding. No configuration file/settings were changed for this follow-up. |
| Deployment credentials | Staging-scoped CI/environment credentials capable of Worker deployment and D1 migration/fixture writes, with secret storage and protected approvals. Confirm available scope limitations in Cloudflare; do not assume tokens are database-granular. No secret values should be put in this report or source control. |
| Network access | Approved access to `api.cloudflare.com` and the specific staging HTTPS endpoint. Provider endpoints are needed only for the separately controlled live-source portion; fixture tests need no live provider scans. |
| Schema and fixtures | Base schema and existing auxiliary schemas/migrations through `0027`, then the revised `0028` and `0029`. Use synthetic accounts, sessions, assets, CVEs, findings, decisions and preferences. Existing schema files include inventory, TOTP, finding status/tickets, remediation, lifecycle and alert schemas; this is more than the minimal performance harness schema. |
| Auth isolation | Independent staging MFA encryption secret if real enrollment is exercised, or valid synthetic staging sessions for API tests. Never copy production sessions, credentials or MFA secrets. |
| Email/cron isolation | Explicitly disable all alert, lifecycle, product-monitoring and assignment delivery paths; omit production mail credentials. Begin with no automatic Cron Triggers. Approved fixture-driven invocation comes first. Retain remediation audit-compatible code/flags required by migration `0026`. |
| Browser routing | Approve staging frontend and API origins. `accounts.js`, `cvie.js`, `inventory.js` and `customer-security.js` contain production API URLs; `account-backend/src/index.js` and the CVIE serializer allow the production frontend origin. A real browser staging run needs reviewed endpoint/CORS/cookie routing for both sides. No origin wiring was changed without approval. A copied production frontend must not accidentally send staging tests to production. |
| Acceptance environment | Agreed region/client network, fixture sizes/mapping density, provider failure simulations, and a measurement window for p50/p95/p99. No production load test is needed or authorized. |

An owner can supply an existing isolated environment or approve creating these resources/configuration separately. Until then, remote staging results must remain **not run**.

### 7.4 Staging validation sequence after the environment is approved

1. Independently verify the selected Worker, D1 ID/name, migration ledger and API origin are staging. Fail closed if a target matches production or is ambiguous. Inspect binding names without logging secrets.
2. Load the complete synthetic schema through `0027`; record private-table counts/checksums, source checkpoints and migration state. Keep a staging-only export for recovery. Do not copy production customer data.
3. Apply revised `0028` then `0029` only if not previously applied. Capture remote D1 metadata for index creation and seed writes. Deploy the compatible branch code to staging, with all delivery and automatic Cron paths disabled.
4. Enable CVIE telemetry, then registry, then bounded serving. Hydrate existing stored intelligence using `backfillEvidenceIndex` in pages of at most 100, testing interruption/resumption. Do not use an external historical rescan as a backfill shortcut.
5. Repeat the 1/10/50 authenticated save-to-render scenarios with known indexed products, cold public caches, cold shared scopes and dynamic stored-data hydration. Exercise expired sessions and cross-account requests. Include real browser timing; the local 263 ms value is not the browser gate.
6. Measure remote rows read/written and latency at 10,000 and 100,000 CVEs with representative mapping density. Include unchanged/changed KEV, corrections/removals, rejected/reinstated disclosures, duplicate saves and source outages. Compare total ingestion-plus-serving consumption, not only one query.
7. Compare inventory, subscription, finding-status, remediation/history, catalogue, lifecycle and notification-preference snapshots before/after. Verify report compatibility and zero real email sends.
8. Execute the rollback procedure below, then re-enable and verify retained checkpoints and source corrections. Attach remote results to this report before requesting production approval.

## 8. Tested local rollback and staging procedure

The executable local rollback regression is `feature rollback preserves private data/checkpoints, maintains projection on new source data and never revives rejected CVEs` in `account-backend/tests/cvie-followup.test.mjs`. It snapshots private CVIE products/subscriptions/scope bindings, catalogue state and source checkpoints; disables both serving flags; inserts new valid and rejected source records; exercises the legacy read route; confirms the snapshots are unchanged; and re-enables fast evidence, which returns valid evidence while excluding the rejected CVE. It passes. Existing wider regression suites cover finding/remediation/history behavior independently.

**This is a locally tested procedure prepared for staging, not a claim of remote staging rollback.** Once isolated staging is available:

1. Stop staged test admission and record aggregate operation metrics, private-data checksums, pending job cursors/leases, source checkpoints and migration versions. Wait for bounded in-flight requests to finish rather than deleting their state.
2. Disable `CVIE_FAST_EVIDENCE_ENABLED`; use the compatible legacy API/read path. Expect legacy reconciliation costs to return. This does not pause accepted source corrections.
3. Disable `CVIE_REGISTRY_ENABLED` to stop registry-first onboarding and new local hydration job execution. Retain public identities, private bindings, source records and hydration/backfill cursors. New identities lacking a legacy mapping remain unresolved, never silently safe.
4. Disable `CVIE_METRICS_ENABLED` independently only if needed for overhead investigation. No schema change is required for these flags.
5. Verify private subscriptions, findings/decisions, remediation history, report behavior and notification preferences against the staging snapshots. Verify rejection tombstones and authoritative KEV removals remain effective.
6. Insert controlled staging source corrections while flags are off and confirm projection triggers still maintain correct sort/membership. This overhead remains and is intentional for consistency on re-enable.
7. Re-enable compatible registry/serving flags, resume bounded existing cursors, and confirm no duplicate work, missing corrections, changed private decisions or notification sends.

Do not drop tables, delete checkpoints, reset source watermarks to now, or restore a whole database snapshot over newer customer activity. Do not roll back to an ingestion writer that resurrects rejected CVEs or restores complete KEV replacement. A serving-flag rollback does not require an old binary. If source ingestion itself regresses, use a reviewed pause/forward fix while preserving accepted evidence.

**Overhead flags cannot disable:** maintained SQL indexes, source projection triggers, queue observation triggers and source content-hash state. Stopping those requires an explicitly reviewed schema/ingestion change with a catch-up plan before re-enabling serving; no such destructive or remote rollback was performed. An old writer that deletes/rebuilds affected relationships can also reintroduce additional projection churn and is not the recommended rollback target.

## 9. Acceptance status and scope limits

| Gate | Current conclusion |
|---|---|
| Resolved product save + first stored evidence under two seconds | **Pass for the measured local Worker API sequence** at 1/10/50 customers. Real browser/network and remote D1 gate still unverified. |
| ≤1,000 reads p95 per 100-result evidence page | **Pass locally: 409** at both 10,000 and 100,000 CVEs. Remote confirmation required. |
| No unnecessary KEV rewrites | **Pass locally:** zero catalogue writes for unchanged content; two source-state writes remain. |
| Lower total D1 consumption | **Pass in the defined mixed fixture**, with density-dependent ingestion tradeoffs disclosed. No production billing claim. |
| Shared discovery/index work | **Pass locally:** one cold shared scope and one hydration job per identity; stale claim fencing tested. |
| Exact/ambiguous/unresolved identity and coverage guidance | **Pass representative fixtures.** No fuzzy auto-bind or missing-data “safe” outcome. |
| Product relevance versus installed applicability | **Preserved:** candidate evidence stays `requires_version_review`; full semantic engines remain outside this follow-up. |
| Data, decisions, reports and remediation compatibility | **Local regressions pass.** Remote synthetic account parity/rollback still required. |
| Staging resources, origin routing, migrations and rollback | **Not run remotely; requirements documented.** No resources/configuration created. |
| Production rollout | **Blocked pending staging validation and separate approval.** PR remains draft. |

No Task 3 work was started. Full incremental NVD ingestion/backlog recovery (Phase 3), comprehensive shared serving/report materialization (Phase 4), ecosystem/version/backport evaluation and full inventory pagination (Phase 5), incremental tenant assessments/report snapshots (Phase 6), and broader scale/production observation (Phase 7) remain deferred. The public archive cap, legacy report query costs and existing 3,000-row per-account inventory limit remain. The local minimal 5,000-row fixture does not certify a complete 5,000-asset MSP account.

The independent 500-example identity corpus, broad precision/recall targets, sustained provider throughput/freshness and long outage recovery remain unverified; this focused follow-up does not claim them. No Queues or additional databases were introduced to hide a local performance issue.

## 10. Reproduction and exact changed files

The local profiling scripts read no Cloudflare credentials and never call the Cloudflare management API. They instantiate disposable Miniflare databases; outbound provider calls are intercepted. Install pinned test tools outside the repository, then provide `CVIE_MINIFLARE_MODULE` and `CVIE_ESBUILD_MODULE` paths. No runtime dependency was added to the application.

- `scripts/cvie-followup-profile.mjs`: complete local authenticated API sequence at 1/10/50 customers. Set `CVIE_PROFILE_ROOT` to an archived `a2e4597` tree for the reviewed comparison, or the current worktree for optimized behavior.
- `scripts/cvie-hydration-profile.mjs`: cold 50-customer scope creation and 1/10/50 public identity hydration.
- `scripts/cvie-ingestion-cost.mjs`: legacy/reviewed/optimized schema comparison at 0/10/100% mapped density. Retains the pinned reviewed migration definitions via `git show a2e4597`.
- `scripts/cvie-local-benchmark.mjs`: legacy versus indexed page/KEV tests at 10,000 CVEs; set `CVIE_BENCHMARK_CVES=100000` for the larger fixture.
- `npm test --prefix account-backend`, `python -m unittest discover -s tests`, and the checked-in smoke scripts cover regression behavior. No remote load command is supplied or run implicitly.

The following paths comprise the PR relative to integrated main `b080025`. Generated public build output, local dependencies and caches are excluded.

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
- [`account-backend/tests/cvie-followup.test.mjs`](../account-backend/tests/cvie-followup.test.mjs)
- [`account-backend/tests/cvie-hyperv.test.mjs`](../account-backend/tests/cvie-hyperv.test.mjs)
- [`account-backend/tests/helpers/d1.mjs`](../account-backend/tests/helpers/d1.mjs)
- [`app.js`](../app.js)
- [`customer-security.js`](../customer-security.js)
- [`cvie.css`](../cvie.css)
- [`cvie.js`](../cvie.js)
- [`docs/cvie-core-phase012.md`](../docs/cvie-core-phase012.md)
- [`docs/cvie-evidence/backend-tests.json`](../docs/cvie-evidence/backend-tests.json)
- [`docs/cvie-evidence/followup-backend-tests.json`](../docs/cvie-evidence/followup-backend-tests.json)
- [`docs/cvie-evidence/followup-d1-100k.json`](../docs/cvie-evidence/followup-d1-100k.json)
- [`docs/cvie-evidence/followup-d1-10k.json`](../docs/cvie-evidence/followup-d1-10k.json)
- [`docs/cvie-evidence/followup-hydration-after.json`](../docs/cvie-evidence/followup-hydration-after.json)
- [`docs/cvie-evidence/followup-hydration-before.json`](../docs/cvie-evidence/followup-hydration-before.json)
- [`docs/cvie-evidence/followup-ingestion-density.json`](../docs/cvie-evidence/followup-ingestion-density.json)
- [`docs/cvie-evidence/followup-smoke-tests.json`](../docs/cvie-evidence/followup-smoke-tests.json)
- [`docs/cvie-evidence/followup-validation.json`](../docs/cvie-evidence/followup-validation.json)
- [`docs/cvie-evidence/followup-worker-after.json`](../docs/cvie-evidence/followup-worker-after.json)
- [`docs/cvie-evidence/followup-worker-before.json`](../docs/cvie-evidence/followup-worker-before.json)
- [`docs/cvie-evidence/local-d1-100k.json`](../docs/cvie-evidence/local-d1-100k.json)
- [`docs/cvie-evidence/local-d1-10k.json`](../docs/cvie-evidence/local-d1-10k.json)
- [`docs/cvie-evidence/production-baseline.json`](../docs/cvie-evidence/production-baseline.json)
- [`scripts/cvie-followup-profile.mjs`](../scripts/cvie-followup-profile.mjs)
- [`scripts/cvie-hydration-profile.mjs`](../scripts/cvie-hydration-profile.mjs)
- [`scripts/cvie-ingestion-cost.mjs`](../scripts/cvie-ingestion-cost.mjs)
- [`scripts/cvie-local-benchmark.mjs`](../scripts/cvie-local-benchmark.mjs)
- [`scripts/cvie-readonly-baseline.mjs`](../scripts/cvie-readonly-baseline.mjs)
- [`scripts/cvie_fast_onboarding_smoke.mjs`](../scripts/cvie_fast_onboarding_smoke.mjs)
- [`scripts/cvie_readonly_sql.mjs`](../scripts/cvie_readonly_sql.mjs)
- [`scripts/cvie_readonly_sql.test.mjs`](../scripts/cvie_readonly_sql.test.mjs)
- [`scripts/update.py`](../scripts/update.py)
- [`tests/test_update.py`](../tests/test_update.py)
