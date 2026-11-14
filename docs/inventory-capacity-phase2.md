# Inventory capacity phase 2 — work in progress

The production baseline is PR361, main `3ce02f24cbcdfd33cd776c6fdd3e4e7a245ed97a`. The serving backend identity is `0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34`. This change is not yet a deployed or remotely certified capacity increase.

## Implemented candidate

- Private inventory pages contain at most 250 rows, use stable keyset cursors, and recheck ownership and organization visibility on every page. Explicit completion metadata prevents partial exports. Cursor scope includes account, actor, organization, customer, environment and resource.
- Transactional revision reads detect inventory and companion mutations between pages. The client discards partial results and retries at most twice; persistent churn produces an error rather than a mixed report.
- Assets, customers, environments, saved statuses, append-only tickets, plugin source/install/check/release results, package inventory and network inventory have paged reads. Personal, team and Workspace clients use the shared reader. Reports fetch only the selected customer's assets and companion records; metadata retains the customer chooser.
- An additive schema introduces paging indexes, per-account revision/count tracking and an atomic 50,000-software-entry ceiling. The old 3,000-entry ceiling remains until this migration is activated. Legacy clients receive a refresh-required error instead of silent inventory truncation above 3,000 entries. A host with five components consumes five entries.
- Existing recovery guards are preserved and new tables are guarded. AI activation, allowances, credentials, permissions, notifications and real customer records are unchanged.

## Validation completed locally

- Full backend regression: 567 tests passed after the indexed-query and authentication checks; the additional parallel-partition mutation test also passes. The focused capacity tests cover 10,000 unique rows, account and cursor isolation, mutation invalidation, revocation, 12,000 tickets, 4,000 plugin mappings, atomic maximum enforcement, cascaded counts and repeatable migration.
- Thirty-second loopback HTTP rehearsal: 50 simultaneous sessions, 50 separate owners/customers, 100 environments, 50,000 software entries. The subsequent full Worker rehearsal includes session, enabled MFA and recovery lease checks: no errors or cross-account rows; 29,596 requests, request p95 66 ms and complete-customer-read p95 232 ms. Fifty active requests were observed. This precedes the final selected-customer index improvement; final results are recorded separately.
- Actual pagination/browser integration: one workspace with 50 customers, 100 environments and 10,000 software entries. With 50 ms simulated request latency, desktop/phone report readiness measured 964/935 ms and customer switches 315/289 ms. Complete 400-finding CSV export, rapid selection changes, report paging and session clearing passed.
- Existing customer security, software-upgrade freshness, imports, finding details and report authorization tests passed.

These tests use local SQLite and intercepted browser requests. They do not measure Cloudflare edge execution, D1 latency/quotas, actual CVIE ingestion contention, sustained imports or fifty simultaneous browsers. Proposed latency targets are not production guarantees.

## Release and remote acceptance still required

1. Finish review and CI reproduction of the scoped production package; never deploy the entire main branch. The website compatibility fallback must serve before the larger database ceiling is activated.
2. Prepare and approve an isolated Cloudflare rehearsal using fictional sessions and data only. The existing staging environment is `cloudflare-cvie-staging`, in separate account `9706b4d98ad72884e67fd1eb875c8a61`; its pinned approval is still commit `4db5c5ae88e2994cbf1637a4777b803ffd28fdd7`, with the legacy release lane disabled. This is not authorization to change its approval pin, recovery state, access policy or retained rehearsal databases. No remote staging change has been performed.
3. Exercise 50 concurrent authenticated sessions, 100 environments, at least 10,000 software entries, concentrated large customers, concurrent writes and CVIE background work. Capture p50/p95/p99, errors, rows read/written, CPU, response bytes, freshness and completeness. Account-wide dashboard/inventory startup and organization rendering still need larger-data measurements; customer report optimization alone is not certification of every page.
4. Release only after remote acceptance. Preserve the previous backend/site version, apply additive schema through the existing protected migration lane, verify recovery guards and actual data counts, and verify production without inserting load-test customers there.

No migration, capacity activation or production publication has occurred in this phase yet. Persisted incremental assessment results are not included in the current candidate.

## Isolated Cloudflare execution proposal

The owner explicitly approved adding and approving this isolated protected test job on November 13, 2026. The reviewed proposal is `deployment/proposals/inventory-capacity/cloud-load-workflow.yml`; the active caller is `.github/workflows/inventory-capacity-cloud.yml`. This approval permits the new staging credential caller and synthetic database, not changes to existing access controls or production resources.

The activated workflow has exact policy tests. It requires the exact reviewed main commit, manual dispatch, first attempt, credential-free package preparation and the existing protected `cloudflare-cvie-staging` review. Only the execution step receives the existing staging token. It creates a new database named `cveharbor-capacity-<run-id>` in staging account `9706b4d98ad72884e67fd1eb875c8a61`; existing and retained databases are never reused. Cloudflare remote development runs the scoped application with real session/MFA/recovery checks against that separate D1. No public route, Access policy, credential value or staging approval pin changes. The named fictional database remains for inspection; the temporary preview ends with the job.

The initial remote run has 50 concurrent sessions, 50 owners/customers, 100 environments, 10,000 host names and 50,000 installed software entries, sustained for two minutes. It checks complete 1,000-entry customer reads, foreign-account denial and authentication. Acceptance requires zero request/completeness errors, request p95 below one second and complete customer-read p95 below three seconds. This first remote scenario does not certify actual CVIE ingestion or concurrent import contention; those remain explicit acceptance gaps. Aggregate-only results exclude tokens, credentials and row contents.

The large-workspace browser audit found a 13.8-second dashboard startup at 50,000 entries with 50 ms simulated request latency. Metadata-first controls and customer-scoped loading now show the selector in about 0.46 seconds and the selected dashboard in 1.32 seconds; switching took 0.52 seconds. Full-workspace reads use at most four disjoint environment requests, retain a shared revision and discard changed partition lists. This is local synthetic evidence, not a production measurement.


## Fresh primary read authority follow-up

The PR385 isolated cloud run 43543591270 failed: both NVD outage phases lost all 50 sessions after D1 resource-window errors. Its mostly-primary data routing demonstrates that replica availability cannot be assumed. No candidate from this outage capacity investigation has been deployed.

The next candidate combines maintenance state and session/MFA validation in one fresh primary SELECT for the audited read routes. The result is restricted to the exact Request and request-local database capability, and session expiry is checked again before use. Later requests, mutations and background work retain current checks; missing control state fails closed. Replica data remains anchored to the resulting primary bookmark. No cross-request authentication cache or recovery lease change is introduced here.

Workspace inventory totals select the currently owned environment set once instead of repeating customer/environment joins for every software entry. Ownership transfers and agent retirement remain enforced. The isolated fixture now includes the existing workspace read tables for integrity and lifecycle delivery, avoiding missing-table queries; this is not a production migration or permission to enable notification jobs.

The scoped package is based on the serving PR381 Windows Agent backend, with an exact eleven-module delta (eight changes, three additions). Package tests: 122 passed. Local 50-customer rehearsal retained all sessions in both outage phases (1,291 and 1,250 journeys); worst endpoint p95 was 466 ms. The timeout workspace-tab probe took 1,324 ms, exceeding the unchanged 1,200 ms gate, so local browser acceptance is not claimed. Cloud acceptance and production release remain pending.


## Snapshot-validated response reuse

PR386 cloud run 43546783039 failed with all measured data reads on primary: 28/50 sessions survived timeout and 49/50 survived HTTP 503. Neither fast individual controls nor the one-provider-attempt result satisfies capacity acceptance. Production remains unchanged.

The next candidate reuses bounded dashboard/CVIE and customer/environment/asset-page JSON responses in Worker memory only. Every lookup still performs a fresh combined primary maintenance/session/MFA check. The key includes the current user, exact URL/scope, relevant feature settings and the exact newly observed D1 bookmark. Any write changes the snapshot; no bookmark means no reuse. A request that observes different bookmarks while loading is not stored. Revocation, enabled MFA, expiry, wrong origin, customer transfers and agent mapping/metadata changes are tested. No promises or authentication decisions are shared across requests, and no endpoint gains writes or background work.

Snapshots expire after five seconds without renewal. This bounds clock-derived status/count reuse; `X-CVEHarbor-Read-At` records the response snapshot time. Private responses retain `Cache-Control: no-store`. Errors, incomplete sections, cookie-setting responses and entries above 512 KiB are excluded. Storage is bounded to 32 MiB/512 entries per database identity, in addition to the existing bounded SQL/page cache. CVIE telemetry still records cache-hit operations with zero data statements. A real 50-customer/50,000-entry memory test fills all dashboard and paginated responses, then proves every hot request performs exactly one fresh authority query.

Validation: 126 scoped package tests and 13 test-harness tests pass. The local timeout/503 rehearsal passes unchanged gates: 50/50 sessions in both phases, 5,385 journeys, worst endpoint p95 247 ms, workspace tab 459/456 ms. No Cloudflare capacity conclusion is drawn from the local approximation. The cloud probe now records whether unchanged primary literal reads return equal bookmarks (boolean only; no bookmark or private value is exported). The cloud gate and production release remain pending.

The cloud observer now derives the cache identity from the original native D1 binding before wrapping it for measurements. It no longer substitutes a constant test identity, so a cloud pass must reflect the production binding lifetime as well as bookmark behavior.


## Query-cost investigation after PR387

Cloud run 43549119081 failed (artifact 14095553764; SHA-256 47accfefab5c840e3c8636ae6fe60771e108c57e07d41b0fc6fc749bd180740a). Unchanged primary bookmarks were equal and response reuse reduced database calls, but only 2/50 sessions survived timeout and 6/50 survived HTTP 503. All six browser probes completed with controls at or below 199 ms, which does not compensate for failed customer sessions. Production remains unchanged.

The next isolated run adds numeric per-query profiles: a fingerprint of SQL structure (never SQL or bindings), native execution time, returned byte count, rows read, primary/replica routing and error counts. The diagnostic observer implements native first() via all() followed by row-zero selection so metadata discarded by first() is measured without issuing another query. Successful-result observation time is recorded before diagnostic serialization. Authentication and application results remain unchanged. Existing workload, failed-session handling and timing gates remain intact; this is an investigation of the same held backend, not a new production candidate. Fourteen observer/outage harness tests pass, including no exported SQL, credentials or values.


## Inventory snapshot residency after the query profile

Diagnostic run 43551651913 (main 0bead390752ad8253aad0e4c1a95b4920f8c9b40) kept all 50 customers through both outages and passed the outage/browser thresholds, but lost four baseline clients to primary-authority resource-window errors. It remains a failed release gate. Its baseline returned about 894 MB of compact inventory query bodies in 120 seconds. Native bindings and primary bookmarks were overwhelmingly reused; snapshots did not change during baseline. Retain artifact 14097145258 (SHA256 916e5b41725535f09c22c8b3686ba006e0fd8f0c309c04ca87ec3a52922dac63).

Inventory pages have only database-dependent values, including explicit stored agent activity. Their exact-bookmark response residency is now 60 seconds, allowing repeated visits to different worker isolates without rebuilding identical pages every five seconds. Every lookup still performs the fresh primary hold/session/MFA check, uses the authenticated owner and exact URL/flags, and requires exactly the same database bookmark. Any database mutation misses immediately. Hits never renew residency. The 32 MiB/512-entry bounds and no-store client headers stay unchanged; no shared external cache is introduced. CVIE and workspace summaries retain five-second expiry because they also depend on the clock.

Validation covers the actual 50-owner/50,000-entry workload revisited after 20 seconds, immediate asset edit visibility, disabled MFA and maintenance holds, independent expiry for workspace summaries, and the 60-second hard residency boundary. The exact scoped production-baseline package passes 42 relevant read, inventory and recovery tests. Production release still requires the next isolated cloud test to pass in full.


## Proposed coordinated authority experiment (approval pending)

PR389 cloud run 43553386748 passed the baseline (12,330 complete journeys, zero failed customers, API p95 205ms) but failed both NVD outage phases: 0/50 and 1/50 customers survived. Inventory payload traffic was halved, but fresh-primary resource-window failures remained. Production is unchanged. This is not a successful capacity release.

The next experiment combines simultaneous hold/session/MFA checks in a single current primary SELECT, executed by one private Durable Object coordinator. It batches for 10ms, at most 128 checks per SQL query and 256 waiting checks. It never reuses an earlier authorization decision or stores request data in durable storage. Each caller receives only its indexed result and the primary bookmark; customer data queries retain the existing bookmark-anchored routes. Deletion/expiry, MFA disablement and maintenance holds still deny access. Schema and incomplete-result failures fail closed; transient failures retain the existing bounded retry behavior.

The experiment is confined to test files. No production application module, release identity or production configuration changes. The proposed protected manual main-only workflow `inventory-capacity-coordinator.yml` has credential-free preparation and the existing staging credential, concurrency lock and 45-minute limit. It adds one private Worker `cveharbor-capacity-authority` and one Durable Object namespace in staging account 9706b4d98ad72884e67fd1eb875c8a61. The only D1 binding is retained fictional database b4a226d7-35e8-469f-abfe-2a2eee0a96de. The coordinator has no public handler, routes, workers.dev or preview URLs. Existing resources with that name must have the exact test marker and bindings before update. The Worker/namespace are retained for inspection. No new D1 database, credential, access-policy setting or production/existing-staging deployment is part of this test.

Local evidence: one SQL query served 50 simultaneous authority checks, with correct customer isolation, revocation while queued, session expiry, MFA and maintenance behavior. Full application/SQLite and Chrome outage rehearsal passed all 50 customers in both phases, 2,400/2,500 journeys, endpoint p95 at most 193ms and browser controls at most 139ms; 200 saved advisories retained. This does not prove cloud performance. The workflow security checker passes with only the explicit additional caller allowed.

**Do not merge this credential-caller expansion or create the test coordinator until the owner separately approves it.** That approval covers the additional isolated test infrastructure and job only; a successful experiment is not authorization to change production architecture.
