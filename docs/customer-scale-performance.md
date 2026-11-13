# Customer-scale performance audit — 2026-11-13

## Result and release boundary

This release reduces browser blocking in the personal customer dashboard, customer reports and inventory. It does **not** certify production capacity for thousands of fully inventoried hosts or 50 simultaneous active customers. Synthetic browser inventory bypasses the current API cap, and the mocked API has 100 ms latency. Production D1 latency, concurrency, ingestion throughput and a concentrated large-customer distribution remain separate acceptance work.

The scoped package overlays four assets on verified PR360 (main `1bb05f0b7d5f4c47afbe347ce27f613e32e4e922`, site version `a4c3f8d0-3ae6-4fed-80ce-3e95aded1347`, deployment `e698f06f-7374-4ed4-980e-ff8e6d12767b`). Backend identity `0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34` is retained. No schema, credentials, access roles, AI activation, allowances or inference calls change. Held main-branch backend work is not released.

## Reproduced bottlenecks and fixes

- Dashboard matching and repeated asset/finding joins blocked the main thread. Matching now yields cooperatively and cancels obsolete selection work; scoped assessments are reused until inventory or advisory evidence changes. Asset lookup maps replace repeated scans.
- Dashboard findings now render 50 rows per page. Report software, inventory, verification, references and evidence sections are also paged. Totals and CSV still use all available scoped findings; the existing matcher limit and PDF limit remain explicitly bounded.
- Collapsed inventory customers previously created all hidden software controls. Their contents are created on expansion, with ten hosts per environment page and fifty components per host page. Coverage-review details are also built only on expansion, with 50 entries per page.
- AI priority cards select the same top three findings without sorting every candidate. A parity regression covers exploitation, severity, duplicates and stable ties; no AI service is involved in prioritization.
- Focus storms previously reread and rebuilt unchanged inventory. Focus checks still revalidate authorization, coalesce overlapping requests and reload inventory after 60 seconds. Explicit inventory-change broadcasts and exports bypass that window. A save received during an authorization check is retained. Session loss clears private results and cancels pending rendering.
- Report export waits for the current render and checks that the customer/environment did not change. CSV remains complete across UI pages; print uses its separate scoped document.

## Measurements

Controlled local Chrome fixture: 50 customers, 100 environments, 2,000 host names, 10,000 software entries, 5,000 advisories, including 42 matching PHP advisories for each of 2,000 PHP entries (84,000 asset–CVE candidates across the account). Desktop 1440 px and phone layout 390 px; actual Windows hardware, no CPU throttling. Network responses are fictional and delayed by 100 ms each. No real customer mutations, notifications or paid AI requests.

Before: dashboard longest blocking task 1,374 ms, approximately 17,470 DOM elements, customer selection 459 ms. Report selection 1,164 ms on desktop; original report blocking-task measurement covered initial unselected state only and is not a valid full-render baseline. A repeated focus burst caused another inventory read.

After (representative development run, with all correctness assertions passing):

| View | Desktop selection | Phone-layout selection | Longest task, desktop / phone | Rendered elements after selection |
|---|---:|---:|---:|---:|
| Dashboard | 230 ms | 248 ms | 222 / 237 ms | 4,143 |
| Reports | 879 ms | 916 ms | 66 / 122 ms | 2,716 |
| Inventory | 250 ms | 200 ms | 182 / 185 ms | 6,511 |

Dashboard initial ready time was about 2.3–2.4 seconds in this run. None of these measurements is a production p95 or a guarantee of zero delay. The test requires selection under 1.2 seconds, maximum observed task under 300 ms and no extra inventory reads from the focus burst. Browser fixture gates run against both the exact release package and downloaded serving assets in the protected workflow.

Correctness checks include 1,680 findings for the selected customer, 50 displayed rows, next-page access, fast selection cancellation, all 1,680 CSV rows, explicit-save refresh during a focus check, and expired-session clearing. Existing tests retain version exclusions, remediation statuses/tickets/notes, customer isolation, source guidance, upgrade history, printing and mobile controls.

## Capacity limits found

`account-backend/src/inventory.js` advertises 100 customers, 500 environments and **3,000 software rows per account**. Both the asset read and write cap use 3,000. A host with five recorded components consumes five rows. Thus the customer/environment counts can fit the requested topology, but thousands of inventoried hosts cannot be certified under this cap. `plugin-monitor.js` and other companion account reads have corresponding limits. Team customer reads are customer-scoped but not fully paginated. Browser matching retains up to 5,000 findings per customer/environment; narrowing scope remains necessary for dense result sets. PDF findings retain the existing 250-entry presentation limit; CSV includes all available filtered findings, not unlimited server results.

**Do not raise the asset cap alone.** That would leave older reads and companion data incomplete and increase browser memory and work. The current release intentionally retains the limit.

## Required next capacity release

1. Add indexed customer/environment-scoped, cursor-paginated inventory and companion reads, explicit completeness metadata and consistent authorization on every page. Migrate every consumer, including organization views, Workspace, collectors/imports, matching, status/ticket joins and exports. Test duplicates, omissions, concurrent saves/deletions, revoked access and cross-account cursors before raising the cap.
2. Store versioned assessment results keyed to inventory and advisory revisions. Incrementally reassess changed products/assets in background work; browsing reads the latest completed result and displays freshness and pending work. Retain exclusions, rejected-advisory removals, applicability uncertainty and customer isolation. CVIE discovery and AI generation must not block menus.
3. Exercise the complete synthetic system in an isolated Cloudflare Worker/D1 environment, including 50 simultaneous sessions, 100+ environments, at least 10,000 software entries, larger/concentrated accounts, active CVIE ingestion and export jobs. Record p50/p95/p99, errors, database rows read/written, CPU/memory, queue age and inventory-to-finding freshness. Use existing held architecture work only after its own review and acceptance gates; merging main is not authorization to publish it wholesale.
4. Proposed acceptance targets: interactive menus below 100 ms at p95, cached customer switches below 500 ms at p95, initial usable dashboard below 2 seconds at p95, no lost or cross-customer findings, and no browser crash during a sustained test. These are targets, not results achieved here. Validate first, then choose and raise the account cap to the tested bound.

An isolated remote scale environment has not been verified in this audit. No production load generator, staging resource creation or credential change was performed. Existing instructions require separate authorization for any new credentials/access configuration; routine reviewed site/backend deployments retain standing approval.
