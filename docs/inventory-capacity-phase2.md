# Inventory capacity phase 2 — work in progress

The production baseline is PR361, main `3ce02f24cbcdfd33cd776c6fdd3e4e7a245ed97a`. The serving backend identity is `0b15e96eb98e5d1a2f7e2961e858886c62c632f7eaed1b02d7241a0e7ff34a34`. This change is not yet a deployed or remotely certified capacity increase.

## Implemented candidate

- Private inventory pages contain at most 250 rows, use stable keyset cursors, and recheck ownership and organization visibility on every page. Explicit completion metadata prevents partial exports. Cursor scope includes account, actor, organization, customer, environment and resource.
- Transactional revision reads detect inventory and companion mutations between pages. The client discards partial results and retries at most twice; persistent churn produces an error rather than a mixed report.
- Assets, customers, environments, saved statuses, append-only tickets, plugin source/install/check/release results, package inventory and network inventory have paged reads. Personal, team and Workspace clients use the shared reader. Reports fetch only the selected customer's assets and companion records; metadata retains the customer chooser.
- An additive schema introduces paging indexes, per-account revision/count tracking and an atomic 50,000-software-entry ceiling. The old 3,000-entry ceiling remains until this migration is activated. Legacy clients receive a refresh-required error instead of silent inventory truncation above 3,000 entries. A host with five components consumes five entries.
- Existing recovery guards are preserved and new tables are guarded. AI activation, allowances, credentials, permissions, notifications and real customer records are unchanged.

## Validation completed locally

- Full backend regression: 565 tests passed before the final report request-count optimization. The focused capacity tests cover 10,000 unique rows, account and cursor isolation, mutation invalidation, revocation, 12,000 tickets, 4,000 plugin mappings, atomic maximum enforcement, cascaded counts and repeatable migration.
- Thirty-second loopback HTTP rehearsal: 50 simultaneous sessions, 50 separate owners/customers, 100 environments, 50,000 software entries. No errors or incorrect/cross-account rows; 31,712 requests, request p95 57 ms and complete-customer-read p95 212 ms. This was the initial fixture distribution; rerun after fixture host grouping changes before treating it as final evidence.
- Actual pagination/browser integration: one workspace with 50 customers, 100 environments and 10,000 software entries. With 50 ms simulated request latency, desktop/phone report readiness measured 964/935 ms and customer switches 315/289 ms. Complete 400-finding CSV export, rapid selection changes, report paging and session clearing passed.
- Existing customer security, software-upgrade freshness, imports, finding details and report authorization tests passed.

These tests use local SQLite and intercepted browser requests. They do not measure Cloudflare edge execution, D1 latency/quotas, actual CVIE ingestion contention, sustained imports or fifty simultaneous browsers. Proposed latency targets are not production guarantees.

## Release and remote acceptance still required

1. Finish review and CI reproduction of the scoped production package; never deploy the entire main branch. The website compatibility fallback must serve before the larger database ceiling is activated.
2. Prepare and approve an isolated Cloudflare rehearsal using fictional sessions and data only. The existing staging environment is `cloudflare-cvie-staging`, in separate account `9706b4d98ad72884e67fd1eb875c8a61`; its pinned approval is still commit `4db5c5ae88e2994cbf1637a4777b803ffd28fdd7`, with the legacy release lane disabled. This is not authorization to change its approval pin, recovery state, access policy or retained rehearsal databases. No remote staging change has been performed.
3. Exercise 50 concurrent authenticated sessions, 100 environments, at least 10,000 software entries, concentrated large customers, concurrent writes and CVIE background work. Capture p50/p95/p99, errors, rows read/written, CPU, response bytes, freshness and completeness. Account-wide dashboard/inventory startup and organization rendering still need larger-data measurements; customer report optimization alone is not certification of every page.
4. Release only after remote acceptance. Preserve the previous backend/site version, apply additive schema through the existing protected migration lane, verify recovery guards and actual data counts, and verify production without inserting load-test customers there.

No migration, capacity activation or production publication has occurred in this phase yet. Persisted incremental assessment results are not included in the current candidate.
