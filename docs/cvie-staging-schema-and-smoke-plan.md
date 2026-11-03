# Task 2C: staging schema and synthetic validation execution plan

Status: prepared for owner review; **no remote migration or fixture load authorized or executed**. This is the current next-phase plan, superseding the initial empty-infrastructure assumptions in older staging preparation documents. PR #243 remains draft and unmerged. PR #252 remains on hold.

## Authentication milestone

[Run #14, attempt 2](https://github.com/Prat007ai/cveharbor/actions/runs/41691571014/attempts/2) succeeded at `01f5133f410053a733ba6c9e45df613114695ed6`. Its sanitized provision/access artifacts confirm:

- Only `cveharbor-site-staging` was updated: deployment `73fdd8bf-246c-4af0-9be9-3adfb805c624`, version `70dd01cb-56e2-4b23-bc66-5b59a4fc274e`.
- API deployment `9cf2324d-14e9-4818-8760-185247090fbc`, version `6c39aeca-a26f-4c39-bfdf-b41d4fc33e1d`, remained unchanged.
- All 28 GET probes passed: anonymous/forged JWT requests received Access redirects; service authentication returned 200 on all six sampled asset routes; authenticated cross-origin asset probes received Worker 403, establishing Worker execution before assets. Active-version metadata separately verifies universal Worker-first routing.
- Service authentication without an application session received 401 on `/v1/me`; the private API public origin returned 404. Access service credentials do not grant an application session.
- Native local workerd tests validate signed human and service assertions and reject invalid assertions. An interactive human browser SSO login was not exercised by these live probes.

Automated frontend authentication validation is complete. Full Task 2C database, application-session, browser and performance validation remains pending. The corrected JWKS fetch uses Workers-supported `redirect: manual` and explicitly rejects redirects; JWT verification is retained. No migrations, email or schedules were enabled.

## Exact execution boundary

Use only the existing protected `cloudflare-cvie-staging` environment and its existing staging credentials. Account: `9706b4d98ad72884e67fd1eb875c8a61` (CVEHarbor Staging). Database: `cveharbor-accounts-staging`, UUID `fac61562-fc31-426d-8032-550aba63b7f6`. Frontend: `https://cveharbor-site-staging.cveharbor-staging.workers.dev`. Private API: `cveharbor-accounts-staging` through the existing service binding.

No new resources, environments or workflows; no production access, deployment, Access-policy changes, background processing, email, external provider fetches or production data imports. Both Workers and the database must be preserved. Retain all existing account/name/UUID, repository/branch/SHA, reviewer and operation gates. Do not reuse the currently approved `deploy-frontend` operation for SQL.

## Phase A: schema only, separate execution approval

1. Prepare a narrowly scoped migration operation in the existing protected workflow for review. It does not exist today: current operations create the database or deploy Workers only. Pin its final commit and operation in the protected environment after owner approval; no initial push may execute SQL. Preparation and local tests must finish before requesting execution. No Worker deployment belongs in this operation.
2. Revalidate staging account/database identity, current Worker versions/bindings, Access boundary, disabled schedules/provider/email, and exact SQL checksums. Read current D1 schema and row counts without returning data. Earlier diagnostics reported zero tables; do not assume this remains true. Abort if any application tables, unexpected objects or prior migration state exist; prepare a reviewed forward plan rather than replaying bootstrap.
3. Generate `bootstrap-through-0027.sql` using `python staging/scripts/schema.py` at the pinned source. Apply it only to the exact staging UUID with an explicit staging config/account; never use the backend's default production Wrangler config. Then apply `0028_cvie_source_efficiency.sql`, then `0029_cvie_identity_registry.sql`, with verification between phases. The [review manifest](cvie-evidence/staging-schema-plan-manifest.json) pins all 29 input files and the aggregate bootstrap SHA-256 to application source `01f5133f410053a733ba6c9e45df613114695ed6`.
4. SQL includes built-in catalogue seeds, triggers and historical data transformations; it is not pure DDL. This scope authorizes only checked-in schema/seed SQL on a verified empty staging application schema, not customer fixtures or external imports. Review these statements as part of the final executable diff. Never silently skip errors or mark a failed phase complete.
5. Record sanitized receipts per phase: source/SQL digest, target identity, start/end, success/error category, and schema fingerprints. Define durable completion/reconciliation in the executor before approval; no extra bookkeeping table is implicitly approved by this plan. A lost response is ambiguous, not permission to retry. Read back actual schema before deciding the next action.
6. Compare expected tables, columns, indexes and triggers against local SQLite, excluding D1 internal objects. Expect 90 application-schema tables. Run supported integrity/foreign-key checks, verify built-in seed invariants and absence of customer/session/fixture rows. Recheck authentication and unchanged Worker versions/settings. Report reads/writes and final schema digest, never credentials or row contents.

Local preparation revalidated all 29 source file Git blob hashes against the deployed commit, then executed the complete ordered schema in in-memory SQLite with foreign keys enabled, per-file foreign-key checks and final integrity check: **90 tables, passed**. This does not establish remote D1 compatibility; remote execution must inspect every D1 result for HTTP errors, `success:false`, and statement errors, with a failing phase/statement identifier and a fixed sanitized error category.

On any mismatch or failed/ambiguous phase: stop, retain resources, collect sanitized read-only evidence, and propose recovery. No automatic drop, recreation, replay, destructive rollback or database restore. D1 file execution may partially succeed; local SQLite validation is not proof of remote all-or-nothing behavior.

## Phase B: bounded synthetic CVIE smoke, after schema acceptance

Prepare the deterministic fixture generator and authenticated harness locally before approval to write fixtures. Submit their exact checksums, row counts, SQL and request list for review. Use reserved `.test` identities and synthetic vulnerability records only; no live feeds or production snapshots. Proposed ceilings: two isolated tenants, two users, two customers, ten products/assets per tenant, 100 synthetic CVEs, at most 2,000 fixture rows, 200 API requests, concurrency two and ten minutes. Stop at 100,000 D1 rows read, 10,000 rows written, any unexpected resource/config change, tenant leak or attempted external delivery. Instrument budget enforcement before execution; do not assume provider blocking alone prevents queued background work.

Required matrix:

| Check | Expected result |
| --- | --- |
| Anonymous/forged Access assertions and direct API origin | Remain blocked |
| Valid Access service authentication, no application session | Static assets work; application API returns 401 |
| Properly authenticated synthetic application sessions | Normal authorized API reads and bounded approved mutations succeed |
| Tenant A attempts tenant B reads/writes | Denied, no leaked records or changed rows |
| Deterministic product identity and version matching | Expected positive/negative evidence; stable pagination and idempotent bounded writes |
| KEV/rejection/correction synthetic cases | Match fixture truth without sending notifications |
| Unknown product/no match | Empty or explicit pending result, no uncontrolled discovery |

Use real application session and MFA authorization rules. Session fixture preparation must follow existing middleware; do not add an authentication bypass or test-control HTTP route. Never emit raw session tokens, Access assertions or service secrets in logs/artifacts. If existing API flags, a TOTP secret or another configuration change is necessary, present the exact change for separate approval before proceeding. Registry/fast-evidence flags are currently off; do not describe baseline smoke as validation of enabled optimization. Keep scheduled handlers disabled, outbound providers blocked and all delivery flags off; avoid application operations that queue discovery until their bounded behavior is demonstrated locally.

Capture sanitized request outcomes, expected-vs-actual fixture counts, tenant isolation, D1 cost and latency. Leave synthetic records identifiable; cleanup is a separately reviewed scoped operation, never a database reset. No larger 10k/100k load campaign, feature activation, rollback experiment or rescan is included. Those remain the subsequent Task 2C performance phase after smoke acceptance.

## Next approval

Review this plan first. Codex will then prepare and locally validate the narrowly scoped executor in PR #243 using the existing workflow. The next execution request must name its final commit and **schema-only staging migration** operation and include exact SQL digests and stop conditions. Fixture writes, API configuration/deployment changes and larger CVIE testing need their own explicit scope approval. Until then, do not dispatch or rerun a write job, alter the protected approved-operation variables, or execute SQL remotely.
