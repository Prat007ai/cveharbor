# Task 4 implementation review

Baseline: main `6e52d77e7ae634c73f6bb9389111b98d55f3d287`. Isolated branch: `feat/workspace-operational-dashboard`. No production deployment or merge authorized for this task.

The application is static HTML, plain JavaScript and shared CSS, built by `scripts/build_site.py`. `workspace/index.html` retains the account-page OTP/MFA controls and uses `account-page.js` and the narrow `command-center.js` sidebar. These shared authentication/navigation modules are reused without modification. New workspace CSS is scoped to this page.

Account access is enforced by the Worker session/MFA lookup, followed by `user.id` filters on inventory, findings, remediation and monitoring. There is no separate delegated-customer role model in the current application. New read operations preserve this contract and join customer/environment/asset ownership at every level; caller-supplied user/customer IDs cannot broaden access.

## Data mapping

- Customers: account-owned inventory_customers count.
- Active environments: unavailable because inventory_environments has no active flag. Show registered count as context.
- Monitored assets / coverage: unavailable. inventory_assets represents technology entries and can contain multiple entries for one host; there is no unique monitored-host denominator.
- Remediation: stored remediations only; Open + Investigating are unresolved. Remediated, Accepted Risk and Not Applicable remain separate. Customer finding statuses are a separate chart view with exact existing labels. Candidate CVEs are never inserted or counted as tracked work.
- Activity: inventory_software_history is real append-only change history where installed. No synthetic creation/deletion/remediation events from current records.
- Assets added: inventory entries with actual created_at and authorized customer/environment names; labelled as registered entries, not unique monitored hosts.
- Environments: registered account-owned records. Existing environment manager route is reused; customer dashboard links use its supported `customer` query parameter.
- Needs Review: explicit saved customer_finding_statuses rows only, not implicit matches.
- Reports: existing /customer-reports/ generation and export remain available; no persisted report archive, drafts, schedules or downloadable export history exists.
- Intelligence: a compact build-generated public advisory JSON projection for a defined 30-day snapshot period. No full CVE dataset download on workspace load. Public/global scope and coverage limitations are explicit.
- Health: website monitor check timestamps/errors, last digest submission state, and optional existing lifecycle provider message states for the last 30 days. Provider delivery and inbox placement remain distinct; no success percentage is inferred.

## Shared files and dependencies

Minimal integration edits: account-backend/src/index.js (authenticated GET routing), scripts/build_site.py (CSS/artwork and bounded public advisory projection). These files overlap ongoing lifecycle/backend work; review current main before merge. No edits to ingestion, customer records, schemas, account-page.js, command-center.js, customer-security.js or lifecycle modules. Backend read module and tests are additive. Deploy the compatible read API before or with the workspace frontend after review; UI shows unavailable states on an older API.

Additional capabilities requiring separate approval: active-environment lifecycle, unique asset/monitor linkage, comprehensive audit events, persisted report archives/drafts/scheduling, unified provider-delivery health across all email features (the existing optional lifecycle message states are reused). No tables, triggers, indexes or background jobs are added here.

## Implemented components and source files

| Files | Change |
| --- | --- |
| `workspace/index.html` | Header, five metrics, eight navigation cards, activity/report/remediation tabs, intelligence and health panels; existing login and MFA markup retained. |
| `workspace-dashboard.css`, `assets/workspace-harbor.svg` | Scoped responsive styling, reduced-motion support, static vector lighthouse and sea, focus states and loading treatments. |
| `workspace-dashboard.js` | Auth-event-driven read orchestration, six-query aggregate response, tab navigation, five-row pagination, status charts, errors/empties and cancellation/clearing on sign-out. |
| `account-backend/src/workspace-summary.js`, `account-backend/src/index.js` | Two authenticated read-only routes, below the existing session/MFA guard. |
| `scripts/build_workspace_intelligence.py`, `scripts/build_site.py` | Bounded global public projection, 30 calendar days through the source snapshot date, capped at 50 feed records with a full period count; publish new page assets. No ingestion changes. |
| `scripts/browser_smoke.mjs` | Update old workspace assertions for the new summary API, markup and bounded feed. |
| `account-backend/tests/workspace-summary.test.mjs` | Real SQLite ownership, optional-schema, pagination, rejected-write, session/MFA and provider-evidence tests. |
| `scripts/workspace_fixture.mjs`, `scripts/workspace_dashboard_smoke.mjs`, `scripts/workspace_dashboard_browser.mjs` | Synthetic-account interaction and browser tests. Fixtures are never copied to public output. |
| `tests/test_workspace_intelligence.py` | Period boundaries, deduplication, bounded output and empty feed tests. |
| `.github/workflows/verify-workspace-dashboard.yml` | Branch/PR verification and screenshot artifacts; no secrets, production calls or deployment jobs. |

## API and query contract

`GET /v1/workspace/summary` performs six SELECT queries in parallel: account-owned inventory counts; remediation counts grouped by exact saved status plus overdue unresolved records; saved customer finding status counts joined through owned inventory; website monitor timestamps/error counts; latest alert digest submission; optional lifecycle message states for messages created during the last 30 days. New provider evidence reuses Task 3's optional tables without creating or activating them. Existing user-prefix indexes support account restriction. No per-card requests or complete private inventory downloads are needed.

`GET /v1/workspace/items?view=activity|assets|environments|review&offset=0` performs one selected, account-restricted query, fetching six rows to return five and a next-page offset. Offset is validated and capped at 10,000. The view is selected from a fixed SQL map. User/customer query parameters never change authorization. Environment rows open the existing environment manager; customer links use the dashboard's existing supported customer selector.

All new responses use `Cache-Control: no-store`. No GET invokes `.run()`, schema setup, scans, email sending, CVIE synchronization, or audit writes. Existing authentication, route names, account restrictions, schemas and records remain unchanged. Public intelligence is a static JSON build artifact, not a D1 endpoint.

## Validation and review evidence

- Existing backend suite plus new workspace tests passed in CI; the initial complete run passed 258 tests, with an additional provider-evidence test added afterward.
- Public snapshot tests cover date boundaries, future records, old records, duplicate identifiers, a 50-record payload cap, and empty data.
- Frontend tests cover exact open-remediation calculation, unavailable monitored asset/active-environment states, report limitations, pagination, status-model switching, GET-only network behavior, errors, empty records and sign-out clearing.
- Chromium exercises the actual existing account-page integration with intercepted synthetic private records. It checks 320, 390, 650, 768, 820, 1024, 1280, 1672, 1920, 2560 and 3840px widths, narrow desktop sidebar, no overflowing cards, keyboard tabs, pagination, and empty/error/signed-out states.
- Existing site browser smoke and Worker release smoke passed. The repository has no separate workspace TypeScript compiler or lint script; JavaScript syntax checks, Python tests, builds and applicable automated suites are used.
- Draft PR: https://github.com/Prat007ai/cveharbor/pull/230. Review images use synthetic private account data and the real public snapshot, never production customer records. CI artifact: `workspace-review-synthetic-data` (desktop, wide, mobile, empty and error screenshots plus measurements).

## Remaining limitations and coordination

The page deliberately displays unavailable active-environment and unique-monitored-asset totals, with registered counts as context. Saved report history, drafts, schedules and server-retained exports do not exist. Activity currently covers recorded software changes; deletion and full remediation event history are not inferred from current records. Scan freshness covers existing website monitoring evidence, not a universal scan guarantee. Provider evidence is limited to lifecycle message states when that optional storage exists; digest submission is labelled separately and inbox placement is never claimed.

No historical trends are invented. Customer finding statuses and account remediation records are shown separately to avoid double counting or confusing potential matches with confirmed exposure. The aggregate may show partial/unavailable states on missing or failed optional services.

Concurrent work after the baseline changed generated snapshots and production verification (`#229`), outside this PR's source edits. Recheck shared integration files against main before approval. Task 3 lifecycle storage is optional, and Customer Security Dashboard/Reports continue to own matching, generation and exports. Deploy the compatible read API before or with the new frontend only after explicit approval. This task does not merge or deploy itself.


## Visual reference refinement

Follow-up review tightened the composition against the original 1672px mockup: the overview row begins near 174px and the three operational panels near 512px. Added the current local date card, a static wireframe sea/lighthouse illustration, existing search/alerts navigation in the header, stronger icon tiles and gradients, customer/event row icons, compact severity badges, percentage labels derived from actual remediation counts, colored remediation summary tiles, and neutral circular health indicators. The donut center now shows unresolved tracker records (Open + Investigating), consistent with the overview metric; all saved statuses remain separate in the chart and legend.

The date uses the browser's actual local date. Decorative artwork is not a data series. No invented trends, percentage health gauges, report history, or unread-alert badges were added. The search control links to the existing vulnerability search; it does not promise an unsupported cross-customer global search. No backend, query, authorization or schema changes were needed for this visual refinement.

Revalidated the build, frontend interaction checks, existing browser/Worker smoke checks, and Chromium layouts at 11 widths from 320px to 3840px. Review images use intercepted synthetic private records and the public advisory snapshot; they do not show production customer data.

## Approved production release preparation

The user approved merging and deploying the complete reviewed workspace on November 2, 2026. Reconciled the newer lifecycle picker/dialog and global dropdown-contrast changes from main without replacing them. The workspace stylesheet reference retains the new shared stylesheet cache version.

Added a narrowly scoped `workspaceCodeOnly` Worker release classification and SELECT-only pre/post-deployment probes (`scripts/verify_workspace_d1.mjs`). This release skips unrelated CVIE migrations, cache refreshes, bootstrap jobs, secret configuration and monitoring activation. The probe exercises the shipped queries on D1 under a verified nonexistent account, checks empty scoped results, reports optional-source availability and verifies the unauthenticated API boundary after deployment. It creates no login sessions or customer records. A regression test verifies the probe's read-only behavior and failure on a missing required table.

Production website verification now checks the operational workspace markers and exact published dashboard JS/CSS, lighthouse SVG and bounded intelligence snapshot. Deployment continues through the existing protected Cloudflare website and account Worker workflows. No new schema, services or runtime feature flags are introduced.
