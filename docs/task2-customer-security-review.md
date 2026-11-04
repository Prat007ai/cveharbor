> **Phase 1 deployment notice:** Use [the consolidated administrator checklist](reviews/phase1-administrator-checklist.md) for current release, credential, staging and recovery steps. Deployment/migration/rollback recipes below are feature-history references, not instructions to execute during Phase 1. Feature behavior descriptions remain applicable unless superseded by the current implementation.

# Task 2: customer security dashboard and reports

## Starting point and isolation

- Starting checkout: `/workspace/cveharbor`, branch `work`, commit `edff71a37b9d8abb4778d583fa4c147b6369c49a`.
- No tracked modifications existed. Untracked `public/` generated assets, `node_modules/`, and Python bytecode were present and left untouched.
- Task checkout: `/workspace/work/cveharbor-task2`, independent Git clone made with `--no-hardlinks`, branch `codex/task2-customer-security-reports`.
- No AGENTS.md was present in the repository. No production database, migrations, configuration, deployment, merge, or email delivery was used.
- GitHub comparison against `504fc875a934a0517ddf6fc19bfa415912c708e4` showed that the ongoing release branch was 14 commits ahead of this base. This task does not contain those newer fixes. The base already contains earlier Hyper-V corrections such as `10348cb` and `0fe63e9`.
- The newer changes include CVIE provider/coverage/identity modules, `cvie.js`, `cvie.css`, associated tests, and data refreshes. They were inspected through read-only GitHub metadata, not merged into Task 2.

## Existing implementation and reuse

| Concern | Source | Existing API / D1 storage |
| --- | --- | --- |
| Report and dashboard rendering, filters, exports, remediation UI | `customer-security.js`, `customer-reports/index.html`, `customer-dashboard/index.html` | `/v1/inventory`, `/v1/inventory/status` |
| Customer/environment ownership | `account-backend/src/inventory.js` | `inventory_customers`, `inventory_environments`, `inventory_assets`, all scoped by `user_id` |
| Finding statuses | `account-backend/src/finding-status.js` | GET `/v1/finding-statuses`, PUT `/v1/finding-statuses/:asset/:cve`; `customer_finding_statuses` |
| Ticket references | same module | GET `/v1/finding-tickets`, POST `/v1/finding-tickets/:asset/:cve`; `customer_finding_ticket_history`, legacy `customer_finding_tickets` |
| Score and history | `customer-score.js`, `account-backend/src/customer-score.js` | `/v1/customer-score-history`; `customer_security_score_snapshots` |
| Plugin coverage, installation status and sources | `plugin-monitor.js`, `plugin-sources.js`, `plugin-advisories.js` under backend src | `/v1/plugin-monitor`, `/v1/plugin-installation-status`, `/v1/plugin-sources`; existing monitoring/source tables |
| Intelligence widget and matching | `cvie.js`, `cvie.css`, `inventory-matching.js` | Existing CVIE APIs and tables; implementation unchanged |
| Authentication and email | `account-backend/src/index.js` | Existing authenticated session/MFA, origin checks, customer-report-email delivery |
| Sidebar | `command-center.js`, existing shared sidebar CSS | Existing routes, icons, tooltips, highlighting and responsive behaviour unchanged |
| Build and tests | `scripts/build_site.py`, backend Node tests, Python unittest, smoke scripts | Static build, jsdom, existing Node SQLite test support; no new runtime dependency |

The shared finding table now takes a read-only mode. Both views use the existing asset/CVE status and ticket records. No new remediation store or scoring algorithm was introduced. Status saves retain existing reviewer notes.

## Changes

- Report header retains PDF, email and CSV controls; selectors remain scoped to the selected customer and environment.
- The existing mounted CVIE widget is moved alongside the existing score component. The widget is not reimplemented. Source status/backlog is explicitly identified as shared intelligence status; report verification counts come from scoped findings.
- Four executive cards, a static status/ticket findings table, a read-only software attention table, five independent initially collapsed detail sections, and timestamped report details follow the mockup's hierarchy.
- Plugin status/source editors and manual plugin checks are available in the dashboard's installed-software accordion, not in report content. Reports read saved monitoring results; they do not invoke the legacy on-demand plugin-advisory fallback if monitoring storage is unavailable.
- Dashboard findings provide explicit status saves and append-only ticket additions. Critical/high attention counts update on successful saves. Medium/low findings alone do not create red attention.
- Score thresholds, calculation, confidence and coverage remain unchanged. Reports read cached score history without automatic writes; the dashboard exposes an explicit Record current assessment action using the existing endpoint.
- Reports refresh saved remediation on focus and before PDF/CSV generation. Export fails visibly if saved remediation cannot be read. Session changes clear private rendered content and disable exports.
- CSV respects customer, environment, status filter and sort. PDF includes assessment availability, confidence/coverage, findings, recorded statuses/tickets and timestamped report details. Print content is held stable during browser print capture.
- The existing email PDF upload flow remains. The dialog captures and displays customer/environment at opening so later selector changes cannot relabel its request.

## Deferred architecture: immutable report archive (approval required)

Only **score snapshots** exist. Full reports are reconstructed from live inventory, advisory and remediation data. Downloaded PDF files retain their contents, and the email service attaches the uploaded PDF bytes unchanged; this does not constitute an application-managed report archive.

A separately approved implementation would require:

1. A versioned, immutable report payload containing customer/environment identity, generated timestamp, inventory, findings, saved statuses/tickets, assessment and methodology version, advisory references and source timestamps.
2. A new D1 `customer_report_snapshots` table with snapshot ID, owner user ID, customer/environment IDs, generation timestamp, payload version, payload JSON and a content hash; an index on owner/customer/environment/time. Snapshot content must not be updated when current findings change. Retention, account deletion and customer deletion behaviour need an explicit decision.
3. Authenticated creation and read endpoints with the current ownership checks. Server-side assembly/validation must establish the selected scope and recorded remediation values; an arbitrary client-supplied document is insufficient.
4. A deterministic PDF-generation or validated PDF-artifact binding workflow, with email referring to a snapshot ID. Durable PDF files would also require an approved private object-store binding and retention/access rules, or an approved renderer to reproduce PDFs from stored snapshots.
5. Migration, backup, rollback and staging validation, coordinated after the earlier CVIE fixes.

No snapshot table, migration, object store, renderer dependency or email architecture change is included. Approving this design is a separate decision from reviewing/merging the frontend branch.

## Existing limitations retained

- The permission model is account ownership, not separate per-customer viewer/editor roles. Backend session, origin and asset ownership checks remain enforced. This task does not create roles or restrict an authorized account owner from calling existing APIs outside this UI.
- Tickets are immutable append-only references. Correcting a reference means adding the correct reference while retaining history. Replacing/deleting earlier references would change the existing contract and is not included.
- Email accepts a user-selected PDF and checks PDF format/size and customer/environment ownership; it cannot prove that the document's contents belong to the selected customer. The dialog identifies the scope, but cryptographic/server-side content binding requires the deferred snapshot design.
- CVIE remains unchanged, including existing synchronization and product identity controls. Its shared source backlog must not be interpreted as a customer's verification count. CVIE controls are the explicit intelligence exception to the read-only reporting workflow; no remediation, plugin metadata or score writes originate from report content.
- Matching retains the existing 5,000-result evaluation bound and 250-row detailed display/PDF limit. CSV exports the full currently available filtered set. Limits must be visible; large scopes should be narrowed by environment.
- Reports show potential candidates and recorded review statuses. They do not claim independent vulnerability or patch verification.

## Integration and deployment

Review/cherry-pick the Task 2 commit onto the final approved earlier-fix branch, or rebase this branch there in an isolated checkout. Do not replace whole shared files with this base version.

Highest likely conflict is `customer-security.js` if the other session also changes dashboard/report rendering. Preserve its final API fields and source-status behaviour when resolving. `styles.css` additions are scoped to customer pages. `cvie.js`, `cvie.css`, scoring, inventory matching, backend runtime sources, schema, workflows, and deployment configuration are unchanged by this task.

After integration rerun the build, backend tests, Python tests, customer security/scoring smoke tests, CVIE smoke tests, and Chromium regression. Existing status/ticket/monitoring/score schemas must already be activated for those features; this task does not activate them. Static assets carry updated cache versions. No production deployment or merge is authorized by this change set.

## Validation

Final validation results and artifact locations are recorded in the delivered completion report. Test fixtures are synthetic; browser API/email traffic is intercepted locally. In-memory SQLite tests exercise the real Worker routes and ownership checks, without connecting to D1.

### Original Task 2 local validation results

| Check | Result |
| --- | --- |
| `python scripts/build_site.py` | Passed; static assets generated in the isolated checkout |
| `npm test` in `account-backend` | Passed, 19 test files reported, including the new real-Worker/in-memory-SQLite scope and ownership regressions |
| `python -m unittest discover -s tests` | Passed, 112 tests |
| `node --test site-gate/tests/*.test.mjs` | Passed |
| `node scripts/customer_security_smoke.mjs` | Passed: read-only report DOM, dashboard statuses/tickets, retained notes and drafts, five accordions, scoped customer/environment selection, score/no-score states, refresh-before-export, filtered CSV, stable print capture, expired-session clearing |
| `node scripts/customer_score_smoke.mjs` | Passed; existing model unchanged |
| `node scripts/cvie_client_smoke.mjs` | Passed; existing CVIE client unchanged |
| `node scripts/customer_security_browser_smoke.mjs` | Passed in Chromium at 390, 768, 1024 and 1440 pixels: no page overflow, preserved sidebar/source widget, independent accordions, dashboard save, scoped CSV, generated PDF, intercepted email success and failure, no page errors |
| PDF text extraction | Passed: selected customer/environment, no-score state, recorded status/ticket, report details and timestamp/timezone; no other-scope fixture inventory |
| `node --check` for changed JavaScript and test modules; `git diff --check` | Passed; no dedicated lint command is configured |

Browser test setup used the existing installed Playwright/Chromium tools. To rerun with a custom installation, set `CVEHARBOR_PLAYWRIGHT_MODULE` and `CVEHARBOR_CHROMIUM_PATH`; use `CVEHARBOR_REVIEW_DIR` for screenshots/PDF/CSV results. Defaults write test artifacts under `work/task2-browser/`. All network requests are intercepted, so no local HTTP server or production session is required. The cloud process sandbox required an approved browser execution exception; no production access was requested.

Not validated: real account sessions, production D1 schema activation/data volume, SMTP2GO delivery, or behaviour after integration with the ongoing bug-fix branch. These need an authorized staging/release check. Production data and services were not used. Immutable report storage remains deferred pending explicit architecture approval.

### Changed files

- `customer-dashboard/index.html`: dashboard accordions and existing assessment script.
- `customer-reports/index.html`: header actions, breadcrumb, scoped selectors, CVIE/assessment layout.
- `customer-security.js`: shared findings view, read-only reports, dashboard remediation, print/export and session handling.
- `styles.css`: scoped layout, status/attention badges, responsive tables and print refinements.
- `scripts/customer_security_smoke.mjs`: replaces obsolete expectations that reports contain editors with behaviour/regression coverage and runs the backend isolation regression.
- `scripts/browser_smoke.mjs`: removes the superseded all-Needs-Review-is-red source assertion; severity behaviour is covered in the customer smoke suite.
- `scripts/customer_security_fixture.mjs`: synthetic shared UI fixtures.
- `scripts/customer_security_browser_smoke.mjs`: isolated Chromium regression and export flow.
- `scripts/customer_report_isolation.test.mjs`: real backend route/ownership regression tests using ephemeral SQLite.
- `docs/task2-customer-security-review.md`: starting-state evidence, reuse map, architecture limits, integration and validation record.

Backend runtime/API changes: none. Database/schema/migration changes: none. Dependency, authentication, authorization, scoring, ingestion, scanning, matching, navigation and deployment configuration changes: none.


## Integration review — November 1, 2026

- The user confirmed the table-presence query returned no missing prerequisites, and explicitly deferred immutable report archives. No D1 changes are part of this release. Table presence alone does not establish full column/index compatibility or production end-to-end behaviour.
- Integrated base: `main` commit `8dbaa980829a058ab4bebdc56695b295e688eb0f`, 25 commits beyond the original Task 2 base. It includes the newer .NET/product coverage, scan fencing, D1 expression-depth and real-D1 release-check fixes.
- Integration branch: `codex/task2-customer-security-integration`, in a separate worktree at `/workspace/work/cveharbor-task2-integration`. The original Task 2 branch remains intact.
- Applied the original published Task 2 commit `53e907573a2fefdbeda62936a4ecb973edc3a1d5` without conflicts. Upstream changes had no file overlap with Task 2.
- Integration adjustment: moved the new isolation test from `account-backend/tests/` to `scripts/customer_report_isolation.test.mjs`, and invoke it from the existing `customer_security_smoke.mjs` CI command. The existing Worker workflow watches `account-backend/tests/**` on main and would otherwise run Worker deployment, CVIE migrations, and a CVIE refresh for a test-only change. This adjustment removes that trigger from the net diff. No deployment workflow was modified.
- The current static-site workflow still publishes on qualifying pushes to main. Merging to main must therefore be treated as a deployment action and needs explicit approval. Neither main nor any production resource was changed by this integration review.

- The broad frontend smoke suite contained a legacy source-string assertion requiring every Needs Review finding to be red. Replaced that obsolete expectation with behaviour checks in the customer smoke suite: critical findings are red, high-only findings are amber, medium-only findings are neither, and closing a critical finding removes its red software attention.


### Integrated validation results

All checks below passed on the combined code based on `8dbaa980829a058ab4bebdc56695b295e688eb0f`:

- Static build and `python scripts/verify_production.py --preflight`.
- Backend `npm test`: all 20 existing test files, including the newer CVIE coverage/.NET/D1-query regression tests.
- The relocated real-Worker ownership/isolation test, invoked by `node scripts/customer_security_smoke.mjs`, including cross-account reads/writes and scoped email payload checks.
- Python unittest: 112 tests. Site-gate tests passed.
- Full `scripts/browser_smoke.mjs` and `scripts/threat_health_smoke.mjs` passed; customer, score and CVIE client smoke suites passed.
- Chromium customer report/dashboard: widths 390/768/1024/1440, live status changes, read-only reporting, score availability, independent accordions, CSV, PDF, mocked email success/failure, and no browser errors. Additional integration checks verify the upstream CVIE coverage details stay expanded across refresh in the relocated report widget, the 3/12-month selector works, and the global source backlog is not reused in the customer verification header.
- Unmodified upstream Chromium CVIE coverage, .NET and Hyper-V regressions passed at widths 390/1366/1920/2560 with local/intercepted APIs and in-memory data.
- Extracted PDF contents include the selected customer/environment, no-score assessment, saved status/tickets and generation details, with no other-customer or other-environment fixture inventory.
- JavaScript syntax and `git diff --check` passed. The final diff against the integrated main base has no changes under `account-backend/` or `.github/`, nor to `cvie.js`, `cvie.css`, scoring, matching, or sidebar source.

Ten source/test/documentation files differ from the integrated main base. Integration added no new runtime functionality beyond Task 2; follow-up changes address tests and release isolation. Local screenshots/PDF/CSV verification artifacts are under `work/integration-browser/` and are synthetic. No production email, D1 query/write, migration, scan job, merge to main, or deployment was performed during integration. Real authenticated production/staging checks remain a release step after explicit authorization.

Use **`codex/task2-customer-security-integration`** for review and release, not the original Task 2 branch: the integration branch contains the current fixes and avoids the unrelated Worker deployment trigger. Full report archiving remains explicitly deferred by the user.
