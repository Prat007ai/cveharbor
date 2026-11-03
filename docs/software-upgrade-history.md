> **Phase 1 deployment notice:** Use [the consolidated administrator checklist](reviews/phase1-administrator-checklist.md) for current release, credential, staging and recovery steps. Deployment/migration/rollback recipes below are feature-history references, not instructions to execute during Phase 1. Feature behavior descriptions remain applicable unless superseded by the current implementation.

# Inventory upgrades and software history

## Starting state and isolation

Started from production commit `f72d4afa9ca10523e3f1f8d1ff8ba00ffd0aac6b` in a clean tracked worktree on `codex/software-upgrade-history`. This includes the deployed report redesign and earlier CVIE read/progress fixes. The previous report worktree and its generated files were left intact.

## Findings and implementation

- The existing matcher already excludes WordPress core and structured CVIE findings when the saved numeric version is clearly outside every supported affected range. No broad CVIE matching or ingestion change is needed.
- Already-open reports/dashboard refreshed remediation but not inventory. They now re-read inventory and recompute findings on focus/visibility return, after an inventory-change notification from another tab, and before PDF/CSV/email preparation. Notifications contain no customer information; the receiving page fetches its own authenticated records. Requests in progress are shared, and session changes prevent late results from restoring private content.
- Generic plugin advisories often say `Autoptimize before ...`, whereas the inventory name is `WordPress Plugin: Autoptimize`. The conservative single-range comparison now recognizes the actual plugin name. Ambiguous/unsupported ranges remain verification candidates; an upgrade does not automatically mark them fixed.
- Saved plugin findings and release/update evidence for an older installed version are excluded from the current assessment and tables. Coverage remains pending until a matching-version check is available. Existing post-edit plugin checks are retained; completing those checks notifies other tabs. Read-only report refreshes do not trigger plugin checks.
- Both pages have an independent, initially collapsed **Software Upgrade History** section, preserving all five existing report sections. It shows product, asset, environment, previous/recorded versions and the server timestamp. It includes downgrades, corrections, unknown-to-known versions and product changes without guessing their meaning.
- Existing remediation statuses, tickets and advisory records are retained. Only the current finding view is recomputed; previously saved PDFs are unchanged. The existing scoring algorithm and authentication/ownership rules are unchanged.

## D1 setup — manual, not executed by this task

In Cloudflare D1, select **cveharbor-accounts → Console** and execute the complete contents of:

`account-backend/software-upgrade-history-schema.sql`

It creates one table (`inventory_software_history`), one scope index and one conditional update trigger (`inventory_software_version_changed`). It does not alter existing inventory values, delete findings, backfill guessed history, or touch CVIE tables. Setup is repeatable with `IF NOT EXISTS`.

The database trigger records a changed version/product in the same transaction as the existing asset update, including existing import/update paths. A failed audit insert rolls back the update. Re-saving identical values or editing only notes produces no history row. Capture starts when this trigger is installed, including edits made by the currently deployed Worker before the new reader is published. Existing deletion semantics are retained: deleting an asset/customer/account cascades to its history. There is no new general-purpose archive or audit-retention policy.

The timestamp means **version change recorded in CVEHarbor**, not independently verified deployment time. Earlier upgrades cannot be reconstructed from current inventory or plugin-check timestamps.

Optional read-only installation check:

```sql
SELECT type, name FROM sqlite_schema
WHERE name IN ('inventory_software_history',
               'idx_inventory_software_history_scope',
               'inventory_software_version_changed');
```

Expected: one table, one index, one trigger. Production setup is verified through a SELECT-only deployment preflight; this task does not execute the setup SQL.

## API and performance

`GET /v1/inventory/software-history?customer_id=...&environment_id=...&before=...` reuses the existing authenticated inventory router. Customer is required; environment and the descending ID cursor are optional. Ownership checks run before history access. An environment must belong to the selected customer. Missing table or trigger yields `ready:false`; UI never pretends an absent audit log is an empty complete history.

Reads fetch at most 101 indexed rows to return 100 plus a next-page cursor. There are no history mutation endpoints. History is cached per selected scope, cleared on inventory refresh/session change, and paginated using **Load older changes**. PDF preparation reads a fresh current inventory and the newest 100 changes; if more exist, the PDF explicitly says so. CSV remains a findings export and respects the selected customer/environment/status filter.

## Validation

- Real inventory Edit → Update asset flow exercised in Chromium using intercepted synthetic WordPress/plugin data. Already-open report and dashboard updated through the cross-tab notification, without reloads or production access.
- WordPress core and plugin out-of-range findings disappear; other still-affected and ambiguous findings remain. Cached old-version plugin findings/release indicators are rejected. Exports independently re-read inventory.
- SQLite executes the actual additive D1 SQL and real inventory route: old/new values and server dates, repeated saves, notes-only edits, downgrade/product changes, setup idempotence, transaction rollback on audit failure, pagination, environment/account isolation, missing trigger/table, no invented past history and cascade deletion all pass.
- Full Worker tests verify authenticated history reads, no foreign customer/environment access, rejected unauthenticated access and no writes from report reads.
- 22 backend test files and 112 Python tests passed. Customer, software-upgrade, score, CVIE client/polling, full browser/DOM and site-gate smoke checks passed. Static build/preflight, syntax and whitespace checks passed; no dedicated lint command is configured.
- Chromium report/dashboard suite passed at 390/768/1024/1440. Upgrade-history browser suite passed at 390/768/1440, including both actual edit forms, responsive tables and PDF output. Extracted PDF includes new versions and both history rows, retains the still-affected CVE, and excludes the two old out-of-range CVEs. Email tests remain intercepted; no real email was sent.

## Deployment and conflicts

D1 setup remains a manual user action. The Worker workflow detects this inventory-only change set and requires a read-only history-schema/reader preflight before deploying code. It skips CVIE migrations, secret changes, cached-evidence resets and collection jobs for this release. Other backend changes and manual runs retain their existing deployment path. A branch workflow checks the same prerequisite before merge. No CVIE engine, scan scheduler or ingestion module is changed. Frontend may show history unavailable until the new read endpoint and D1 setup are present.

Likely shared-file conflicts: `customer-security.js`, inventory frontend/matcher, `account-backend/src/inventory.js` and report HTML/styles. The new schema is a separate named file; existing migrations are untouched. Integration must preserve concurrent CVIE fixes and rerun the upgrade and ownership regressions.

## Changed files

- Runtime: `account-backend/src/inventory.js`, `inventory.js`, `inventory-matching.js`, `customer-security.js`, `index.html`, both customer page HTML files, `styles.css`.
- D1 setup: `account-backend/software-upgrade-history-schema.sql`.
- Tests: `account-backend/tests/inventory-history.test.mjs`, existing customer fixture/smoke/browser and isolation scripts, `scripts/browser_smoke.mjs`, new `scripts/software_upgrade_smoke.mjs` and `scripts/software_upgrade_browser_smoke.mjs`.
- This review and setup guide.
