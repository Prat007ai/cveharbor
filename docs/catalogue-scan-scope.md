# Technology catalogue and scan scope fix

## Starting state and overlap

Isolated branch `codex/catalogue-scan-scope` starts from clean production commit `9d1c434f0f8211389cb521c286281ae4567019d7`. It includes #217 software history, #219 customer CVE dialogs, #218 shared CVIE scans, and #220 shared-source/status clarification. Existing worktrees were left intact. Open PRs #92/#93 concern public advisory coverage, not this catalogue implementation. Unpublished changes in other sessions are not visible; shared-file overlap remains possible in app.js, cvie.js, account-backend/src/cvie.js, shared-scopes.js, cvie-records.js, index.js and the deployment workflow.

## Confirmed root causes

1. `index.js` catalogue PUT persisted both `defaults` and `products` but passed only `products` to `subscribeProducts`. `syncAccountProducts` repeated that omission. Built-in checkboxes therefore did not control registered catalogue scans.
2. `app.js::renderCategories` appended every CVIE product absent from the built-in taxonomy to the custom-product list. Those registrations included customer inventory and the independent watchlist, so unchecked technologies reappeared.
3. CVIE status/progress/advisory APIs returned the union of catalogue, inventory and stack subscriptions. The explorer presented this account-wide count as its product scan scope.
4. Catalogue PUT wrote on every save, lacked a revision check, and could race with delayed synchronization. Frontend save applied the mutable draft after its request completed, and stale status responses could outlive the saved selection.
5. Previous unsubscription deleted orphan product rows (and cascaded private historical evidence). The fix retains history while removing subscriptions and invalidating obsolete private leases.

Screenshots establish visible mismatch but cannot establish that all 56 products were unneeded scans. Inventory/watchlist registrations and shared jobs must be distinguished from catalogue jobs. The SELECT-only production diagnostic reports aggregate subscription counts without account identities; no retrospective daily-write attribution is claimed.

## Implementation

- The exact selected built-ins plus enabled custom products become catalogue subscriptions. Custom products have an explicit monitoring checkbox. Empty saved catalogues stay empty.
- Saved preferences remain in `user_technology_catalogue.preferences_json`; normalized `selection_keys` are included inside that existing JSON. Legacy JSON remains readable. No schema change.
- A SHA-256 revision of the saved JSON detects stale edits. Conditional writes reject races. Identical saves do not write or start work. Conditional synchronization prevents an older preference snapshot from restoring removed jobs or removing a newer selection.
- `catalogue-selection.js::activeSubscription` checks the current saved selection in backend queries and scheduling. `ownedProductSql`, `evidenceContext` and status/advisory routes accept catalogue/inventory/stack scope. Server-side ownership remains required.
- `runCvieStep` accepts scope for save/sync-triggered work. Background scheduling still uses all legitimately active origins/accounts. Catalogue removal does not change inventory, watchlist, remediation or another user's preferences.
- Removed catalogue subscriptions disappear immediately; obsolete private work loses its lease/commit token. Active private requests recheck selection before processing a response. A shared source request already running may finish its current page; no subsequent page is scheduled without a valid subscriber. Shared history and private cached evidence are retained.
- Existing shared scope identity keys, source-request budget and leases continue deduplicating jobs. Retained products preserve cursors/status. Source ingestion, source verification, affected-version matching and scoring algorithms are unchanged.
- Explorer panels/filter options/results/counts use the saved selection. Immediate client invalidation discards pre-save status responses. Reload, account events, focus and cross-tab change notifications reload saved preferences; drafts are submitted as an immutable snapshot. Failed saves retain the previous successfully saved display.
- NVD describes scoped product history, potentially backed by a shared scan. CISA/CVE Program retain explicitly shared queue labels. Catalogue counts distinguish queued/checking, complete history, review-required and failed/retrying. Completion never implies an installation is secure.

## D1 efficiency

Identical catalogue saves perform zero writes (tested with SQLite `total_changes()`). Subscription changes use set-based JSON bindings and only add/remove differences. Catalogue sync does not query inventory/stack; inventory sync does not read catalogue preferences. Polling uses scoped reads and existing lightweight progress refreshes. Removed products cannot be requeued by stale catalogue subscriptions. Existing shared scans avoid separate source jobs for multiple subscribers. The fix does not change unrelated public ingestion writes or reduce intelligence completeness.

## Validation

- 24 backend test files, including actual authenticated catalogue GET/PUT and SQLite query execution, pass. New tests cover two built-ins, explicitly disabled custom products, reload, no-op writes, revision conflicts, adding, empty selection, stale synchronization, user separation, inventory/watchlist independence, private in-flight invalidation and shared work retained for another account.
- Real app.js + cvie.js + account/CVIE handlers against SQLite pass exact selection, failure, pending saves, refresh, sign-out/sign-in, adding and empty catalogue scenarios. Existing CVIE client/polling race tests pass.
- Chromium uses intercepted requests routed to the actual handlers with synthetic data. Two selected technologies appear in both category panels and scan rows; reload, removal, addition, failed save and empty catalogue pass. Screenshots checked at 390/768/1440px.
- Existing customer Chromium regressions pass: responsive layout/sidebar, scoped findings, status saves, CSV, PDF and mocked email. Existing customer/upgrade/CVE-dialog/isolation tests pass.
- 112 Python tests, explorer DOM tests, static build/preflight, syntax, workflow YAML and whitespace checks pass. No separate lint command is configured.
- Production checks are SELECT-only: schema-compatible scoped handlers for a nonexistent synthetic account and aggregate counts; no customer identities or finding content are logged. No production test saves, emails, bulk rescans or migrations.

## Release and limitations

The final user instruction authorizes production publication after validation. A narrow catalogue-only release mode deploys Worker code with SELECT-only pre/post checks. It skips migrations, shared-history bootstrap, NVD secret changes and evidence-cache resets. Frontend publication verifies the versioned deployed assets. Existing shared-scan setup is reused; no D1 action is required.

An already-issued shared HTTP request cannot be reliably interrupted across Worker isolates. Its current public page may complete; the next scheduling decision checks active subscribers. Inventory/watchlist or other-account monitoring can legitimately continue after a personal catalogue removal. Unresolved product identities still require the user's exact-product choice. No claim of reduced production daily writes is made without measurement.

## Files

Backend: `catalogue-selection.js`, `cvie.js`, `cvie-records.js`, `shared-scopes.js`, `index.js` under account-backend/src; `account-backend/tests/catalogue-scope.test.mjs`.
Frontend: `app.js`, `cvie.js`, `index.html`, customer-dashboard/index.html and customer-reports/index.html (CVIE cache version only).
Validation/release: scripts/catalogue_scope_smoke.mjs, scripts/catalogue_scope_browser_smoke.mjs, scripts/verify_catalogue_scope_d1.mjs, scripts/browser_smoke.mjs, scripts/customer_security_smoke.mjs, scripts/worker_release_mode.mjs, scripts/worker_release_smoke.mjs, .github/workflows/verify-catalogue-scope.yml, .github/workflows/deploy-worker-code.yml, and this report.
