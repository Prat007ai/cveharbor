# Customer report layout correction

Starting production commit: `8d11b6f886d12c4d5a632bd5013d225c2e90bb9a`.
Isolated branch: `codex/task2-report-layout`, in a new worktree. The starting tracked tree was clean. Generated files and dependencies from earlier work were not overwritten.

The first release retained oversized generic panels and report spacing. This correction follows the supplied mockup: compact header and export icons, customer/environment selectors with the existing history/refresh controls on their right, aligned intelligence/assessment panels, a circular score with real unresolved finding counts, four icon summary cards, compact seven-column findings, software attention, five slim expandable rows, and a single report-details footer.

The existing narrow sidebar and responsive navigation are unchanged. The redundant horizontal brand header is hidden on this report page only. Tables scroll inside their containers on smaller screens; all seven findings columns fit at desktop width. Long software descriptions remain available through titles and the detailed evidence section. Statuses and ticket references remain static badges/text.

CVIE controls are moved with their existing event listeners, not recreated. Presentation observes direct panel redraws so controls survive polling without duplicates. Scan details start collapsed in reports, including during active scans; user expansion, live progress and coverage details persist on subsequent refreshes. No CVIE engine source is changed.

The numeric ring uses the existing assessment value and classification colours. Insufficient Data remains a neutral No Score indicator. Its severity legend explicitly describes unresolved potential matches, not verified vulnerabilities or a new scoring model. All values come from selected-scope records.

## Files

- `customer-reports/index.html`: page scope class, compact header and source-control placement, refreshed asset versions.
- `customer-security.js`: report-only composition, source control placement, score legend and compact cells. Shared dashboard management behaviour is preserved.
- `styles.css`: screen-only report-scoped styling; no sidebar, dashboard or print-style changes.
- `scripts/customer_security_browser_smoke.mjs`: actual browser layout checks, control survival, numeric/no-score and active-scan presentation coverage.
- This review record.

## Validation

- Static build and production preflight passed.
- Customer, score, CVIE client, full DOM/browser and threat-health smoke suites passed.
- Backend test files: 21 passed on the integrated base; isolated ownership/remediation tests passed.
- Python: 112 tests passed. Site-gate tests passed.
- Chromium at 390, 768, 1024 and 1440 pixels: no document overflow; sidebar, selectors, source controls, assessment, five independent report sections and exports present. At 1440 pixels, both top panels align; the seven-column table fits without horizontal scrolling.
- Browser workflows: dashboard status save, read-only report refresh, scoped CSV, generated PDF, intercepted email success/failure, no page errors. Numeric score and insufficient-data views inspected visually. Active scan details remain available and retain user expansion through refresh.
- Extracted PDF includes the customer/environment, actual no-score state, saved remediation status, ticket reference and report details. Other customer/environment fixture assets are absent.
- JavaScript syntax and whitespace checks passed. No dedicated lint command is configured.

All workflow tests use local synthetic data or in-memory databases. No production remediation writes, emails, D1 queries or migrations are used. Real email delivery is not retested. This update adds no API, database, permission, dependency, scoring or matching changes. Immutable report archives remain deferred.

## Integration and release

The starting base includes the earlier deployed Task 2 work and CVIE navigation fixes. Further CVIE read/progress optimizations arrived while this layout was being checked. They touch CVIE, backend, workflow and feed files; none overlap this correction's five files. Rebased without conflicts onto `c84a8983158ce63b50d8a8db32105976cffa1d88`, preserving all eight newer commits. Combined customer, CVIE client/polling, backend, build/preflight and Chromium checks passed. Source cards retain the mockup order even if the API returns a different order; controls and user-expanded scan details survive both full refresh and lightweight progress polling. No unrelated Worker deployment should be triggered by this frontend-only diff. The existing main publication workflow performs the release and live asset verification.
