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
- Health: website monitor check timestamps/errors and last digest submission state only. No provider inbox delivery conclusion or operational success percentage is inferred.

## Shared files and dependencies

Minimal integration edits: account-backend/src/index.js (authenticated GET routing), scripts/build_site.py (CSS/artwork and bounded public advisory projection). These files overlap ongoing lifecycle/backend work; review current main before merge. No edits to ingestion, customer records, schemas, account-page.js, command-center.js, customer-security.js or lifecycle modules. Backend read module and tests are additive. Deploy the compatible read API before or with the workspace frontend after review; UI shows unavailable states on an older API.

Additional capabilities requiring separate approval: active-environment lifecycle, unique asset/monitor linkage, comprehensive audit events, persisted report archives/drafts/scheduling, unified provider-delivery health. No tables, triggers, indexes or background jobs are added here.
