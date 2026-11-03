> **Phase 1 deployment notice:** Use [the consolidated administrator checklist](reviews/phase1-administrator-checklist.md) for current release, credential, staging and recovery steps. Deployment/migration/rollback recipes below are feature-history references, not instructions to execute during Phase 1. Feature behavior descriptions remain applicable unless superseded by the current implementation.

# CVEHarbor Vulnerability Intelligence Engine (CVIE)

CVIE registers a product when a signed-in user adds it to the platform explorer,
records it in inventory (including imported assets), or saves it in the account
watchlist. Existing account products are registered on the next authenticated
CVIE sync. It reads public advisory sources; it does not scan customer networks.

See [the reliability audit](cvie-reliability-audit.md) for additional edge-case
tests, hardening changes and remaining coverage/capacity limits.

The explorer's default disclosure period is three calendar months, with an
explicit twelve-month option. Product cards, advisory search, inventory matching,
customer dashboards/reports, and existing opt-in digests consume the shared
results. Existing remediation statuses, tickets and customer records are not
rewritten. Disclosure age is separate from whether an installation remains
vulnerable or a finding has been resolved.

## Scan behavior

### Shared product coverage contract

Every registered product, including additional products outside the public
catalogue, now goes through `product-coverage.js`. The plan identifies its checked
source families, original-disclosure discovery terms, component constraints,
versioned coverage signature and limitations. Provider-specific naming is
reviewed adapter data; history pagination, candidate discovery, retries,
account isolation and completion use the same scanner.

An exact source identity is narrower than a public catalogue topic. The catalogue
review in [cvie-catalogue-coverage.md](cvie-catalogue-coverage.md) explicitly marks
collections such as Linux, Azure and Application dependencies. Selecting one
member does not establish coverage for the whole collection. The interface shows
the selected source identities and an expandable coverage explanation; incomplete
collection coverage and bounded discovery cannot become an unqualified zero
result. The coverage panel retains its expanded state across polling.

For every resolved product the engine checks all configured affected families and
also discovers public CVE IDs using product terms before NVD CPE analysis.
Candidates enter the original-disclosure queue, where structured vendor/product
evidence is required. Original product names with a release suffix are recognized
only when the exact label boundary, vendor identity and source version information
agree. A name prefix alone cannot turn a connector, third-party library or a
different Windows release into a match. Explicit CPE evidence retains precedence.

Each discovery term is bounded to three pages per date window to prevent broad
keywords from overwhelming shared provider/ingestion budgets. Reaching that limit
sets a persistent coverage limitation. Structured affected-CPE history continues
through every page without that truncation. Original-feed coverage timestamps and
pending ingestion remain visible. Counts are verified available matches, not a
claim that every historical disclosure or related product has been covered.

Product-directory lookup now persists its cursor across pages and filters an
explicit vendor. Automatic identity selection requires a complete search and an
exact product-name match; a single unrelated result or one member of a broad
category still needs confirmation. Very broad searches stop with a limitation
and a request to narrow the product rather than pretending the directory was
fully searched. Old completed scans with an older coverage signature requeue
once while keeping their cached evidence and customer data.

Registered products use verified private matches across the explorer, inventory
reports and digests; broad public keyword tags cannot inflate their findings.
Mappings for renames or additional families still require authoritative evidence.
The shared contract supports those mappings but does not invent them or assert
exhaustive coverage for an unknown product.

### Windows Hyper-V

`HyperV`, `Hyper-V`, `Hyper V`, `Windows Hyper-V` and `Microsoft Hyper-V` are
recognized as the Microsoft Windows component. A raw `HyperV` NVD directory
search also returns unrelated HyperView/hypervisor products. Live NVD checks
confirm that current Windows Hyper-V advisories use affected Windows host CPEs,
rather than a separate generic Hyper-V family. The engine therefore asks for the
Windows host (for example, **Microsoft Windows Server 2022 · Hyper-V**).
The current host choices are verified against actual NVD affected configurations
in `data/cvie-hyperv-directory-check.json`; new host families require validation
before adding them to `account-backend/src/hyperv.js`.

History requests combine that host's affected CPE with the `Windows Hyper-V`
component query. NVD normalization independently checks both conditions. Original
CNA disclosures must identify the same Microsoft Windows host and explicitly
name Windows Hyper-V; Windows client `Version` and Server Core labels are
recognized. Unrelated Windows components, Linux guest drivers and third-party
hypervisors do not become Hyper-V matches. CISA still supplies exploitation
evidence by CVE ID. The installed Windows build, features and prerequisites need
review against the linked Microsoft advisory.

Old unresolved Hyper-V choices are repaired when that account opens CVIE; an
invalid earlier selection is returned to host selection and its derived cache
is removed. Valid host selections survive account/inventory sync. Repairs fence
old in-flight responses and preserve inventory, review decisions and tickets.
Shared keyword categories cannot supply additional unverified host matches in
the explorer, inventory reports or opt-in email digests.

`scripts/probe_cvie_hyperv.mjs` verifies host selection, a real 12-month NVD scan,
original Microsoft disclosures and KEV in disposable SQLite. The development
workflow records only public-source evidence and does not deploy. The separate
Chromium smoke script captures the real interface using isolated account
handlers and public advisory samples at 390, 1366, 1920 and 2560 pixels.

### General product scans

The existing **.NET Core** explorer category means modern .NET, ASP.NET Core,
legacy .NET Core and SDKs. NVD's `.net_core` family only covers the older releases
through 3.1. CVIE therefore checks the separately verified Microsoft `.net`,
`asp.net_core`, `.net_core` and `.net_core_sdk` families. All recent family and
disclosure-discovery pages must finish before the three-month NVD history is
marked complete; each of the five date windows covers every work type.

The `.NET` and `ASP.NET Core` NVD keyword queries discover public CVE identifiers
even before NVD has CPE analysis. Keywords never establish a finding. Those IDs
enter the shared original-disclosure queue, where the existing fixed CVE Program
URLs are fetched and Microsoft affected-product labels are checked. Versioned
runtime, SDK and platform-qualified labels remain intact in the displayed source
evidence. Legacy .NET Framework, third-party NuGet applications, Visual Studio
and separate add-on packages are not folded into Core from summary text alone.
Group-level CNA version conditions remain review-only rather than guessed
numeric installed-version exclusions. Existing cached CNA labels work without
reindexing; new ingestion and old rows follow the same affected-label rules.

Old legacy-only `.NET Core` jobs are requeued once on authenticated CVIE access
or their next scheduled scan. The profile marker survives completion in the
cursor metadata. Coverage timestamps reset while saved evidence, customer
inventory, review statuses and tickets remain. The API and interface display the
checked family coverage. A completed zero-match message describes that identity
scope; pending original-disclosure verification is stated separately. Shared
public keyword categories cannot inflate registered Core findings or digests.

The development-only `.NET` verification workflow exercises a real twelve-month
scan and confirms that recent Microsoft disclosures awaiting NVD CPE analysis
are discovered and displayed after original-product verification. Its runtime
diagnosis reads only aggregate status and public CPE identifiers for the reported
`.NET Core` label, without account IDs, inventory or customer records.

- **Queued / scanning:** shown immediately after the product is saved. CVIE
  prepares the most recent three months first, then backfills the remaining
  history. Closing the page does not cancel the durable database job.
- **Product selection required:** names with multiple NVD product identities are
  presented for confirmation. Supplying the vendor or a product-family CPE at
  registration helps identify the intended product. Unmatched names are never
  turned into invented vulnerability matches.
- **Ready:** every source page in all history windows has been processed. Zero
  results are displayed only as a completed source check, never as proof of safety.
- **Retrying:** provider failures/rate limits preserve previous results, retain
  the cursor, and show a retry message. Missing service setup has its own message.

Each product has an accessible NVD history progress bar driven by completed
history windows, with the current window's checked record count when supplied.
Unknown totals use an indeterminate activity indicator. Retry states preserve the
last saved position, pause the animation and show the scheduled retry time.
Completed history has a full bar; disclosure/KEV indexing is tracked separately.
Scan details open for an initial active scan and retain the user's expanded or
collapsed choice across polling. Animations respect reduced-motion settings.

The explorer's four statistic cards are keyboard-operable drill-downs. Their
mini charts show displayed technology groups, original disclosures by day and
the current indexed severity distribution. Hover reveals the underlying counts.
Chart drawing and hover effects animate without changing the numbers; reduced
motion keeps them static. Daily disclosure charts are not attack-activity charts,
and the indexed/critical totals cover the index rather than just the chart period.
Public counts remain limited to the shared index plus available private results.

The product/history cache is private to an account. Database leases, fenced
writes and a shared provider request budget prevent overlapping workers from
advancing the same job or contaminating a corrected product identity. Record
writes and pagination advancement commit together. Responses are paginated, so
the shared site's bounded public index does not truncate these product scans.

An additional five-minute cron processes up to six source pages per tick. Browser
polling can advance a job too, using the same durable rate budget. Completed
products become due for a fresh twelve-month check after six hours. Anonymous
NVD requests are spaced at least 6.5 seconds apart globally; an optional NVD key
uses a one-second interval. HTTP Retry-After is respected, with backoff for
failures. Completion time depends on source availability, result volume and the
queue; no instant-completion claim is made. A source page older than a day is
marked overdue.

Bulk registration and source-page writes use bound JSON sets rather than one
database query per product or CVE. A 500-product import and each 50-record source
page are tested against D1's query budget. The cron batch stays bounded for free
Worker limits as well as paid deployments.

## Sources, freshness and reconciliation

CVIE combines three independently checked sources:

- NVD supplies product/CPE history and severity enrichment.
- The official CVE Program change log supplies original disclosures from vendors and authorized CNAs, including CVEs that do not yet have NVD product analysis.
- CISA KEV supplies independent evidence of known exploitation. A listing is
  evidence of exploitation, not a live measurement of attacks on an account.

A separate minute cron checks due feeds and processes five original records per
invocation. The CVE change feed is due every five minutes and KEV every fifteen.
The worker streams the needed change-log prefix, persists its checkpoint only
after queuing all entries, and processes product-relevant KEV records and recent
changes before unrelated historical records. The first direct-disclosure sync
starts with the previous 24 hours; it is not a complete CNA historical archive.
Initial backfill can take time, and its backlog remains visible.

The source panel shows last successful checks, publisher timestamps, incomplete
indexing, rate limits and outages separately. Source failures preserve last good
records and timestamps. Retry-After and retry backoff are enforced. API errors,
malformed/truncated feeds and unexpected catalogue reductions never become green
success or zero-vulnerability claims. Original-record URLs are constructed from
validated CVE IDs; URLs embedded in feeds are not fetched.

Records merge by CVE ID with provenance. The original CNA description/version
evidence takes precedence where available, NVD can supply missing severity, and
score disagreements are explicit. Authoritative withdrawals suppress stale NVD
and public-snapshot rows. Explicit CNA unaffected-product corrections suppress
stale product matches. Known-exploited CVEs remain visible outside the selected
3/12-month history, retaining their original publication date. KEV dateAdded is a
separate field and can trigger a new opt-in alert without inventing CVSS severity.
Reports and CSV exports retain evidence status and source check times.

## Matching and coverage

The historical adapter uses NVD's CVE API and CPE directory. It uses
the affected-product CPE, not a summary substring. Rejected CVEs, negated
configurations and unrelated product mentions do not become matches. CVIE keeps
original publication dates, summaries, CVSS scores, vendor references and structured
version bounds. Original CNA records and the independent KEV catalogue enrich
that history. Existing public/vendor feeds remain available alongside it.

**Coverage combines NVD history with continuously ingested original CNA records
and KEV evidence.** NVD may lag disclosure, the CNA stream begins at its displayed
coverage checkpoint, and some products lack usable structured identifiers. CNA
matching requires an affected-product CPE or a precise vendor/product match.
CNA records are vendor/assigner-authored disclosures; CVIE does not scrape every
vendor website. A successful check does not promise exhaustive vendor coverage.
Broad labels such as “Linux” or “.NET” can require a more specific product.

Numeric version-range comparisons are preliminary review matches. Non-numeric
versions, distribution backports and complex configuration prerequisites require
vendor verification. The engine does not infer confirmed exposure, perform an
endpoint scan, mark issues patched, or initiate blocking actions.

Known brand titles, CPE product names and vendors are matched against 3,459
registered Simple Icons brand identifiers (version 16.36.0; CC0 notice in
[simple-icons-license.md](simple-icons-license.md)). Existing local Microsoft
artwork is retained. Missing/failed logos use a neutral initial badge. No
arbitrary customer URLs, favicon discovery or image HTML are accepted.

## Deployment preparation

This feature is developed on `feat/cvie-product-intelligence`. Its verification
workflow performs a real NVD backfill in a disposable SQLite database and writes
only public provider evidence to `data/cvie-provider-check.json`. It does not
deploy or mutate production.

For an approved release, the backend deployment workflow applies only
`account-backend/migrations/0019_cvie.sql` and the additive
`account-backend/migrations/0020_cvie_evidence.sql` before deploying the Worker. The
migration adds CVIE tables/indexes and an initial request-budget row; it does not
reapply the original account schema or modify inventory. Missing tables fail
closed with a service-setup message. Existing `NVD_API_KEY`, if configured in
GitHub, is copied over stdin to an encrypted Worker secret; otherwise anonymous
NVD access works with the lower request budget.

After the corrected Worker is deployed, the guarded
`account-backend/migrations/0021_cvie_audit_refresh.sql` applies the new
applicability rules to cached affected-product rows, queues canonical records
for re-normalization and restarts resolved NVD jobs without deleting their last
verified advisories. It does not alter inventory, review statuses or tickets.
The maintenance marker makes subsequent deployments leave completed work alone.

After deployment, `scripts/verify_cvie_production.py` checks API health,
unauthenticated CVIE rejection, the nine CVIE tables and actual scheduled
disclosure/KEV ingestion. It reads schema and public feed metadata only. It allows
time for new Cloudflare cron schedules to propagate; successful deployment is
reported separately from a feed that has not yet passed its live checks.

Limits: 50 additional catalogue entries and 500 distinct actively monitored
products per account. Removing a product stops its job once no inventory,
catalogue or watchlist subscription remains. Removing an account cascades to its
CVIE results. NVD receives configured software product/vendor query strings.
Customer hostnames, account identifiers and installed versions are not included
in those queries. Original CVE lookups use public CVE IDs only.

## Verification

```sh
cd account-backend && npm test
cd ..
python3 -m unittest discover -s tests
python3 scripts/build_site.py
python3 scripts/verify_production.py --preflight
node scripts/browser_smoke.mjs
node scripts/customer_security_smoke.mjs
node scripts/customer_score_smoke.mjs
node scripts/threat_health_smoke.mjs
node scripts/cvie_client_smoke.mjs
```

Real Chromium review, after installing Playwright and starting a local server
for `public/` on port 8080:

```sh
node scripts/cvie_browser_smoke.mjs
node scripts/explorer_cards_browser_smoke.mjs
```

`CVIE_PLAYWRIGHT_MODULE`, `CVIE_CHROMIUM_PATH`, `CVIE_ICON_DIRECTORY` and
`CVIE_SCREENSHOTS` can point to local tools/assets/output. Browser account and
scan-state responses are isolated fixtures; advisory content comes from the
verified live NVD scan. Screenshots explicitly identify that distinction.
