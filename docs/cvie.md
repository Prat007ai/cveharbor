# CVEHarbor Vulnerability Intelligence Engine (CVIE)

CVIE registers a product when a signed-in user adds it to the platform explorer,
records it in inventory (including imported assets), or saves it in the account
watchlist. Existing account products are registered on the next authenticated
CVIE sync. It reads public advisory sources; it does not scan customer networks.

The explorer's default disclosure period is three calendar months, with an
explicit twelve-month option. Product cards, advisory search, inventory matching,
customer dashboards/reports, and existing opt-in digests consume the shared
results. Existing remediation statuses, tickets and customer records are not
rewritten. Disclosure age is separate from whether an installation remains
vulnerable or a finding has been resolved.

## Scan behavior

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

## Matching and coverage

The current product-history adapter is NVD's CVE API and CPE directory. It uses
the affected-product CPE, not a summary substring. Rejected CVEs, negated
configurations and unrelated product mentions do not become matches. CVIE keeps
original publication dates, summaries, CVSS scores, vendor references, structured
version bounds and NVD's CISA KEV attribution. Existing public/vendor feeds remain
available alongside it.

**Coverage means NVD records with affected-product CPE metadata.** New CVEs can
appear before NVD assigns product configurations, and the directory may not cover
every product. A successful scan is not a claim of exhaustive vendor coverage.
Broader vendor/CNA adapters can be added behind this same job/status interface.
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

For a later approved release, the backend deployment workflow applies only
`account-backend/migrations/0019_cvie.sql` before deploying the Worker. The
migration adds CVIE tables/indexes and an initial request-budget row; it does not
reapply the original account schema or modify inventory. Missing tables fail
closed with a service-setup message. Existing `NVD_API_KEY`, if configured in
GitHub, is copied over stdin to an encrypted Worker secret; otherwise anonymous
NVD access works with the lower request budget.

Limits: 50 additional catalogue entries and 500 distinct actively monitored
products per account. Removing a product stops its job once no inventory,
catalogue or watchlist subscription remains. Removing an account cascades to its
CVIE results. No customer assets or usernames are sent to NVD.

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
```

Real Chromium review, after installing Playwright and starting a local server
for `public/` on port 8080:

```sh
node scripts/cvie_browser_smoke.mjs
```

`CVIE_PLAYWRIGHT_MODULE`, `CVIE_CHROMIUM_PATH`, `CVIE_ICON_DIRECTORY` and
`CVIE_SCREENSHOTS` can point to local tools/assets/output. Browser account and
scan-state responses are isolated fixtures; advisory content comes from the
verified live NVD scan. Screenshots explicitly identify that distinction.
