# CVIE reliability audit — 1 November 2026

## Release status

The production engine is running. The hardening changes described here are on
`fix/cvie-reliability-audit`; this audit does not deploy them or modify customer
records. The live-source and runtime evidence files below record their own check
times. A green source check means the provider was checked successfully, not that
every vulnerability or every historical original record has been indexed.

## Scope

Reviewed product registration, identity changes, account subscriptions, NVD
directory/history requests, calendar windows, resumable pagination, shared rate
budgets, leases and transactional writes. Also reviewed original CVE ingestion,
CISA KEV reconciliation, record corrections, version matching, browser caches,
account changes, report integration and opt-in alert selection.

## Confirmed weaknesses and fixes

| Area | Previous edge case | Hardened behavior |
| --- | --- | --- |
| Record revisions | An older mirror response could overwrite newer CNA evidence, including a rejection. | Monotonic revisions protect both the canonical record and its affected-product index. A pending newer revision stays queued. |
| Feed revisions | An old change-log or KEV snapshot could move stored evidence backwards. | Regressing publisher timestamps are rejected and last verified evidence is retained. Invalid or future KEV listing dates are also rejected. |
| Product identity | Vendor corrections did not restart unresolved jobs, a conflicting vendor could inherit a known product's CPE, and validated mixed-case CPEs were stored without normalization. | Vendor changes requeue identification and invalidate incompatible cached results. Explicit CPEs are stored canonically. Inventory synchronization preserves explicitly supplied vendor data. |
| Exact product matching | Removing punctuation could conflate two products; a display name could broaden an explicit CPE. | A second structured product-label check preserves punctuation and treats the selected CPE as authoritative. Counts and exclusion rules use the same validated matches. |
| Version uncertainty | Unknown statuses/defaults, custom version schemes or source exceptions could imply a confident result. | Unsupported or uncertain applicability remains a review candidate. Numeric exclusion requires supported source evidence. |
| Severity | Null/blank scores could become zero, contradictory labels could hide a critical score, and enrichment could override an original CNA score. | Missing scores stay unrated, valid NVD primary metrics are preferred within each CVSS version, CNA metrics take precedence over ADP enrichment, and numeric/label conflicts are exposed. |
| Incomplete responses | A malformed NVD entry could advance a window while contributing no results. | Malformed identifiers/dates and records outside the requested window cause a retry; progress is not advanced. |
| Shared queue | A large product history could monopolize the scan queue. | Least-recently-attempted products get turns within the existing recent-history priority. New disclosure revisions reset an older failure's retry budget. |
| Product corrections | An unaffected-product correction could disappear from private results but survive in an older public snapshot. | Account-scoped exclusions travel to the browser and alerts. Reports suppress the affected product's stale lead while retaining other products' evidence for that CVE. |
| Legacy overrides | Old PHP/category exceptions could override newer structured CVIE evidence. | Legacy guards apply to legacy data, preserving current structured product/version evidence. |
| Alert coverage | Large low-priority histories and repeated product associations could consume the digest limit before urgent findings were considered. | Recent eligible evidence is selected and ranked first; CVEs are deduplicated with their product associations before the bounded result limit. Selection is scoped to the account's chosen technologies. |
| Alert revisions | New NVD analysis could be hidden behind an older original CNA publication/update date. | Evidence revision time is retained separately from original publication time and drives alert deduplication/recency. |
| Browser isolation | Late responses, account changes or a failed replacement fetch could retain an earlier account's results. | Immediate cache clearing, request generations and state/page account identifiers reject stale or mixed-session responses. |
| Client recovery | Requests could wait indefinitely, and multi-cursor pagination cycles were not detected. | Supported browsers enforce a request timeout; visited cursors detect cycles while preserving clearly labelled last verified results. |
| Evidence freshness | An original-disclosure outage was visible globally but not on each record. | Individual findings and exported evidence also carry the disclosure verification warning. |

## Verification

- `account-backend/tests/cvie-audit.test.mjs`: 29 targeted regression scenarios.
  The initial 12 scenarios were reproduced failing before their fixes.
  Additional checks cover lease expiry/recovery and 500 paginated advisory
  associations without omissions or cross-account access.
- Existing account, CVIE, digest and security-related backend test files.
- 112 Python data/build tests and the existing site/report/score/threat smoke checks.
- `scripts/cvie_client_smoke.mjs`: deferred-response logout/account races,
  failed page replacement, state/page identity mismatch, pagination cycles and
  product-specific correction propagation.
- Real Chromium CVIE checks: registration, progress, 3/12-month selection,
  reports, expiry, source failure retention, withdrawals, older KEV retention,
  reduced motion and desktop/mobile overflow.
- Real-provider checks use a disposable SQLite account/database, never production
  customer accounts. The product probe covers Apache Tomcat, PHP, WordPress and
  Windows Server 2022.
- Production inspection reads public source metadata and aggregate product-job
  health only. It returns no inventory, product names, customer names, email
  addresses or account findings. The runtime report states whether a successful
  production NVD job has actually been observed.

Evidence:

- [Three-source reconciliation](../data/cvie-provider-check.json)
- [Product-family NVD checks](../data/cvie-product-check.json)
- [Read-only production source health](../data/cvie-runtime-check.json)

## Important limits

1. **Coverage is not universal.** NVD can lag disclosure or product analysis.
   Original CNA ingestion starts at its recorded coverage checkpoint and is not
   a complete twelve-month original-record archive. NVD supplies historical
   product coverage, while the CNA stream adds ongoing disclosures/corrections.
   Initial indexing and individual retry backlogs remain visible.
2. **An advisory match is not confirmed exposure.** Backported packages, custom
   version ordering, architectures and deployment prerequisites require vendor
   or human verification. CVIE does not scan endpoints or mark systems patched.
3. **Source checks and publication times are different.** An unchanged publisher
   release date can be legitimate even when successful checks continue.
4. **Large-scale throughput is not proven by registration tests.** The audit
   exercises 500-product registration and large/duplicate alert histories, but
   does not establish a production freshness SLA for many simultaneous accounts.
   NVD quotas and the Cloudflare plan still constrain queue speed. Before a broad
   public launch, sustained load testing, quota monitoring and shared/incremental
   history caching deserve a separate capacity review.
5. **This is not a formal penetration test.** Account isolation is tested with
   synthetic accounts and real SQL. No real customer's login/MFA session or
   private data was used for the audit.

The supported conclusion is that the observed engine paths are tested and the
identified weaknesses are fixed on the audit branch. No finite review can make
an upstream-data service “bulletproof” or promise it finds every vulnerability.
