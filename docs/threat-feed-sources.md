# Threat feed integrations

Implemented on `fix/threat-feed-health` and released through the production
GitHub Actions workflow. No production indicator data was replaced with test
fixtures. Live collection and production verification run in GitHub Actions;
this cloud session still has separate network and secret restrictions.

The blocklist.de/GreenSnow expansion and complete current-list downloads are on
`feat/expanded-attack-feeds`, pending production review.

| Source | Category | Collection |
| --- | --- | --- |
| [DShield / Internet Storm Center](https://isc.sans.edu/) | Limited scanning-source list | Existing `feeds.dshield.org/feeds/topips.txt` |
| [blocklist.de](https://www.blocklist.de/en/export.html) | Reported server attacks and brute-force activity | `lists.blocklist.de/lists/all.txt` |
| [GreenSnow](https://greensnow.co/) | Reported scanning and attack activity | `blocklist.greensnow.co/greensnow.txt` |
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | Botnet command-and-control IPs | Existing `feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| [ThreatFox](https://threatfox.abuse.ch/api/) | Malware-associated IPv4 addresses and ports | Authenticated POST to `threatfox-api.abuse.ch/api/v1/`; `get_iocs`, `days: 7` |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Listed IPv4 network ranges | `www.spamhaus.org/drop/drop_v4.json`, newline-delimited JSON |

The initial fixture checks were followed by live collection in GitHub Actions.
Live checks exposed a response larger than 4 MB and the provider's
multiple observation timestamp representations; the collector now allows a
bounded 32 MB ThreatFox response and supports UTC date strings and Unix times. A missing timestamp schema must
not silently turn IP reports into an empty healthy feed. Provider access does
not independently establish commercial redistribution permission.

## Activation

1. For direct validation in this cloud session, apply the saved environment
   configuration draft. Production GitHub Actions does not depend on that draft.
   Required hosts for this session are
   `feeds.dshield.org`, `feodotracker.abuse.ch`, `threatfox-api.abuse.ch`,
   `threatfox.abuse.ch`, `www.spamhaus.org`, and existing geolocation host
   `ipwho.is`. Production verification needs `cveharbor.com`. GitHub access must
   use the existing repository connection; REST API access is separately blocked
   in the current local network policy.
2. The repository already has `MALWAREBAZAAR_API_KEY`, confirmed by the owner's
   GitHub settings screenshot. The hourly collector uses the dedicated repository
   secret `THREATFOX_AUTH_KEY` when configured, otherwise it tries that existing
   abuse.ch key. No new key or duplicated GitHub secret is required just to try
   the integration. Successful ThreatFox authorization must still be verified;
   the secret's name or existence does not establish service entitlement. A
   dedicated ThreatFox key remains available if needed. For local validation,
   securely bind the appropriate key as environment secret `THREATFOX_AUTH_KEY`.
   The environment draft declares that requirement but does not supply a key or
   synchronize GitHub secrets. Never put the key in chat, source or browser JS.
3. Validate real responses into a temporary directory before changing published
   data. Confirm upstream terms for CVEHarbor's commercial use and public output.
4. Review the branch against current main, then publish code through the normal
   deployment workflow once access and live validation are resolved.

The existing hourly schedule is retained. A missing key or failed source produces
a labelled partial snapshot and a failed health check, rather than silent success.
The workflow publishes available/retained data before reporting degraded health.

## Data behavior

- IPs and CIDR ranges have separate totals. Spamhaus ranges are never expanded
  into hosts, placed on the host map, or included in individual-IP firewall exports.
- ThreatFox details retain malware family, source confidence, port, IOC ID,
  provider first/last observation when supplied, and a source reference. Multiple
  observations share one IP report, with up to ten evidence records per IP.
- The ThreatFox request covers seven days. Observations older than 30 days or
  more than five minutes in the future are rejected. Its retained reports also
  expire 30 days after the source observation. This is an application expiry rule,
  not a claim about the provider's full retention policy.
- A failed source's last successful data is retained for at most 72 hours, visibly
  marked stale. A publication older than three hours shows a stale warning.
- Each source publishes at most 500 entries. Total parsed count and truncation
  are visible. Reports are grouped into attack/scanning sources (DShield, blocklist.de and GreenSnow),
  malware-associated IPs (Feodo and ThreatFox), and network ranges (Spamhaus).
  Groups start collapsed and open one at a time. An open group initially shows
  30 source reports with a Show more button.
- Activity, feed and IP search filters apply to both the list and map. Choosing
  an activity clears incompatible feed filters; explicit filters or a search open
  the matching group. Network ranges remain excluded from the host map.
- Geolocation performs at most 20 new lookups per run with five-second timeouts,
  reusing existing cached locations. Unlocated reports remain in the list.
- Existing firewall files are cumulative historical review templates, not a
  current automatic blocklist. Failed sources do not advance their export history.
- Coverage is IPv4 only. Counts are not a measure of all malicious infrastructure
  or proof of attacks against an organization. No automatic blocking is added.

## Local validation

`python3 -m unittest discover -s tests -v` passes 104 tests. Added cases cover both
new formats, observation expiry, duplicate IOC evidence, invalid/private inputs,
missing authentication, authenticated POST construction, key exclusion from
published data, failed-source retention expiry, CIDR export exclusion, larger
weekly responses, UTC timestamp fields and Unix observation times.

`node scripts/threat_health_smoke.mjs` covers healthy/degraded/stale publications,
unique totals, source filters, pagination, provider evidence, text escaping and
network-range exclusion from map totals. Site DOM smoke and build preflight are
also checked. Production verification checks the threats route, its frontend
scripts and the exact published indicator snapshot against the release artifact.

Native accordion and responsive layout checks are in
`scripts/threat_activity_visual_smoke.cjs`. With a local server running, set
`CVEHARBOR_PLAYWRIGHT_MODULE` and `CVEHARBOR_CHROMIUM` if Playwright/Chromium are
installed outside the repository, and optionally `CVEHARBOR_SCREENSHOTS` for
review artifacts. The script checks keyboard expansion, exclusive groups, lazy
rendering, filters, pagination focus, map synchronization and overflow at widths
1366, 1920, 2560 and 390. Its screenshots show the local UI using the committed
public dataset; external requests are blocked and no account writes are sent.


## Complete current attack/scanning downloads

The page preview remains capped at 500 entries per feed. Current attack/scanning
exports include **all** accepted public IPv4 addresses from successfully fetched
DShield, blocklist.de and GreenSnow lists, deduplicated across those sources:

- `attack-scanning-current.txt`: plain IPv4 addresses, one per line.
- `attack-scanning-current.csv`: IP addresses with all reporting source names.
- `attack-scanning-current.json`: generation time, source coverage, count and TXT
  checksum. Collection timestamps are not attacker last-seen observations.

These files are replaced by each current successful collection, separately from
existing cumulative FortiGate/Sophos history. Failed-source retained indicators,
malware reports, network ranges and private/reserved addresses are excluded.
Partial source coverage is labelled. The UI pauses downloads when the snapshot
or export is older than three hours; an empty export is unavailable.

No firewall connection, automatic blocking, rule activation or policy replacement
is added. Customers can review the current list against their logs and allowlists
before using their firewall's supported IP-list import/update process.

`scripts/validate_attack_feeds.py` tests the actual public feeds and exports into
`data/attack-feed-validation/`, without production writes or API keys. The
`Validate public attack feed integrations` development workflow runs this check
and commits its evidence to the development branch; it never writes main. The
report records the code revision that was validated. Generated validation files
are not copied into the public website. Direct local validation needs network
access to `lists.blocklist.de` and `blocklist.greensnow.co` as well as DShield.


The development live validation run succeeded:
https://github.com/Prat007ai/cveharbor/actions/runs/41251261529
It validated 17 DShield, 25,275 blocklist.de and 3,187 GreenSnow IPv4 records,
producing 26,417 unique current export IPs. The limited preview contains 1,009
unique attack IPs across 1,017 source reports. These are snapshot counts, not
fixed totals or evidence of attacks on a particular customer.

For a local six-feed UI preview, set `CVEHARBOR_ATTACK_VALIDATION_REPORT` to the
absolute `data/attack-feed-validation/report.json` path when running the native
browser test. It combines the validated attack data with the committed malware
and network-range snapshot for local testing only, copies the actual validated
exports into generated `public/`, and verifies TXT/CSV downloads byte for byte.
No synthetic IP records or customer data are used in that preview.
