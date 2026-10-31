# Threat feed integrations

Implemented on `fix/threat-feed-health` and released through the production
GitHub Actions workflow. No production indicator data was replaced with test
fixtures. Live collection and production verification run in GitHub Actions;
this cloud session still has separate network and secret restrictions.

| Source | Category | Collection |
| --- | --- | --- |
| [DShield / Internet Storm Center](https://isc.sans.edu/) | Limited scanning-source list | Existing `feeds.dshield.org/feeds/topips.txt` |
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | Botnet command-and-control IPs | Existing `feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| [ThreatFox](https://threatfox.abuse.ch/api/) | Malware-associated IPv4 addresses and ports | Authenticated POST to `threatfox-api.abuse.ch/api/v1/`; `get_iocs`, `days: 7` |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Listed IPv4 network ranges | `www.spamhaus.org/drop/drop_v4.json`, newline-delimited JSON |

The initial fixture checks were followed by live collection in GitHub Actions.
Live checks exposed a response larger than 4 MB and the provider's
`first_seen_utc` / `last_seen_utc` field names; the collector now allows a bounded
32 MB ThreatFox response and reads those fields. A missing timestamp schema must
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
  are visible; the page initially renders 150 reports with a Show more button.
- Geolocation performs at most 20 new lookups per run with five-second timeouts,
  reusing existing cached locations. Unlocated reports remain in the list.
- Existing firewall files are cumulative historical review templates, not a
  current automatic blocklist. Failed sources do not advance their export history.
- Coverage is IPv4 only. Counts are not a measure of all malicious infrastructure
  or proof of attacks against an organization. No automatic blocking is added.

## Local validation

`python3 -m unittest discover -s tests -v` passes 98 tests. Added cases cover both
new formats, observation expiry, duplicate IOC evidence, invalid/private inputs,
missing authentication, authenticated POST construction, key exclusion from
published data, failed-source retention expiry, CIDR export exclusion, larger
weekly responses and the provider's UTC timestamp fields.

`node scripts/threat_health_smoke.mjs` covers healthy/degraded/stale publications,
unique totals, source filters, pagination, provider evidence, text escaping and
network-range exclusion from map totals. Site DOM smoke and build preflight are
also checked. Production verification checks the threats route, its frontend
scripts and the exact published indicator snapshot against the release artifact.
