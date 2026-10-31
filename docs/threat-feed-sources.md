# Threat feed integrations

Implemented on `fix/threat-feed-health`. Live access has not been validated and
these changes have not been deployed. No production indicator data was replaced
with test fixtures.

| Source | Category | Collection |
| --- | --- | --- |
| [DShield / Internet Storm Center](https://isc.sans.edu/) | Limited scanning-source list | Existing `feeds.dshield.org/feeds/topips.txt` |
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | Botnet command-and-control IPs | Existing `feodotracker.abuse.ch/downloads/ipblocklist.txt` |
| [ThreatFox](https://threatfox.abuse.ch/api/) | Malware-associated IPv4 addresses and ports | Authenticated POST to `threatfox-api.abuse.ch/api/v1/`; `get_iocs`, `days: 7` |
| [Spamhaus DROP](https://www.spamhaus.org/drop/) | Listed IPv4 network ranges | `www.spamhaus.org/drop/drop_v4.json`, newline-delimited JSON |

The new parsers were validated against representative fixtures. The environment
proxy returned HTTP 403 for upstream requests and documentation; current service
availability, actual response formats, account entitlement and commercial display
or redistribution terms still require confirmation before production activation.
An API key alone does not establish redistribution permission.

## Activation

1. Apply the saved environment configuration draft. Required hosts are
   `feeds.dshield.org`, `feodotracker.abuse.ch`, `threatfox-api.abuse.ch`,
   `threatfox.abuse.ch`, `www.spamhaus.org`, and existing geolocation host
   `ipwho.is`. Production verification needs `cveharbor.com`. GitHub access must
   be restored through the existing repository connection as well.
2. Obtain a ThreatFox key with appropriate service entitlement. Store it securely
   as environment secret `THREATFOX_AUTH_KEY` for local validation, and as the
   repository Actions secret `THREATFOX_AUTH_KEY` for the hourly collector. The
   environment draft declares the secret requirement but does not supply a key
   or synchronize GitHub secrets. Never put the key in chat, source or browser JS.
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

`python3 -m unittest discover -s tests -v` passes 95 tests. Added cases cover both
new formats, observation expiry, duplicate IOC evidence, invalid/private inputs,
missing authentication, authenticated POST construction, key exclusion from
published data, failed-source retention expiry and CIDR export exclusion.

`node scripts/threat_health_smoke.mjs` covers healthy/degraded/stale publications,
unique totals, source filters, pagination, provider evidence, text escaping and
network-range exclusion from map totals. Site DOM smoke and build preflight are
also checked. These checks do not substitute for live upstream validation.
