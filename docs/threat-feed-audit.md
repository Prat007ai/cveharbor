# Threat indicator freshness audit

## Evidence available in this environment

The retained Git history contains 281 changes to `threat-data.js`. Comparing the
actual `(IP, source)` pairs, rather than file timestamps, found only two sets:

- 234 snapshots: 20 source reports, from 2026-10-28 13:33 UTC through
  2026-10-31 05:02 UTC.
- 47 snapshots: 22 source reports, from 2026-10-31 05:52 UTC through
  2026-10-31 21:23 UTC. These comprise 17 DShield entries and 5 Feodo entries.

The saved files show recurring publication attempts and successful fetch flags.
They do not independently prove that current upstream responses are fresh.
The environment proxy denied direct requests to both feed URLs and production
with HTTP 403. An attempt to fetch GitHub main also failed because the Git proxy
could not supply authentication. This audit therefore uses retained history;
it does not claim an independently verified current production dataset.

## Scope and defects

DShield `topips.txt` is a limited top-IP feed; Feodo supplies botnet C2 indicators.
Neither is a complete malicious-IP directory. An increasing total is not a valid
success criterion. Source counts, changes, fetch health and publication age must
be inspected separately.

The original collector discarded a failed feed's previous data, returned success
when just one source produced indicators, and exposed no source fetch/change
history or truncation metadata. The publishing workflow ignored threat collector
failure and only checked the separate CVE collector. The browser showed a
collection timestamp without a stale-snapshot warning. Its total did not update
with the selected source/search, and row limits were not explained.

## Local corrections

- Preserve failed-source indicators, marked retained/stale, and preserve their
  last successful fetch. Do not advance failed-source firewall export history.
- Nonzero collector exit for partial/total failure; flag degraded collection after
  publishing the labelled fallback snapshot, so workflows do not silently pass.
- Per-source timestamps, response hash, upstream Last-Modified when supplied,
  added/removed counts and explicit 150-entry source truncation metadata.
- Distinguish IP-set changes from timestamp/body changes. Preserve last-change
  tracking across identical runs; legacy snapshots do not invent a change time.
- Show a warning after three hours without a fresh publication, and show feed
  failures, retained data, narrow coverage and actual filtered/displayed counts.

## Validation and remaining work

89 Python tests pass, including new unchanged-list, same-count/different-IP,
partial failure, total failure and truncation scenarios. Browser tests cover
fresh, failed and aged snapshots, duplicate-IP source reports and filter counts.
Existing site DOM smoke checks and build preflight also pass. No live indicator
files, customer data or firewall configurations were changed by the tests.

Changes remain on `fix/threat-feed-health`, not deployed. Direct upstream and
production comparison remains blocked until the environment network settings
allow `feeds.dshield.org`, `feodotracker.abuse.ch` and `cveharbor.com`. Those domain
additions were saved in the configuration draft, preserving existing domains.
Saving a draft does not apply it. GitHub access also needs to be restored through
the platform's existing repository connection before fetching/publishing updates.
Broader feed coverage is a separate decision; do not inflate counts or silently
add unreviewed sources to make the page appear active.
