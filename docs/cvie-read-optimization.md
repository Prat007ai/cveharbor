# CVIE read reduction

Routine visible-page polling uses `/v1/cvie/progress` every 30 seconds while
product jobs are active, and every 60 seconds otherwise. The private endpoint
checks readiness and loads only the signed-in account's subscribed product jobs.
It does not compute advisory counts, reconcile source records or page through
findings. Authentication remains mandatory and responses remain `no-store`.

The browser loads a full snapshot initially, on an explicit refresh, when a
product identity or saved scan result changes, or after 60 seconds without a
successful full result refresh. This time bound also catches original-source
corrections that do not change a product's NVD scan timestamp. Returning to a
visible tab checks progress; hidden tabs stop automatic polling. Late and
revoked-session responses retain the existing account isolation checks.

Public CVE Program/CISA source metadata and queue aggregates share a 30-second
in-memory cache per database binding in each Worker isolate. Concurrent misses
share one promise, failures are retried, and callers receive independent copies.
Local source ingestion invalidates this cache. Other isolates expire their own
entries within 30 seconds. Account-specific NVD status is appended afterwards;
private products, assets and findings are never put in this shared cache.

For 100 continuously visible, actively scanning clients, the polling interval
reduces the nominal rate from 45,000 to 12,000 cycles per hour, before accounting
for request duration. When progress is unchanged, full snapshots reload about
once per minute instead of every eight seconds. These are request estimates,
not a measured billing reduction. Cold Worker instances and authentication still
read D1. D1 bills rows scanned/written, not the number of SQL statements.

Tests cover 100 warm progress requests (two D1 statements each, excluding the
authentication middleware), concurrent public-cache misses, expiration,
invalidation, failed loads, account changes, hidden tabs, source corrections and
session revocation. The production D1 verifier also records per-stage row metrics
using synthetic identities and public evidence, without reading customer rows.

NVD history jobs and cached NVD results are still account-specific. Sharing scans
by verified public product identity and using incremental source updates are
separate architectural improvements; this change does not claim to implement
either. Customers' inventory, installed versions and review decisions must remain
account-private in any subsequent shared-product design.
