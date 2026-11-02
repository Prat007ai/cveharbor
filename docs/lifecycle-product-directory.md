# End of Support & Patch Watch product directory

The product picker includes 86 common families across Microsoft development tools,
Linux, Java, JavaScript, Python, PHP, databases and infrastructure. Aliases and
bounded edit-distance suggestions are searched locally. A suggestion must be
selected; a spelling similarity never establishes an identity or support date.
The compact curated data is shipped with the website and Worker, not inserted
into D1. Some listed tools do not have published lifecycle data in the source.

Authenticated customers can look up an unlisted official product name, select a
source-returned release branch, and save their installed version privately in the
existing lifecycle_watches table. A failed lookup still permits an unresolved
private watch without a fabricated source URL or support date. Saved unresolved
watches can be resolved later with explicit product/branch confirmation.

The directory queries fixed endoflife.date endpoints, with response-size and
timeout limits and no redirects. It never fetches customer-supplied URLs or sends
installed versions. endoflife.date is community-maintained; its dates are labeled
accordingly and are not evidence of a customer's support entitlement or an
installed security fix. Microsoft .NET SDK, MAUI, EF, legacy components and other
frameworks remain selectable when this source has no data; absence stays unknown.

Public lookup results use Cloudflare Cache API, shared within a Cloudflare cache
location, with 500 deterministic slots plus one compact index. Hash collisions
replace a cached public product, never customer data. Each slot holds at most 40
release branches / 24 KB. Fresh results are reused for 24 hours; cached results
may remain for seven days and are marked stale if a refresh fails. Cache eviction
or a different cache location can require another source lookup. It is not a
durable complete directory. Failed names are not cached or promoted. The
existing public source snapshot supplies the broader published product directory.

D1 stores private watches and a single independent lifecycle-directory provider
budget row in cvie_provider_budget; the NVD budget is untouched. No new schema,
bulk product/version import, migration, configuration, email consent, or campaign
activation is required. The legacy production lifecycle API supports the complete
picker/save/resolve flow. Enhanced monitoring code can reuse verified branches
if its separately controlled schema and scheduling are enabled; this release does
not enable them. Existing official adapters remain separate from community data.

Validation includes SQLite tests for both schemas, cache limits, failed lookups,
private versions, ownership, and absent dates. Chromium uses actual legacy
Worker handlers with synthetic local accounts to test typo suggestions, branch
selection, saves/reload, unresolved saves, later resolution and responsive layouts.
Live source probes perform public reads only. Deployment uses the monitoring
code-only path and verifies that schema, secrets, flags, sender and schedules
remain unchanged.
