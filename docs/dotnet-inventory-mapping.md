# Microsoft .NET inventory mapping correction

The deployed PowerShell collector exports `.NET Runtime`, but the live backend
only recognizes the older `.NET Core` catalogue label. An unrestricted NVD name
search consequently offered unrelated Borland and BusinessObjects products.

This correction adds exact Microsoft component aliases without enabling the held
product-registry feature or using AI. The supported names are `.NET Runtime`,
`.NET Desktop Runtime`, `.NET Core Runtime`, `ASP.NET Core Runtime`, `.NET SDK`,
`.NET Core SDK` and `.NET Framework`, including explicit Microsoft prefixes.
Bare `.NET`, third-party products mentioning .NET and conflicting vendors are
not automatically resolved. Framework, runtime, ASP.NET Core and SDK identities
remain distinct. The existing broad `.NET Core` catalogue profile is unchanged.

On inventory synchronization or a chooser POST, only unresolved exact aliases
are repaired for the authenticated account and requested subscription scope.
Obsolete directory choices/leases are cleared and source assessment is queued.
Explicit identities, concurrent edits, other accounts, customer records and
installed versions are preserved. Existing inventory does not need reimporting.

## Coverage limits

Mapping identifies a source product family; it does not establish exposure or
complete coverage. `.NET Runtime` maps to modern Microsoft `.net`; the explicitly
named `.NET Core Runtime` maps to the legacy `.net_core` family. The collector
currently uses the generic runtime name for legacy installations too, so legacy
Core inventory needs the explicit legacy identity. Desktop runtime mapping covers
the base .NET family, not every Windows Desktop-specific component. SDK mapping
uses the directory's `.net_core_sdk` family, which has sparse legacy entries;
it must not be treated as complete modern SDK coverage or compared using runtime
versions. Framework still needs Windows servicing/build verification. Unknown or
absent findings are not a clean bill of health.

Public identity verification is recorded in
`data/dotnet-inventory-mapping-evidence.json`. Every family has a non-deprecated
NVD directory entry. Microsoft documents runtimes and SDKs as separate installed
components at https://learn.microsoft.com/en-us/dotnet/core/install/how-to-detect-installed-versions.

## Scoped release and verification

The release reconstructs the serving PR343 package, identity
`0caf38d9c1ea4ed9bbc8c91f71cd8074b69559ae66cb33919d74d607b7519927`,
from commit `86bc0c8f61cb0b4b042b48bef4c8685ac2e738ec` and overlays only
`product-identity.js` and `cvie.js`. Package assembly rejects any extra change.
No website publication, migrations, credentials, permissions, Azure settings or
AI activation are included.

Use the existing protected backend workflow with `team_release=dotnet-mapping`,
`team_commit` equal to the reviewed main commit and `release_mode=code-only`.
The release requires exact-main application/security checks and all three
inventory jobs (collector, workflow and mapping). Pre/post checks require the
expected predecessor/new identity, unchanged Worker bindings, retained recovery
version, protected authentication routes and all organization AI flags paused.

Fictional tests cover new aliases, the screenshot's unrelated candidates, old
saved unresolved rows, repeat refresh, ownership/scope, explicit selections and
concurrent edits. Dashboard matching retains separate 8.0.1/8.0.2 entries and
evaluates a fictional range without inventing a real CVE or fixed version.

After authorized deployment, refresh Northstar Demo PR343's inventory dashboard
and verify `.NET Runtime` has Microsoft identity with no Borland/BusinessObjects
choices. Public source availability may delay assessment. Confirm both saved
versions and the fictional unknown product remain, and verify AI is still paused.
Retain the prior Worker version for recovery; follow the separate recovery
authorization procedure if rollback is required.
