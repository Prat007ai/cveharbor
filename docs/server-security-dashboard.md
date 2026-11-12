# Server inventory and security dashboard

The Customer Security Dashboard groups software entries by customer, environment and normalized Asset Name. Collector exports default Asset Name to the computer hostname. A user-supplied AssetName remains a logical asset label; the dashboard does not claim it was verified against a host.

Each server card shows its hostname/asset name, customer, environment, recorded role, software versions and candidate CVEs. Search and role filters affect this server section. Expand the card to view matching evidence and source links. Side-by-side versions remain separate. No-match and limited-assessment states do not imply security. All data uses existing authorized inventory and matching results; there are no new AI or inventory network calls.

The optional collector argument `-ServerRole 'Web'` records explicit metadata at the start of Notes. Supported roles: Web, Database, Application, Active Directory, File, Print, Remote Desktop, Other. Multiple roles use `-ServerRole 'Web','Application'`. Five-column CSV compatibility is retained. Existing WEB, Application and Database asset types are supported as role fallbacks. Other assets without explicit roles show Not recorded. Inconsistent nonempty roles across software entries are flagged. Existing exact import duplicates skip Notes changes; use existing asset editing to correct roles on each software entry.

## Release and verification

Website-only overlay on PR343's verified website: version 7ffba3df-904c-42f3-aa73-3f22456b209a, deployment 2ce36ef1-19a7-49a0-8d28-9a76378adc50, successful run https://github.com/Prat007ai/cveharbor/actions/runs/43134390154. Frozen reconstruction source: efa4c40be1205e3ba99cbc6572c9f565077df2e2. The publisher verifies live predecessor bytes before replacing exactly five assets and adding two, and retains the prior version for recovery.

Backend identity remains ae8e1add427ec56e9950b742a8ada776dee6a79c798ca162cd09cb949e9c6c9a (PR344). No migration, credential, role-grant or AI activation change. Keep AI paused.

Run `node --test scripts/server_security.test.mjs`, `pwsh -NoProfile -File scripts/test_windows_collector.ps1`, and `SERVER_TEST_SITE=<assembled-site> node scripts/server_security_browser.mjs`. Browser checks use fictional accounts at 1440, 768 and 390px and cover personal/organization scoping, identical hostnames in different environments, multiple versions, safe source links, role filters, finding detail context and access revocation. Existing CSV import checks also run against the assembled and served site.

Use Publish reviewed production website with site_release=server-security and reviewed_commit equal to the reviewed main merge. Complete exact-main application/security and inventory checks, then the delegated protected cloudflare-site-production approval. Owner must be eligible, main-only deployment and administrator bypass disabled. The broad PRODUCTION_DEPLOYMENTS_ENABLED switch remains absent/false. Verify served bytes, repeat fictional browser tests and inspect the signed-in dashboard. Record run/version and AI pause verification in the PR.
