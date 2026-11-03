# Workflow source inventory — 2026-11-03

Scope: all 263 current branch heads; 146 unique workflow file versions across 38 paths. No branch heads were changed during collection. Main was `147d2671d993e6297205cb5816aca53969cc71b7`. Counts describe the baseline before this security PR.

“Ungated” means a source reference to Cloudflare, site-access or SMTP credentials without a job environment. It does not establish that credentials exist or have production permissions. A workflow appearing on a branch does not mean its push trigger matches that branch. Historical runs/deleted branches remain a separate credential-cutover consideration.

| Workflow | Distinct versions | Branch heads containing it | Referenced environments | Credential references without environment |
| --- | ---: | ---: | --- | --- |
| activate-confirmation-domain.yml | 2 | 15 | cloudflare-worker-production | None |
| activate-customer-score.yml | 2 | 180 | cloudflare-worker-production | None |
| activate-finding-tickets.yml | 2 | 196 | cloudflare-worker-production | None |
| activate-immutable-tickets.yml | 2 | 188 | cloudflare-worker-production | None |
| activate-plugin-installation-status.yml | 2 | 187 | cloudflare-worker-production | None |
| activate-plugin-monitor.yml | 4 | 198 | cloudflare-worker-production | None |
| activate-plugin-sources.yml | 2 | 189 | cloudflare-worker-production | None |
| audit-remediation-integrity.yml | 1 | 1 | cloudflare-worker-production | None |
| bootstrap.yml | 44 | 263 | cloudflare-site-production, github-pages | None |
| check-cvie-runtime.yml | 2 | 47 | cloudflare-worker-production | None |
| check-site-gate-hosting.yml | 2 | 49 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, CLOUDFLARE_SITE_API_TOKEN, SITE_GATE_PASSWORD |
| cvie-phase012.yml | 1 | 1 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN |
| cvie-staging-diagnostics.yml | 1 | 1 | cloudflare-cvie-staging-readonly | None |
| cvie-staging.yml | 1 | 1 | cloudflare-cvie-staging | None |
| deploy-account-worker.yml | 5 | 224 | cloudflare-worker-production | None |
| deploy-worker-code.yml | 23 | 199 | cloudflare-worker-production | None |
| diagnose-linux-cve.yml | 1 | 1 | None | None |
| recovery-write-hold.yml | 1 | 1 | cloudflare-worker-production | None |
| retire-public-site-origin.yml | 1 | 48 | github-pages | None |
| test-product-monitoring-email.yml | 1 | 32 | None | ALERT_SMTP2GO_API_KEY, SMTP2GO_API_KEY |
| validate-attack-feeds.yml | 1 | 50 | None | None |
| validate-phase1-d1-staging.yml | 1 | 1 | cloudflare-phase1-staging | None |
| verify-assignment-acknowledgement.yml | 10 | 18 | None | None |
| verify-catalogue-scope.yml | 3 | 33 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN |
| verify-cve-lookup.yml | 1 | 229 | None | None |
| verify-cvie-coverage.yml | 1 | 43 | None | None |
| verify-cvie-d1.yml | 5 | 42 | cloudflare-worker-production | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN |
| verify-cvie-dotnet.yml | 1 | 44 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN |
| verify-cvie-hyperv.yml | 1 | 46 | None | None |
| verify-cvie.yml | 2 | 48 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN |
| verify-disclosure-trend.yml | 2 | 225 | None | SITE_GATE_PASSWORD |
| verify-malware-dialogs.yml | 2 | 226 | None | SITE_GATE_PASSWORD |
| verify-multipage.yml | 3 | 217 | None | SITE_GATE_PASSWORD |
| verify-product-monitoring.yml | 5 | 32 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN, SITE_GATE_PASSWORD |
| verify-remediation-redesign.yml | 2 | 19 | None | None |
| verify-remediation-ui.yml | 4 | 224 | None | SITE_GATE_PASSWORD |
| verify-software-history.yml | 1 | 37 | None | CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_API_TOKEN |
| verify-workspace-dashboard.yml | 1 | 21 | None | None |

The complete branch-head/version/job inventory is supplied separately as `CVEHarbor-Workflow-Security-Inventory.json` and `.csv`. These files contain ref SHAs, paths, secret names and conditions, not secret values. See [the configuration handoff](phase1-security-configuration.md) for required manual controls and proposed corrections.
