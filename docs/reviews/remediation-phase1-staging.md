# Phase 1 D1 staging and secure configuration

## What is prepared

Workflow: `.github/workflows/validate-phase1-d1-staging.yml`.
Harness: `scripts/phase1_staging.mjs`.

The harness uses a separate Cloudflare D1 database and synthetic fixture data. It invokes the real Worker handlers against D1 through the tested REST batch adapter; all advisory and mail calls are intercepted. It does not deploy a Worker, create customer records in production, copy production data, or send real email. Wrangler packaging is tested separately. A hosted Cloudflare Worker traffic/latency rehearsal remains a distinct operational check if needed; do not describe this harness as a deployed staging Worker.

## Configure without sharing secrets in chat

An authorized administrator must create an empty disposable D1 database named `cveharbor-phase1-staging` or `cveharbor-phase1-staging-<suffix>`. Prefer a separate staging Cloudflare account. Scope its credential to staging resources as narrowly as Cloudflare supports; do not use a production token as a fallback.

Create/protect GitHub environment `cloudflare-phase1-staging` with:

| Type | Name | Value/source |
| --- | --- | --- |
| Secret | `CLOUDFLARE_STAGING_API_TOKEN` | Staging-only D1 credential entered through the secure GitHub environment UI/API. |
| Secret | `CLOUDFLARE_STAGING_ACCOUNT_ID` | Account containing only the intended staging resource, or the explicitly approved staging account scope. |
| Variable | `STAGING_DATABASE_ID` | UUID of that separate database. Must differ from the production UUID in Wrangler. |
| Variable | `STAGING_DATABASE_NAME` | Exact approved staging name above. |
| Variable | `STAGING_DISPOSABLE` | `true`. |

Distinct staging secret names prevent accidental inheritance of generic repository-level production secrets. No SMTP2GO credential is needed. No production Worker or DNS permissions are needed. The harness verifies the remote database's returned UUID and name before any write; it also rejects the production UUID before making an API request.

In the current development environment no secrets, runtime identity, or staging resources are configured. Remote Cloudflare API access is not available through its current destination policy. No remote database was created or tested. In a managed environment, configure the staging credential binding and authorized Cloudflare API destination through the supported secure configuration interface. GitHub-hosted execution uses the protected environment above.

## Execution

Use the reviewed source revision in an authorized runner. Do not merge just to make a new draft workflow dispatchable.

1. Run local tests and packaging first.
2. Select `bootstrap` in **Phase 1 isolated D1 staging rehearsal**. It requires an empty database. It installs the checked-in baseline schemas through 0030 and synthetic identities/inventory. It refuses to reseed or wipe an existing database. Interrupted bootstrap requires investigation or a fresh disposable database, never an automatic reset.
3. Select `validate`. It requires the staging marker and only the known synthetic account identities. It snapshots existing table content, applies 0031/0032 and recovery guards twice, and checks data equality. It exercises assignment creation, hold/drain/freeze/resume, a retained acknowledgement URL, record linking, status synchronization, intercepted participant notifications, and read-only integrity/foreign-key checks.
4. Retain the aggregate result and exact source revision. Require `passed=true`, all audit counts zero, zero foreign-key violations and zero real emails. Run `validate` again to verify repeatability; only synthetic session expiry is refreshed for repeated API tests.
5. If validation leaves a hold active, inspect the disposable database. Do not use a production recovery command against an assumed staging target: the production control CLI is deliberately pinned to production config. Use the isolated staging harness or a separately reviewed staging-only repair.

Equivalent staging commands, with configuration already injected securely:

```sh
node scripts/phase1_staging.mjs bootstrap
node scripts/phase1_staging.mjs validate
```

The CLI uses `CLOUDFLARE_ACCOUNT_ID` / `CLOUDFLARE_API_TOKEN` internally; the staging workflow maps the two distinct staging secrets into those process variables only. Never print them or pass token values in command arguments.

## Production audit preparation

Use `.github/workflows/audit-remediation-integrity.yml` with the existing `cloudflare-worker-production` environment. The `preflight` mode requires no new production schema and executes SELECT-only checks. The `installed` mode also verifies Phase 1 guards and operational state. Both include foreign-key consistency and report aggregate counts, never customer information.

Before production approval, retain a successful live preflight, verify production environment/branch protection, and retain successful isolated D1 validation. These remote results are still outstanding; successful local simulation is not a substitute.
