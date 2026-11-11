# Backup AI platform owner and release verification

The owner explicitly authorized equal AI platform-owner permissions for `prat.mahen@gmail.com` and `prat@mahendran.tech` on November 11, 2026. Both accounts remain subject to the existing MFA/session checks. Organization roles and read-only dashboard delegates gain no additional access. AI must remain paused for every organization until the Azure owner confirms the model settings.

## Production state and scope

PR #341 is merged at `17cdd73a653de97cbb6155db63f405a6cddf6b79`. Its additive database migration succeeded in run 43082359055; do not rerun that migration. Backend run 43083673118 deployed version `8dcfd396-07dd-4c8c-80a7-d2f848b30f7b`, package `b27e7dfae44a4de59daf6e9e903a74a3bf34132be06bb8de622746d1b1cc625a`. Its immediate after-deployment check saw a different build; subsequent public readiness checks returned the exact intended package and healthy schema. The website overlay has not yet been published.

This follow-up reconstructs the exact PR341 backend and changes only `ai-admin.js` and the added non-secret binding `CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL`. Package identity: `ce561b7756d14c874d353470c84b8c9228626e400df8d776dcb83ee03eadeb2a`. It changes no database objects, Azure credentials, existing bindings, customer inventory, model settings, prices or allowance logic.

The after-deployment check now waits up to twelve five-second intervals only while the exact healthy predecessor is still serving. Unexpected builds, schema failures and recovery holds fail immediately. Exhausted retries remain a failure. The complete schema, owner MFA, unchanged-binding hash, secret-binding presence, predecessor recovery and anonymous-access checks still run. Both before and after checks require zero enabled organizations.

## Release sequence

1. Review this follow-up and obtain its merge approval. Require application/security, accounting, package and website checks on the exact merged main commit.
2. Verify owner eligibility, main-only production environments and disabled administrator bypass. Approve under the owner's standing deployment delegation and record the scope.
3. Deploy `team_release=organization-ai`, `team_commit=<approved main SHA>`, `release_mode=code-only`. All unrelated selectors stay off. No migration is needed. Require the serving PR341 predecessor and both existing MFA-enabled owners. Retain the complete backend recovery receipt.
4. Publish the already-approved dashboard overlay through `session-navigation` with `site_release=organization-ai` and the same reviewed commit. The website predecessor remains PR337 version `5471b3b6-eb78-4bee-a753-659e8675244f`, deployment `c9beba0a-0541-4da5-bc9d-db98b9ca8f0e`. Publish only the two navigation files and seven AI assets from PR341; preserve unrelated website assets and current feeds.
5. Verify served bytes, fictional responsive UI tests, authenticated owner controls and all organizations paused. Do not submit paid inference or click Enable. Record all run links and remaining live checks.

## Validation

Local tests cover both owners' administrative actions, refusal to revoke either owner as a dashboard delegate, ordinary organization-owner/delegate denial, invalid owner bindings, backup-account MFA enforcement, exact predecessor propagation, retry exhaustion, unexpected builds, schema failures and recovery holds. All 18 targeted authorization/accounting/release-health tests passed. Scoped package reconstruction confirms only the intended module and configuration addition change the serving backend. CI runs native Cloudflare accounting and broad application/security checks before production approval.
