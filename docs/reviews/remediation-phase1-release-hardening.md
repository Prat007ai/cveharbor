# Phase 1 release hardening — implementation results

November 3, 2026. Scope: draft PR #251, Phase 1 only. No merge, production deployment, production migration, production-record mutation, or Phase 2 work was performed.

## Corrections completed

1. **Frontend publication gate.** Every publication, including scheduled runs, must match the deployed backend's source/schema/configuration identity and pass live SELECT-only schema/integrity/hold checks. The gate runs before frontend provider changes, and is also enforced inside the deployment script. Public feed updates do not invalidate API compatibility. Production writers and publication share a concurrency group.
2. **Explicit manual release modes.** Manual Worker deployment defaults to code-only, never maintenance. Phase 1 explicitly selects migrations 0031 and 0032 plus table guard installation and verification. Unknown schema diffs fail closed. Unrelated CVIE maintenance requires an explicit separate selection. Recovery code-only supports a compatible fix while retaining a fully drained frozen hold.
3. **Database-backed recovery control.** Additive migration 0032 creates operational state, event history, and leases; it does not transform customer data. Guard installation covers all existing application tables, including optional schemas, without installing unrelated features. Admission hold stops new Worker requests and cron work; leases retain in-flight/background operations until completion. Freeze is a separate atomic step requiring zero leases. Table triggers then block writes/cascades. Resume requires the current revision, complete guards, clean integrity/foreign-key checks, and zero leases.
4. **Auxiliary writer coverage.** Existing activation, account-deployment, and production CVIE probe workflows use the same lock and check the hold before writes. Schema-activation workflows refresh guards for new tables. Protected production credential/branch policies remain necessary to prevent historical workflow revisions bypassing current source safeguards.
5. **Isolated D1 staging harness.** Explicit separate UUID/name/disposable checks, empty-database-only bootstrap, synthetic account validation, migration preservation/repeatability, original receipt link, linking/status/notification tests, and hold/freeze/resume. Mail is intercepted. Staging secrets have distinct names, so absent configuration cannot silently fall back to a generic production token.
6. **Independent read-only production audit.** A dedicated workflow uses the existing authorized Cloudflare environment. Its client rejects mutations/multiple statements before sending and checks zero rows written. Preflight works before the new migrations; installed mode adds operational state/guard checks. Both include aggregate foreign-key consistency.

No UI redesign, status vocabulary change, reminder-policy change, token rotation, participant-access change, assignment resend, or historical email replay was introduced by these release controls.

## Validation completed locally

- Backend: **39 test files passed**.
- Recovery: **7 dedicated scenarios passed** (included in the backend suite).
- Release/staging/audit: **8 scenarios passed**.
- Python: **119 tests passed**.
- Existing Phase 1 browser regression with real Worker handlers and synthetic/intercepted email: **passed**.
- Site build and local generated-route/asset preflight: **passed**.
- Wrangler 4.156.0 Worker packaging with `deploy --dry-run`: **passed**, with the required recovery runtime setting. This was not a deployment.
- Current full Phase 1 diff classified as the isolated integrity release; workflow YAML parsed successfully.

The staging harness was executed against disposable SQLite using the same bootstrap/rehearsal code prepared for Cloudflare D1. It refused reseeding, retained existing data across repeated installation, verified original acknowledgement access after resume, and completed clean integrity/foreign-key checks. Actual remote D1 execution remains outstanding.

Recovery tests additionally proved that an assignment email already in progress can finish recording its delivery state during drain; freeze refuses while its lease is active; resume does not replay that email. A hold alone is therefore not permission to start database recovery: wait for zero leases and explicitly freeze first. Revoked/expired reviewer behavior, historical linking, status mail, and tenant isolation remain covered by existing regression tests.

## Remaining configuration and evidence

- Provision/protect `cloudflare-phase1-staging` and a separate disposable D1 database. Configure `CLOUDFLARE_STAGING_API_TOKEN`, `CLOUDFLARE_STAGING_ACCOUNT_ID`, `STAGING_DATABASE_ID`, `STAGING_DATABASE_NAME`, and `STAGING_DISPOSABLE=true` through the secure environment UI/API.
- Run staging `bootstrap`, then `validate`, retaining the exact revision and aggregate results. This harness tests real D1 through Worker handlers; it does not deploy a Cloudflare-hosted staging Worker.
- Run the production `preflight` audit in the existing authorized environment. No production integrity counts can yet be reported as passing: credentials and authorized Cloudflare API access are unavailable in this development environment.
- Confirm required reviewers and approved deployment branches on production environments, and that older/unreviewed branches cannot receive production-write credentials through repository-level secret inheritance. This administrative configuration was not inspected or changed.
- Verify the updated draft PR's exact-head CI checks before production approval. No workflow containing production actions was dispatched during this work.

## Operational effects and limitations

Normal operation gains transient lease insert/delete bookkeeping for write-capable requests and scheduled work. Public receipt/reviewer GET pages remain read-only. During a recovery hold, account APIs and reviewer/receipt pages return maintenance 503; read-only operational auditing remains available. Existing links are retained, but their normal expiration clocks continue. Due reminders/notifications resume under existing rules; activation/resume does not replay historical messages.

Crashed executions may leave persistent leases. They deliberately do not auto-expire: investigate execution/provider evidence before separately approving cleanup. Row guards do not prevent arbitrary administrator DDL or a database restore, so protected operational permissions remain essential. No automatic customer-data repair, reverse link, schema downgrade, or disaster restore is included.

Use `remediation-phase1-release.md` for exact production/recovery order and `remediation-phase1-staging.md` for secure configuration and rehearsal instructions. The previous routine old-schema rollback recipe is superseded: retain compatible recovery/canonical-link behavior and prefer a forward fix.

**Readiness:** implementation and local validation are complete. Production approval remains conditional on remote D1 staging, a clean live production preflight, production environment/branch protections, and green CI for the final draft revision. The PR remains unmerged and Phase 2 remains blocked.
