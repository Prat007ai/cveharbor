# Phase 1 staging and secure validation

Use [the consolidated administrator checklist](phase1-administrator-checklist.md)
for the current environment matrix, Cloudflare setup, exact commands and approvals.
This page replaces the earlier workflow-name/credential instructions.
Use [the permanent staging architecture](permanent-staging-architecture.md) for the
verified existing account, permanent D1/Workers, integration gaps and refresh plan.

## Permanent staging and disposable entrypoints

Reuse existing `cloudflare-cvie-staging`, `CF_STAGING_*` settings,
`cveharbor-accounts-staging` D1 (UUID `fac61562-fc31-426d-8032-550aba63b7f6`)
and both staging Workers in account `9706b4d98ad72884e67fd1eb875c8a61`.
The inspected run passed Access checks; full schema/app/R2/email testing remains.
Do not recreate these resources or run the following disposable bootstrap on them.
The existing one-D1 inventory guard must be reviewed before adding a disposable D1.
The staging schema builder must be corrected before incorporating 0030–0032.


- **D1:** `.github/workflows/security-phase1-staging.yml`, display name
  **Phase 1 readiness - isolated synthetic D1 rehearsal**; environment
  `cloudflare-phase1-staging`; operations `bootstrap` and `validate`.
- **R2:** `scripts/rehearse_intelligence_r2.py` in an approved secure runner.
  There is no R2 staging Actions workflow/environment dependency in this release.
  Never put staging keys in the production `cloudflare-intelligence-data` environment.
- **Production preflight:** `.github/workflows/security-phase1-audit.yml`, environment
  `cloudflare-production-audit`, separate `CLOUDFLARE_AUDIT_*` secrets; SELECT only.
  That workflow has no installed-mode input. Installed checks use the reviewed
  secure-runner command after an approved deployment.

`validate-phase1-d1-staging.yml` and `audit-remediation-integrity.yml` were retired
in the integrated branch. Do not dispatch an old revision or recreate them.

## Isolation and results

D1 **requires** an account separate from production: reuse the existing staging
account above. It also requires an exact empty disposable database
name/UUID, a staging-only D1 Edit token, and `PRODUCTION_ACCOUNT_ID` for the
inequality check. The prior wording "prefer a separate account" is superseded.
The workflow first runs `check_phase1_staging_boundary.mjs`; run that same check
before any CLI bootstrap. Bootstrap once, then validate twice. All mail/advisory
calls are intercepted; no deployed Worker is created by this harness.

R2 requires a fresh empty `cveharbor-intelligence-staging-<suffix>` bucket in a
same existing staging account (separate from production), Standard/private storage, a bucket-only S3 credential pair,
`FEED_STAGING_DISPOSABLE=true` and the verified production account ID. It tests
synthetic upload/readback, rejected stale conditional writes, history retention,
pointer recovery and exact restore. It does not create/delete resources or send
mail. Use a new approved empty bucket for a repeat rehearsal.

Before either PR is merged, run from the reviewed **integrated #251 checkout** in
an authorized runner. The standalone #253 readiness workflows retain an older
pinned harness; they are not the final integrated validation target. After both
approved merges, #251's workflow checks out the run SHA. Do not merge just to make
a draft workflow dispatchable, or weaken environment branch restrictions.

Hosted Worker R2 bindings/authentication/performance remain a separate staging
check with synthetic data and disabled/mocked email. Reuse the existing permanent application/database for that check after its
integration, schema and deployment are approved. Never use production DNS or real
recipients. Sanitized refresh is a separate future approval; synthetic data suffices.

The inspected permanent Access run does not satisfy disposable migration/R2 or
full-feature acceptance. Remote R2/D1 results and live SELECT-only production counts remain pending until
resources and secure credentials are configured. Local simulation is not proof
of Cloudflare permissions, deployment configuration or production integrity.
