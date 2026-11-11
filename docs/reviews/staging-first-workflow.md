# CVEHarbor staging first application delivery

This document describes the reviewed application release process for
`cveharborstage.com` and `cveharbor.com`. It is not permission to merge a
pull request, deploy a Worker, change Cloudflare policy, or migrate a database.

## Activation in this pull request

The only application release configuration change is
`staging/application-release.json: source_mode = reviewed-main`.
The staging build then takes both backend and frontend application files from
the reviewed `main` checkout, instead of the initial pinned production
snapshot. The first release can therefore contain application changes already
present on `main`. Review its built artifact and staging acceptance results
rather than treating it as a no-op.

This transition retains:

- The existing separate staging Cloudflare account and D1 database.
- The exact `production-baseline-209` schema profile and verification of all
  143 application objects, without new migrations or row rewrites.
- Staging only MFA encryption and synthetic email capture.
- Private R2 synthetic intelligence and blocked external provider calls.
- Existing Cloudflare Access administrator and automated service token policies.
- No public backend origin, no live outbound email, and no native scheduled jobs.
- Backend upload and runtime verification before frontend upload, followed by
  Access and custom domain verification.

The baseline's 29 installed schema source files are checked on CI against
their audited SHA256 values. An application change that requires additional
database tables must **not** use this switch to install a migration. Prepare
and approve the database change separately. A successful build is not proof
that every new feature works against the production-only schema.

## Everyday development and promotion

1. Implement fixes and features on dedicated GitHub branches. Open pull
   requests against protected `main`. Require passing application, workflow
   policy, and staging preparation checks before merge.
2. On an approved merge, the existing staging workflow prepares the exact
   reviewed commit and uses the protected `cloudflare-cvie-staging`
   environment. Approve that staging deployment only after reviewing the
   change and its scope. Never manually dispatch an extra release when a push
   release is already active.
3. The existing release verifies schema, resources, Cloudflare Access,
   Worker settings and synthetic intelligence. It uploads the backend once,
   waits for the exact release identity, uploads the frontend only after
   successful backend readiness, and checks the final site boundary.
4. Test `https://cveharborstage.com` with fictional customers and staging
   accounts. Verify changed functionality, login and MFA if relevant,
   regression scenarios, customer isolation, assignments, reports and captured
   notifications. Record the GitHub run and functional acceptance outcome.
5. Promote **only after** explicit human acceptance. The production backend
   and frontend workflows require a successful staging release artifact
   for the exact `main` commit and matching backend source identity before
   their protected production environment jobs may proceed. Production
   environments and their reviewers remain separate from staging.
   Never approve production solely because CI passed.
6. Verify production after separately approved deployment, including app
   health and smoke testing. Keep the staging version IDs, release artifact
   and known-good production version IDs for a forward fix or a separately
   reviewed rollback.

Production gating is conditional on the existing release enablement
variables. Do not enable `PRODUCTION_DEPLOYMENTS_ENABLED` or
`SIMPLE_RELEASE_ENABLED`, weaken an environment, or add bypasses as part
of this staging source transition. Production release must stay under its
existing explicit approvals and recovery controls.

## Schema, security and rollback

- Code-only releases must not run D1 migrations or change recorded migration
  receipts. Schema changes require a separate reviewed plan, tested backup
  and restoration evidence, explicit staging approval and subsequent distinct
  production approval.
- Customer records must not be copied from production. Staging uses synthetic
  inventory and private synthetic intelligence. Email remains captured,
  never delivered to real customers.
- An application PR that changes `account-backend` SQL or introduces an
  expectation for new tables must first establish a compatible schema profile.
  If the checks fail, stop. Do not change the D1 checkpoint to make CI green.
- When a release fails, inspect its sanitized GitHub artifact. Do not blindly
  rerun a partially completed deployment or run initialization again.
- To return to pinned source selection, prepare a separate reviewed PR
  reverting only the source mode, check schema compatibility and obtain a
  new staging approval. Existing D1 data and resources are preserved.

## One time acceptance for the source mode change

- [ ] CI builds the `reviewed-main` backend and frontend and passes all
      staging preparation, isolation and browser tests without credentials.
- [ ] The production-only schema at step 209 still matches the reviewed
      baseline and no migration is requested.
- [ ] The first approved staging deployment completes and all final Access
      probes pass on `cveharborstage.com`.
- [ ] Administrator verifies login, MFA, imported inventory, remediation,
      customer permissions and reports using synthetic records.
- [ ] Production gates and environment approvers remain in place.
- [ ] No production deployment is approved until those staging results
      have been reviewed.

The customer-scoped Remediation Tracker enhancement is a separate feature.
Its customer identity and data migration design require their own review;
this source-mode change does not implement that feature.
