> **Original checkpoint 29 verified; adoption awaits approval.** Run 41707547474,
> artifact 13275811878 verifies 18 empty tables and ten explicit indexes. Do not
> execute the step-0 bootstrap below or set a cursor. Follow the
> [guarded adoption and recovery procedure](permanent-staging-adoption.md).
> Current-manifest checkpoint 37 is not installed yet.

# Permanent CVEHarbor staging: implementation and activation

Updated November 3, 2026. **Prepared code, not activation approval.** PRs #243,
#251 and #253 remain draft. No resources, credentials, security settings, remote
schema, production data or deployed Workers were changed by this implementation.
Phase 2 remains on hold.

## Candidate and compatibility

The integrated application candidate belongs in **PR #243** on
`codex/cvie-core-phase012`. It includes the existing CVIE work from #243, the
Phase 1 integrity/recovery work from #251 and the security/R2 architecture already
integrated from #253. It does not promote CVIE features into the production-scoped
#251/#253 branches. Those drafts link to this staging implementation and retain
their production deployment boundaries. No additional PR is required.

The later #243 migration executor at `515e224c093a9102e5075d6daefae2d39c32e2ce`
was incorporated during development. Its transactional checkpoints, explicit
resume, response reconciliation, usage limits and Worker/Access invariants remain.
Its old 29-file/370-statement plan and `migrate-schema` approval are superseded.
Use this runbook and the new manifest, not historical staging provisioning docs.

Production release integration remains #253 → #251, after separate approval and
feed-transition gates. The integrated #243 staging candidate must not be merged
or promoted wholesale as a substitute for reviewing those production releases.
The pre-existing CVIE functionality in #243 has its own release scope.

## Fixed resource boundaries

| Resource | Required value / current evidence |
| --- | --- |
| Account | Existing `9706b4d98ad72884e67fd1eb875c8a61`; isolated from production |
| Permanent D1 | Existing `cveharbor-accounts-staging`, `fac61562-fc31-426d-8032-550aba63b7f6` |
| API Worker | Existing `cveharbor-accounts-staging`; private service binding only |
| Frontend Worker | Existing `cveharbor-site-staging`; existing workers.dev hostname, Access gate before every asset |
| Origin | `https://cveharbor-site-staging.cveharbor-staging.workers.dev` |
| Intelligence | `cveharbor-intelligence-staging`, private R2; existence/configuration still needs live verification |
| Disposable D1 | None approved in `staging/resources.v1.json`; add exact name AND UUID only after resource review |

Prior live evidence established both Workers, the D1 binding and 28 Access probes.
The last observed D1 was empty. **That is historical evidence, not a new live
inventory check.** The release workflow rechecks identity, inventory, deployed
metadata and Access before changes. An unknown resource or configuration stops it.
No create/delete/reset endpoint is present in the release process.

Permanent staging is for persistent synthetic accounts and application regression.
Disposable tests use separately approved resources in the same staging account,
never the permanent D1. The Phase 1 disposable D1 and empty-bucket R2 harnesses
remain separate: their bootstrap/reset assumptions are unsuitable for a populated
permanent environment. Do not create a second staging account.

## Schema and migration safety

`staging/migrations.v1.json` is the ordered, versioned, SHA-256 validated manifest.
It checks the complete SQL inventory; unknown, omitted, reordered or modified
inputs fail local preparation. Full filenames identify migrations, because #243
and #251 each have distinct 0028 and 0029 files. The manifest retains both sets.

The existing production schema files are applied intact. Phase 1's 0030 notification
outbox, 0031 link/status/history protections and 0032 recovery controls are ordered
explicitly. CVIE's registry/index migrations follow their prerequisites. Four
staging-only tables store schema receipts, captured mail, attachment chunks and
manual job runs. No production table is rebuilt by bespoke staging feature code.

The local plan has **35 source inputs plus one generated guard batch, 740
statements, 102 application/staging tables (103 including sqlite_sequence)**.
The committed `staging/bootstrap-approval.v1.json` pins the complete plan digest:

`a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3`

`python staging/scripts/migration-plan.py` regenerates checkpoints using real
SQLite, validates foreign keys after every statement, and checks final integrity.
Receipts retain full path, checksum, manifest version and applied time. SQLite
and Cloudflare internal history is excluded from fingerprints and never removed.

Remote `migrate` is an **empty-schema bootstrap or exact checkpoint resume**. It
rejects unrecognized/populated schemas and never adopts them automatically. Each
file batch starts with schema/count/seed assertions inside the write transaction.
It records D1 metrics and checks storage, foreign keys, Worker metadata and Access.
Limits are 1,000,000 rows read, 100,000 written and 100,000,000 storage bytes;
these are stop thresholds, not billing quotas. Missing counters also stop writes.
A lost response triggers one read-only reconciliation, not an automatic retry.

Future migrations on a populated permanent database need a reviewed forward plan
with a drained write hold and preservation tests. The current bootstrap cannot be
reused as an unrestricted migration runner. Local manifest-state tests demonstrate
idempotent receipt handling and preservation; they do not authorize remote upgrades.

## Application isolation and intelligence

Both Workers bind the same private `INTELLIGENCE_BUCKET`. They use the #253
content-addressed snapshot reader; frontend scripts pin a manifest version, old
versions remain readable, and a corrupt/missing feed returns an explicit error.
The publisher uploads immutable objects/manifests, reads them back, then conditionally
promotes `current.json`. Failed promotion retains the last known good pointer.
Historical threat/cache data is retained across synthetic republication.

The staging publisher accepts only generated synthetic data. It invokes the same
publication protocol as production, without executing live collectors. Production
hourly feeds and their credentials are unchanged. The existing eight-hour digest
freshness check and lifecycle freshness checks remain active. Staging native crons
are empty and the staging scheduled entrypoint remains a no-op.

The bundled backend replaces every network fetch with a context-bound fixture
transport. It has no native network fallback. Recognized intelligence providers
return synthetic responses; unknown destinations and provider writes fail closed.
The fixture monitor host is `synthetic-monitor.example.org`; its DNS/HTTP/WebRisk
responses are intercepted, with no real request to that domain. Existing hostname,
SSRF, rate, session, MFA and tenant checks remain in application code.

## Captured mail and controlled jobs

All existing SMTP2GO paths retain their templates and notification state machines.
Only the sentinel capture key enters application code. Production provider keys
are neither forwarded nor stored. Registration/login, reviewer verification,
assignment/acknowledgement, status mail, reminders/FYI, digests, lifecycle notices,
monitor notifications and report attachments use the same capture transport.
Provider acceptance is simulated; real delivery/webhook behavior requires separate
synthetic webhook testing, never actual customer email.

Authorized administrators inspect `/__staging/`. Access JWT signature, issuer,
audience and expiry are checked first, then its signed human email must match the
explicit administrator allowlist. A service token or forged identity header cannot
open the inbox. The private API is accessible only through its service binding.
The inbox displays captured HTML as text, avoiding execution of email content.
Attachments are stored in bounded chunks. Captures contain sensitive test codes
and links: retain Access restrictions and use synthetic accounts only. Automatic
mail cleanup is not enabled; retention/deletion requires a reviewed policy.

Reviewer emails point to the same staging origin. The frontend forwards both the
account session and reviewer session cookies while stripping Access credentials.
The same accountless email verification and acknowledgement proofs remain required.

Manual testing is disabled by default. After approval, deploy the reviewed variable
`CF_STAGING_MANUAL_JOBS_ENABLED=true`; native crons still remain disabled. A signed
allowlisted administrator can POST same-origin JSON to `/__staging/jobs`:

```json
{"id":"<new UUID>","job":"hourly","scenario":"synthetic"}
```

Jobs: `remediation` (status/progress/FYI/disclosure/monitor mail), `cvie` (NVD queue),
`hourly` (digests/lifecycle/product/plugin/website checks). Scenarios: `synthetic`,
`provider-failure`, `mail-failure`. Duplicate run IDs do not rerun a job; one active
run is allowed across all jobs. Recovery holds reject new runs. Inspect run state,
application delivery records and captured mail together: dispatch completion alone
does not prove every application-level notification was eligible or delivered.
A crashed running job requires investigation; no automatic lock/lease expiry exists.

## Administrator configuration — approval required before changing it

Reuse **GitHub Settings → Environments → cloudflare-cvie-staging**. Verify that
required reviewers and deployment branch restrictions are enforceable under the
current repository plan; configuration text alone is not enforcement. Permit only
the reviewed `codex/cvie-core-phase012` branch for this draft validation. No PR-triggered
credential access, repository-level staging secrets or production credentials.
Use a protected, explicitly approved execution process if environment reviews are
unavailable; do not enable remote operations assuming protection exists.

| Environment variable | Value |
| --- | --- |
| `CF_STAGING_ACCOUNT_ID` | fixed account above |
| `CF_STAGING_D1_DATABASE_ID` | fixed permanent UUID above |
| `CF_STAGING_ACCESS_ISSUER`, `CF_STAGING_ACCESS_AUD` | reuse verified existing Access issuer/audience |
| `CF_STAGING_ADMIN_EMAILS` | comma-separated approved human administrator emails; maximum 10 |
| `CF_STAGING_MANUAL_JOBS_ENABLED` | `false` initially |
| `CF_STAGING_APPROVED_COMMIT` | exact reviewed full candidate SHA, matching run and checkout |
| `CF_STAGING_PROVISION_ACTION` | one reviewed operation: `migrate`, `publish-synthetic`, `update`, `verify`, `hold`, `freeze`, `recover-code`, `resume` |
| `CF_STAGING_SCHEMA_PLAN_SHA256` | digest above, only after inspecting regenerated plan |
| `CF_STAGING_SCHEMA_RESUME_STEP` | `0` for empty bootstrap; another cursor only after explicit reconciliation review |
| `CF_STAGING_EXPECTED_HOLD_REVISION` | freshly inspected revision for hold/freeze/resume |
| `CF_STAGING_RECOVERY_REASON` | specific 10–500 character reason for recovery operations |

Environment secrets, never values in chat or repository:

- Existing `CF_STAGING_API_TOKEN`: staging-account-only management token. Required
  capabilities: account metadata/read, Workers Scripts Edit (existing names),
  Workers asset upload support, D1 Edit (permanent staging), R2 metadata read,
  Access applications/policies and service-token metadata read. No production
  account access. Cloudflare cannot constrain all account permissions to individual
  Worker names; the executor adds exact resource checks. Do not widen an existing
  token silently. Prior owner-attested scope is retained only for the known 403
  introspection case; conflicting metadata always fails.
- Existing `CF_STAGING_ACCESS_CLIENT_ID` and `CF_STAGING_ACCESS_CLIENT_SECRET`:
  existing Access service-auth policy used only for boundary/readiness probes.
- `CF_STAGING_R2_ACCESS_KEY_ID` and `CF_STAGING_R2_SECRET_ACCESS_KEY`: R2 S3 Object
  Read & Write restricted to the single permanent staging bucket. No production
  buckets/account, D1 or Worker deployment permissions. Used only by the approved
  synthetic publisher subprocess. R2 metadata uses the management token separately.

Cloudflare administrator actions, separately approved:

1. Select the existing staging account, inspect R2 inventory first and reuse the
   exact private bucket if suitable. If missing, request approval to create
   `cveharbor-intelligence-staging`. Keep r2.dev/public URL off, no custom domains,
   no public CORS or automatic object expiry. Do not enable paid resources silently.
2. Verify the existing D1 UUID and both Worker names. Do not delete/recreate them.
   Preserve Access application/policies/service token and existing hostname.
3. Install **staging-only** Worker secrets `STAGING_TOTP_ENCRYPTION_KEY` and
   `STAGING_MONITOR_WEBHOOK_TOKEN` securely on the existing private API Worker.
   Never copy production keys. Preserve the staging TOTP key across updates or
   existing staging users cannot decrypt their MFA configuration.
4. Configure environment metadata and bucket-scoped publisher credentials as above.
   Do not install SMTP2GO, live provider or production secrets on staging Workers.

## Exact activation sequence

Each remote operation needs explicit owner approval, the protected environment
review, matching source SHA and the selected operation. A workflow dispatch input
must match `CF_STAGING_PROVISION_ACTION`. While the workflow is absent from main,
a separately approved `[staging-release]` commit plus **manual rerun** can expose
the job; its initial push always skips it. This implementation commit does not
carry that marker and no remote run was initiated. Never merge merely to dispatch.

1. Review candidate diff, local results and regenerated migration plan. Complete
   the resource/permission checks above; separately approve any missing configuration.
2. Approve `migrate`, digest and step 0. The job rechecks inventory/Access, captures
   a D1 recovery bookmark and existing Worker versions, then executes only the
   guarded bootstrap. Review final checkpoint, counts, metrics and unchanged Access.
   If the D1 is no longer empty, stop: do not reset it or reuse an old cursor.
3. Approve `publish-synthetic`. The job checks the private bucket and publishes only
   generated fixtures using immutable objects, readback and conditional promotion.
   Review the manifest and history metadata. No application deployment occurs.
4. Approve `update`. It requires the full exact schema, no write hold, safe resource
   bindings and both dry runs. It updates the **existing backend first**, verifies
   active metadata and `/v1/staging-readiness` through the existing Access frontend,
   then updates the existing frontend. No frontend upload occurs if those gates fail.
   It verifies frontend Worker-first routing, Access boundaries and unchanged hold state.
5. Approve `verify` for a fresh read-only inventory/schema/Access check. Test human
   SSO, account registration/MFA through capture, customer inventory/findings,
   record linking/duplicate prevention/status history, assignment/receipt/reviewer
   links, tickets, reports and shared feed versions through the real staging site.
6. Only after reviewing the full configuration, approve manual-job enablement via
   another `update`. Use synthetic accounts and controlled scenarios. Verify
   reminder/digest idempotency, failures, freshness and recovery. Keep native crons off.
7. Run the approved disposable D1/R2 rehearsals and separate SELECT-only production
   audit to complete #251/#253 production readiness. Permanent staging tests do not
   replace those provider-specific failure tests or establish production integrity.

## Recovery and future updates

Capture artifacts even on failure. Never rerun a failed migration at cursor 0 or
blindly revert to the original schema-incomplete Worker. Review the reported actual
checkpoint/usage, approve an exact resume or a forward repair. There is no automatic
restore, resource recreation, deletion or SQL replay.

For an installed application: approve `hold` with current revision, wait for zero
active leases, inspect application/notification state, then approve `freeze` with
the new revision. The guards cover inventory, remediations, assignments, receipts,
review sessions, outboxes/history and staging captures/jobs. Do not expire leases
just to make recovery proceed. Capture the D1 bookmark and immutable R2 pointer.

`recover-code` requires frozen, drained state, the exact installed schema and a
reviewed compatible package. It updates backend then frontend with runtime gates
while preserving the hold. It cannot roll back schema or replay notification state.
After verifying integrity, foreign keys, records/history, Access and delivery queues,
separately approve `resume` with the current revision. The resume checks reject
integrity failures and release the freeze/hold together. Rerun `verify` and inspect
captured notifications before allowing further tests.

A D1 Time Travel restore or R2 pointer rollback requires separate approval and a
review of writes since the bookmark. Do not delete outboxes, acknowledgements,
reviewer links or notification idempotency records to make tests pass. Production
credentials/data are never inputs to this recovery process.

Sanitized production refresh is deliberately **not implemented or authorized** in
this change. A later plan must remove sessions, MFA material, tokens, emails,
customer identifiers and pending notification/scan work before import into a held,
isolated database. It must preserve relationships and verify fixture-only egress.

## Validation and remaining gates

[Recorded local results](../cvie-evidence/permanent-staging-local-validation.json):
15 staging test files, 42 backend test files, 7 release/site-gate test files and
169 Python test cases passed. The migration executor contributes 9 failure/resume
cases. CVIE onboarding, customer security/software upgrade and product-monitoring
UI smoke suites passed.

Local validation uses real SQLite schema/SQL, the bundled application, synthetic
provider responses and captured email. It covers authentication/MFA/replay, tenant
isolation, assignment acknowledgement and reviewer progress, link/status/history
and ticket preservation, overdue manager/reviewer reminders without repeats,
report attachment capture, vulnerability digests, lifecycle notices, product and
website monitoring, full manifest/checkpoints, release failure ordering, R2 failure
and history behavior, and Access signature/admin authorization. Native local workerd
also verifies Access JWTs and the capture transport's asynchronous context; both
credential-free Wrangler packages pass.

Remote D1 transaction/metric behavior, R2 conditional writes, deployed service
binding/readiness ordering, live human Access SSO, full staging browser acceptance,
and the production read-only integrity audit remain approval/configuration gates.
Synthetic provider fixtures cannot prove live vendor API availability or actual
mail delivery. None of those pending checks is reported as passed.
