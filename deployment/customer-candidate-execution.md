# Customer remediation protected execution adapter

Implemented in `staging/scripts/customer-candidate-execute.mjs`, with credential-free
artifact sealing, an exact-schema classifier and transactional migration guards.
The existing `cvie-staging.yml` now exposes **none/status/migrate/deploy/resume-frontend**.
Nothing is enabled by default. Do not run an operation until separately authorized.

## PR dependencies and safe merge order

This adapter PR is stacked on PR #267's branch so its diff contains only execution
code, tests, workflow gates and this runbook. Do not merge it into that feature branch
as a substitute for reviewing the final main revision. After #267 merges, retarget
this PR to main and rerun CI/review its isolated diff.

PR #266 (`03c452ae080206ce42215c1a39ca0dd95cb0ab5b` when reviewed) only switches
`source_mode` to `reviewed-main` with the **old step-209 schema**. It is not a dependency
of this adapter and is not a compatible activation path for the extended schema.
Keep #266 draft/deferred; if needed later, rebase and remove its obsolete baseline
activation instructions. Never use its ordinary release against the new schema.

After explicit review/merge approval, the safe sequence is:

1. Before merging **either** #267 or this PR, an administrator must explicitly set
   repository `SIMPLE_STAGING_ENABLED=false`, ensure no old staging job is running
   or awaiting approval, and leave `CF_STAGING_CANDIDATE_ENABLED` unset/false. Do not
   approve queued older workflow revisions. This prevents the #267 merge from
   invoking the currently installed automatic baseline workflow. These settings
   have **not** been changed by this work.
2. Merge #267 only when authorized. Retarget/review/merge this adapter PR separately.
   This adapter's workflow removes push-triggered baseline execution; the former
   automatic job permits only manual `diagnose` or `readiness` dispatches. The
   candidate job is manual-only and additionally requires the baseline lane disabled.
3. Wait for all CI at the **final main SHA**. No migration/deployment runs on merge.
   Review the `customer-candidate-review` artifact and the safe hashes printed by
   “Seal tested candidate artifacts without credentials”. Any subsequent main
   commit needs fresh artifact review and approvals; branch names are not pins.

## GitHub preparation and approvals

Use the existing protected environment **cloudflare-cvie-staging**, its required
reviewers and main-branch restrictions. Verify those protections before opting in;
this PR does not change environment protections, Access policies, secrets or resources.
The workflow uses the existing staging API and Access service-token secrets only.

When explicitly approved to begin read-only validation, set repository variable
`CF_STAGING_CANDIDATE_ENABLED=true`, retain `SIMPLE_STAGING_ENABLED=false`, and set
protected environment variable `CF_STAGING_APPROVED_COMMIT` to the final main SHA.
All existing account/database/Access/admin variables remain in use. Do not change
production settings. New approval variables below are non-secret review bindings,
not credentials; required environment review remains mandatory for each run.

In **Actions → Permanent staging preparation and approved updates → Run workflow**,
select **main**, leave legacy `operation=none`, and provide:

- `candidate_operation=status` initially;
- `candidate_commit`: the exact final main SHA;
- `candidate_sql_sha256`, `candidate_profile_sha256`, `candidate_artifact_sha256`:
  the three reviewed hashes printed by the seal step for that revision;
- leave candidate confirmation/version fields empty for status.

The credential job rebuilds without credentials, then verifies its seal matches
both the explicitly supplied hash and the successful `prepare` job's hash. API,
frontend assets, manifest, SQL, source/profile pins and clean checkout are checked.
No write client exists before authorization. Reports contain only safe check names,
booleans, hashes, timestamps and Worker version IDs; no response bodies/record data.

### Separate migration approval

Review status evidence, exact SQL and the quiet staging-test window. Arrange an
approved pause in application testing/writers for migration; the adapter does not
change Access policies or install a hold system. Before the write, it confirms
Time Travel availability and records a timestamp plus bookmark hash, never the
raw bookmark. Use existing private recovery tooling for any separately approved
backup/export; no new recovery infrastructure is created.

Set `CF_STAGING_CANDIDATE_WRITE_WINDOW=<commit>` and protected environment variable
`CF_STAGING_CANDIDATE_MIGRATION_APPROVAL` to this exact string:

`migrate:<commit>:<sql_sha256>:<profile_sha256>:<artifact_sha256>`

Dispatch a **new run** with `candidate_operation=migrate`, the same reviewed hashes,
and `candidate_confirmation` equal to that full string; approve the protected job.
The adapter rechecks Access/inventory, existing versions/domain/private bucket,
exact original schema/receipts and FK integrity, then uses one D1 batch containing
schema/count guards, the approved CREATE statements and one append-only receipt
in existing `staging_schema_history` (manifest_version=267). It never initializes,
resets, updates existing application rows or applies other migrations. It verifies
all previous table counts, the extended schema, empty new tables and FK integrity.
The SQL checksum from #267 stays unchanged; the execution receipt is additional
staging metadata, not a change to the step-209 receipts or production baseline.

Clear the migration approval after success. Review `customer-candidate-execution`
evidence before granting any deployment approval.

### Separate deployment approval

Set `CF_STAGING_CANDIDATE_DEPLOYMENT_APPROVAL` to:

`deploy:<commit>:<sql_sha256>:<profile_sha256>:<artifact_sha256>`

Dispatch a **new run**, operation `deploy`, same pins and matching confirmation;
approve the protected job. Both Workers dry-run first. The backend uploads once,
then configuration/version and authenticated legacy readiness must pass before
frontend upload. Readiness requires the candidate marker, explicit MFA/monitoring,
exact schema, synthetic R2, captured email, disabled schedules and expected release.
Only healthy HTTP 200 with stale release identity receives the existing bounded
propagation wait. Final custom-domain/schema/Access probes must pass.

Clear deployment/window approvals after completion. Perform fictional-customer
acceptance and keep the baseline lane disabled while the extended schema exists.

## Interrupted operation recovery

Never choose GitHub “Re-run failed jobs” for a write: run_attempt > 1 is rejected.
Use a fresh reviewed dispatch; no automatic upload, SQL retry or rollback occurs.

- **Migration response lost:** dispatch `status`. Exact candidate schema plus its
  matching receipt means the batch committed. A fresh authorized `migrate` detects
  that state and performs no DDL. Exact baseline means the batch did not commit;
  review evidence and reauthorize a fresh migrate. Unknown/partial schema, missing
  receipt or FK failure stops for investigation; never drop objects/reinitialize.
- **Backend upload/readiness interrupted:** dispatch `status` for current versions.
  If the backend matches the approved candidate, use `resume-frontend`, never
  another `deploy`. A fresh deploy refuses a backend already matching this commit.
- **Frontend upload/final checks interrupted:** use the same resume operation. It
  skips frontend upload too if the exact candidate frontend is already active,
  then repeats read-only runtime/security verification.

For resume, set deployment approval and confirmation to:
`resume-frontend:<commit>:<sql_sha256>:<profile_sha256>:<artifact_sha256>`.
Supply `candidate_backend_version` and `candidate_frontend_version` from the reviewed
status evidence. The adapter rejects version drift, verifies the exact backend
configuration and readiness, and never uploads the backend during resume. An
unknown backend or unexpected version must be investigated rather than overwritten.

Failures retain sanitized step/version evidence and never restore the database
or change policies. Any Time Travel restore is a separate reviewed recovery action:
it can discard unrelated writes. After new customer records exist, retain compatible
readers and prefer a forward correction. There is no test-data reset in this adapter.
