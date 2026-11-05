# Protected staging activation: execution review contract

Status: prepared for review, not enabled or executed. No reset is included.
The build/schema profile and local readiness tests are implemented. The live
workflow adapter remains a review item; this document does not make ordinary
`release` capable of publishing the candidate.

Reuse `.github/workflows/cvie-staging.yml`, its protected
`cloudflare-cvie-staging` environment, existing staging concurrency lock and
existing secrets. No new infrastructure or secret is needed. A future adapter
must use explicit manual dispatch only, with separate migration and deployment
operations and no dispatch default that writes. Do not attach candidate execution
to push, PR, ordinary release, initialization or automatic post-merge execution.

## Fixed targets and artifact contract

- Use `TARGET` and `resources.v1.json`: existing backend
  `cveharbor-accounts-staging`, frontend `cveharbor-site-staging`, database
  `fac61562-fc31-426d-8032-550aba63b7f6`, private staging intelligence bucket and
  `https://cveharborstage.com`. Reject any production/disposable/different target.
- Require the final reviewed full commit SHA, protected-environment approval,
  matching `CF_STAGING_APPROVED_COMMIT`, and an artifact produced by successful
  no-credential CI for that exact revision. Branch names alone are insufficient.
- Verify the candidate-profile digest, source digests, migration checksum,
  exact schema hash, API artifact digest and a digest of the final frontend files.
  Reject stale or mixed artifacts. Rebuild after source changes, never substitute
  a candidate manifest into the ordinary baseline output folder.
- Keep candidate output isolated under `.build/customer-remediation-candidate/`.
  Existing baseline config validation rejects these paths/profile; add reviewed
  candidate-specific validation, rather than broadening the baseline allowlist.

## Required ordered gates

| Phase | Reuse / required evidence | Stop condition |
| --- | --- | --- |
| Read-only preflight | Existing `preflight`, inventory and Worker diagnosis; sanitized current versions, Access service-token policy checks, private R2 and domain ownership | Any unknown target, policy/configuration mismatch or credential scope failure |
| Migration approval | Exact SQL checksum, target DB, recovery evidence, approved write window and no active writes | Missing independent authorization, schema drift, partial objects or failed FK check |
| Migration operation | Apply only the approved additive SQL once; no initialization, reset, backfill or unrelated migration | Any unexpected write/schema result; no automatic retry of uncertain writes |
| Migration evidence | All 143 original app objects plus support schema unchanged, unchanged existing rows/counts/history, empty new tables, exact extended schema and FK check | Any mismatch; deployment remains blocked |
| Separate deployment approval | Exact candidate commit/profile and successful migration evidence | Approval for a different commit or SQL is insufficient |
| Both Worker dry runs | Candidate-specific configs validated against the same existing security/resource constraints | Any new binding, exposure, schedule or target |
| Backend upload and readiness | Upload once, inspect version/configuration, authenticated legacy frontend probe, exact release **and candidate profile**, full schema, R2, captured mail, MFA and monitoring | Fail immediately except existing bounded retry for healthy HTTP 200 with stale release identity |
| Frontend upload and final probes | Upload only after backend ready; inspect version; custom-domain runtime and existing Access negative/positive probes | Any failure; preserve failure stage/version evidence, no automatic redeploy/rollback |
| Acceptance | Fictional customers/assets, independent same-CVE records, refresh, assignment receipts, history, isolation, MFA | Capture only safe booleans/statuses in shared artifacts |

Never catch schema/readiness rejection and route through generic `migrate` or
`initialize`. Production-baseline readiness will reject an extended schema;
coordinate the separately approved migration/deployment window and prevent
ordinary baseline releases during it. Review an interrupted-activation recovery
plan before that window. After candidate writes, retain compatible readers and
prefer a forward fix; dropping scope/history tables is not a safe rollback.

The owner's next approval is review of this draft design/code and the protected
adapter implementation before it is enabled. That review is not authorization to
apply the migration or upload either Worker. Those remain separate later approvals.
