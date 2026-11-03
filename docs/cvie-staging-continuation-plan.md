# Task 2C controlled schema continuation — preparation only

**No remote adoption, continuation, export, restore or deployment has been executed.** PR #243 remains draft and unmerged. This package starts from the independently verified ORIGINAL checkpoint 29 and reconciles it with the current integrated manifest using **two separately approved phases**. It preserves the stricter adoption/recovery gate added by the intervening review; there is no combined action that bypasses it.

## Starting evidence and production isolation

[Run #18, attempt 2](https://github.com/Prat007ai/cveharbor/actions/runs/41707547474/attempts/2), source `57069a36a98fed0b29a4b2fb537255e11e80ab90`, confirmed exact original checkpoint **29**: 18 empty tables, 10 explicit indexes, matching column/index definitions, no application triggers/views, valid foreign keys and quick check. It measured **406 reads, zero writes**, unchanged **233,472-byte** storage. [Sanitized verified evidence](cvie-evidence/original-checkpoint29-verified.json) records the original source/reference hashes and report identity.

The inherited production-probe issue was fixed **before further staging development** at `1a6225248548e38a8a26a26d5424decdc1367156`. Live confirmation probes require exact repository/main/push conditions; PRs retain local tests. The policy rejects missing/weakened guards, including the live checker appearing in another PR workflow. [Guard CI](https://github.com/Prat007ai/cveharbor/actions/runs/41727726725) explicitly skipped the production probe and activation. This change preserves those gates, protected environments, hourly publication and branch protection.

Only the existing staging account `9706b4d98ad72884e67fd1eb875c8a61` and D1 `cveharbor-accounts-staging` / `fac61562-fc31-426d-8032-550aba63b7f6` may be addressed. No new resources, environment, deployment, R2 publication, Access/binding/feature-flag change, synthetic/customer import, email or background processing is included.

## Reconciliation and approval boundaries

The integrated manifest includes staging bookkeeping, the original account schema, auxiliary schemas, both branches' distinct 0028/0029 migrations, 0030–0032, and generated recovery triggers. Its checkpoint 29 is **not** the verified original checkpoint 29. Do not use cursor 29 in the integrated bootstrap or replay the original base file.

### Phase A — `adopt-schema`: original 29 → integrated 37, then STOP

Use the existing separately guarded adoption operation and its [review record](reviews/permanent-staging-adoption.md). It requires:

- Exact approved commit, account/UUID, original reference and adoption SQL/specification hashes.
- A fresh, private, validated schema-and-data export, recoverable bookmark, writer-quiescence evidence and administrator attestation, captured within 60 minutes. No recovery export or retention verification is claimed to have been completed during this preparation.
- A fresh full read-only original-state diagnostic. Unknown objects, rows or definition/seed differences stop the action.
- One transactional request: three precondition guards followed by **eight** adoption statements. The SQL creates four staging operational tables and two indexes, then records receipts for the newly applied staging file and independently verified existing base file. **None of the original 29 statements is replayed.** The base receipt's timestamp records adoption, not the earlier physical execution time.

Exact SQL: [adopt-original-checkpoint29.sql](../staging/sql/adopt-original-checkpoint29.sql). The action verifies integrated checkpoint **37** and returns; it cannot migrate further, publish data or deploy a Worker. Expected state: 22 application tables, 12 explicit indexes, two accurate ledger rows, no application triggers/views and unchanged original objects. Expected schema fingerprint: `fb8f3f8dedc0c70181cfa6c7ca3b1a20813424ddbf3dec62446c5f9c334b36e2`.

Do not set a resume cursor for adoption. A failed/lost response triggers read-only reconciliation, never a repeated write. Checkpoint 37 is a proposed result, **not currently installed**.

### Phase B — `migrate`: verified integrated 37 → 740, then STOP

Only after Phase A evidence is accepted and this phase is separately approved, set cursor **37** with the existing integrated plan digest. Capture and validate a **new checkpoint-37 private recovery package** using `python staging/scripts/verify-recovery-export.py --checkpoint 37 --export <private-export.sql> --report <new-private-report.json>`. The default/checkpoint-29 validator remains available for adoption; neither validator contacts Cloudflare. The original checkpoint-29 recovery attestation cannot authorize this phase.

The phase executes **34 remaining batches / 703 statements**. Its first file is `account-backend/totp-schema.sql`. It follows the explicit manifest order through fourteen auxiliary files, 0016–0027, Phase 1's `0028_unified_findings`, `0029_finding_assignment_links`, 0030 status notifications, 0031 remediation integrity, 0032 recovery controls, CVIE's separate 0028 source efficiency and 0029 registry, then 297 generated recovery guards. Never sort by numeric filename prefix.

Every original table/index is preserved in local tests. Checked-in transformations/seeds are included; synthetic or production CVE/customer data is not. Migration 0030 explicitly drops/replaces `review_status_progress`, a trigger introduced by 0027 within this same continuation. It does not remove an object present in the original verified schema. Review that replacement in the original SQL. Recovery schema/guards do not enable scheduled jobs, provider fetches, mail delivery or feature flags.

Final expected state: **102 application tables, 66 explicit indexes, 344 triggers, one view**, excluding SQLite/Cloudflare internal metadata; **35** correctly ordered/checksummed migration receipts; expected built-in identity/source/maintenance/recovery seeds; empty customer/session/notification/staging-mail/job data. Final schema fingerprint: `0627e365f619cf749b34ffcf03fc9aa8db92d38385401436b63121d755bddb7f`.

The protected migration step receives only the staging API, Access and recovery-evidence secrets. It skips package rebuilds, R2/publisher credentials and the general release step. The dispatcher remains mutually exclusive: successful migration returns without reaching upload/publication code.

## Exact SQL checksums and reproducible review

[Machine-readable reconciliation and all batch digests](cvie-evidence/continuation-review.v1.json) lists all 35 new batches: eight adoption statements plus 703 remaining statements = **711 total newly executed statements**, divided across two approvals. Every source-file hash, executable SQL hash (including receipts), statement count and checkpoint range is included. The [integrated manifest](../staging/migrations.v1.json) remains unchanged. No application SQL source was edited.

| Artifact | SHA-256 |
| --- | --- |
| Integrated runtime execution plan, used by both phases | `a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3` |
| Adoption specification | `7ed30868dae48623caaccd9f1bead405333785b7b8c888f0308fb0b11ffe3eea` |
| Eight-statement adoption SQL | `e0e1688936703b027a39b58e924ac05313b55a552436f4950dc60954fd7ae7b8` |
| Complete guarded adoption request | `526b138194b266db8925271144744d1e13e3e32ee9abd99f323c0cfe05a131f9` |
| Phase-B SQL review aggregate (703 statements; NOT a single execution request) | `7a7f0b3d291b2f13bcf8b8ce414de44c2c66989c08caaa58f76b767000139189` |
| Generated recovery trigger SQL | `bb57640c035218f08ab80eaa65fd3d73d3254af26590fb02a756bc657301b3d1` |

Reproduce without credentials:

```sh
python staging/scripts/continuation-review.py
node staging/scripts/prepare-adoption.mjs
node --test staging/tests/*.test.mjs
```

The review builder reconstructs the original baseline, applies the exact eight-statement adoption locally, verifies its equivalence to integrated checkpoint 37, applies all remaining SQL and proves exact final schema/seed/receipt equivalence to a clean integrated installation. It emits `continuation-summary.json`, `continuation-00.sql` … `continuation-34.sql`, and `continuation-phase-b-review.sql` under ignored `.build/schema/`; CI publishes them. The reconciliation fingerprint is review evidence, **not** a runtime approval digest. Runtime approval always uses the integrated digest above. There is no `continue-schema` operation.

Local validation passed **85 staging test groups across 20 test files** and **26 workflow-policy tests**. The private export validator additionally accepts valid checkpoint-29/37 dumps and rejects old-state, data, constraint, receipt and external-file-access cases. Validation uses actual SQLite SQL, per-statement foreign-key checks and final integrity, with conservative published D1 limits plus workerd's five-term compound SELECT cap. Individual source SQL and guards remain within D1's 100 KB limit. Count reads remain separate one-table SELECTs, transported in batches of at most five; no compound UNION is introduced. The migration client is paced to approximately three requests/second to reduce management API pressure. [D1 limits](https://developers.cloudflare.com/d1/platform/limits/) still apply to each statement and the entire 30-second batch call.

## Recovery gate, metrics and failure behavior

The existing adoption recovery gate is retained. Phase B now enforces equivalent evidence **before network access** and revalidates its freshness before every write batch. It binds the private export digest, recoverable bookmark, writer quiescence, exact source commit, integrated plan digest, start checkpoint and schema fingerprint. A missing, stale, cross-account, different-plan or different-state package stops execution. Only evidence/bookmark hashes are logged; private locations and raw bookmarks are not published. Administrator attestations are explicitly not claims that the executor independently downloaded or restore-tested a private export.

Codex will handle technical capture/validation through an approved secure execution path; owner involvement is limited to export-window/private-destination authorization and account actions that the connector cannot perform. No owner console SQL troubleshooting is required. The private recovery export/availability prerequisites remain outstanding; preparing this plan does not waive them. Export may temporarily affect D1 availability, so its window also needs approval. No restore/reset/import is pre-authorized.

Phase A limits remain 100,000 observed reads, 100 writes, 100,000,000 storage bytes. Phase B limits remain **1,000,000 reads, 100,000 writes, 100,000,000 storage bytes**. Record D1 `rows_read`, `rows_written`, duration and size for every returned result, separating migration/guard costs from verification, and initial/final/peak storage/delta. Missing or failed-response counters make totals incomplete/lower bounds, never zero estimates. Local harness counters are synthetic, not predictions of Cloudflare billing. The existing job timeout remains 30 minutes.

Each write batch contains schema, count and seed-value preconditions. After each source file, read back the expected checkpoint and verify foreign keys; end with D1 quick check, exact final objects/data/ledger, unchanged Worker/Access fingerprints and authentication boundary probes. No application session, fixture or background job is created.

Any failure, ambiguity, missing metrics, state change, expired evidence or limit breach stops further writes. One read-only reconciliation reports actual observed state and completeness, never stale checkpoint matches. No automatic retry, resume, receipt synthesis, rollback, table reset, resource recreation or restore occurs. One in-flight batch can cross a stop threshold before the response is available. A later continuation requires explicit review of its matching checkpoint and fresh recovery evidence; never guess a cursor or repeat adoption.

## Approval settings (do not configure or run yet)

**First approval scope:** `adopt-schema` at the final implementation commit, with the existing staging account/UUID, valid private recovery package, and:

```text
CF_STAGING_APPROVED_COMMIT=<full reviewed implementation commit>
CF_STAGING_PROVISION_ACTION=adopt-schema
CF_STAGING_ADOPTION_SHA256=7ed30868dae48623caaccd9f1bead405333785b7b8c888f0308fb0b11ffe3eea
CF_STAGING_SCHEMA_PLAN_SHA256=a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3
CF_STAGING_SCHEMA_RESUME_STEP=<unset/empty>
```

Retain the adoption-specific recovery evidence format in its existing review record. The action then stops at 37 for review.

**Later, separate approval scope:** `migrate` at the reviewed implementation commit, with the same runtime plan digest, `CF_STAGING_SCHEMA_RESUME_STEP=37`, and a fresh **migration-specific** `CF_STAGING_RECOVERY_EVIDENCE` environment secret:

```json
{
  "operation": "migrate",
  "account": "9706b4d98ad72884e67fd1eb875c8a61",
  "database_id": "fac61562-fc31-426d-8032-550aba63b7f6",
  "source_sha": "<exact reviewed implementation commit>",
  "execution_plan_sha256": "a4ad0b27ff77266706693bf34f0880088b0bfe12139a583cca518975981a0fc3",
  "start_step": 37,
  "start_schema_sha256": "fb8f3f8dedc0c70181cfa6c7ca3b1a20813424ddbf3dec62446c5f9c334b36e2",
  "captured_at": "<actual UTC RFC3339 capture time>",
  "bookmark": "<verified private recovery bookmark>",
  "export_sha256": "<actual private export SHA-256>",
  "private_export_reference": "<private encrypted backup reference>",
  "writers_quiesced": true,
  "export_validated": true,
  "restore_available": true
}
```

Never paste this secret or a private export into chat or repository artifacts. No variables/secrets have been changed by this preparation. No protected write-job dispatch/rerun has been initiated.

After schema acceptance, synthetic onboarding, immediate CVE retrieval, matching, tenant isolation and D1-efficiency testing are separately controlled. Validation with CVIE registry/fast-evidence flags enabled remains required; flag activation and any staging Worker deployment need separate approval.
