# Isolated D1 rehearsal — Approval A complete; Approval B pending

The eight databases and two encrypted backup packages now exist under completed
Approval A. Preserve them; do not allocate, export or download again. The actual
UUIDs, retained hashes, read-only evidence and remaining owner decisions are in
[Approval B prerequisites](approval-b-prerequisites.md). No import or rehearsal
SQL write has been authorized or executed. The procedure below describes later
approved execution, not permission to run it.

The [revised development Approval B request](development-approval-b.md) supersedes
the earlier demand for exhaustive external-credential exclusion for this one
disposable-test-data rehearsal. The owner accepts that uncertainty; it is never
recorded as verified exclusion. The exact replacement window and token change
remain proposed, and execution still requires separate Approval B.

This operator-run adapter is separate from the fixed production executor. It has
no create/export/import/delete/reset/deploy/resume API. No GitHub workflow invokes
it. Preparing this source and running local fictional tests does not authorize a
remote request. The original production manifest and all PR #269 staging pins stay
unchanged. Plan Z is never read, moved, overwritten, restored or deleted.

## Targets and approval sequence

Use account **`9706b4d98ad72884e67fd1eb875c8a61`** only. Each case needs a newly
created, independently approved UUID; use the existing exact UUIDs in the linked
prerequisite record. Never substitute
production `46710e51-7ca4-4571-b89c-921b9969de0b` or permanent staging
`fac61562-fc31-426d-8032-550aba63b7f6`. Both are hard denied, including under a
mislabelled account. All eight approved UUIDs must differ; metadata must match the
exact case name. Arbitrary database/SQL/endpoint inputs are not CLI options.

| Case | Exact proposed resource name | Starting data |
| --- | --- | --- |
| success | `cveharbor-prod-repair-restore-pr270` | Fresh production backup restored and independently verified |
| schema | `cveharbor-pr270-rehearsal-schema` | Reviewed synthetic SQL only |
| count | `cveharbor-pr270-rehearsal-count` | Reviewed synthetic SQL only |
| expiry | `cveharbor-pr270-rehearsal-expiry` | Reviewed synthetic SQL only |
| race | `cveharbor-pr270-rehearsal-race` | Reviewed synthetic SQL only |
| rejected | `cveharbor-pr270-rehearsal-rejected` | Reviewed synthetic SQL only |
| interrupt | `cveharbor-pr270-rehearsal-interrupt` | Reviewed synthetic SQL only |
| lost | `cveharbor-pr270-rehearsal-lost` | Reviewed synthetic SQL only |

Separate databases avoid dropping objects, deleting rows, resetting state or
replaying a consumed intent between cases. There is **no cleanup required between
tests**. Eight resources require a quota check, especially on the Free plan; stop
if current capacity is insufficient. Do not upgrade plans or reuse staging.

**Approval A: preparation and allocation.** Authorize the eight names above, private
storage/custody verification, creation and read-only isolation inventory, and a fresh
production bookmark/export encrypted to the owner. Source is production account
`aa99b9b15e0492302e4f6484b8d27bc2`, database
`46710e51-7ca4-4571-b89c-921b9969de0b`, baseline
`327bab011a4ffe3654aab618f859a8cdaef14aa7d4bbd03c0db96d4f7b0a225d`, active Worker
`07055fe8-f1ab-463f-97b2-372b458b6056`. Reverify source and an existing quiet window;
this approval does not authorize changing settings to obtain one. Capture can
temporarily affect availability/latency; record its start/end and provider limits.
Stop after evidence collection. No imports or rehearsal mutations under Approval A.

**Approval B: exact-UUID recovery and SQL rehearsal.** After creation, present each
UUID/name/account/creation receipt, backup/package hashes, exact source commit,
rehearsal and production manifest digests, restore/import file checksums, isolation
inventory and UTC window. Request explicit transfer of the fresh production copy
to the success UUID, initialization of the seven synthetic UUIDs, and the exact
case operations below. Bind the approved UUIDs and hashes in the private approval
JSON. No placeholders or “any database” authorization is accepted. The owner need
not assemble these inputs; the operator prepares them for review. This separation
preserves the distinction between completed capture/allocation and still-pending
restore verification and rehearsal authority.

Both approvals exclude production repair/resume/rollback, staging deployment,
customer-only remediation activation, security or environment changes and cleanup.

## Backup, encryption and restore procedure

Private destination: **`C:\CVEHarbor-Recovery\production\pr270\<capture-uuid>\`**.
Verify owner-only Windows ACLs, sync/ordinary-sharing exclusions, trusted admin
access, capacity and passphrase-encrypted key custody before creating a package.
The owner explicitly waived full disk encryption for this PC/test data on November
6: record `disk_encryption_status: unverified`, never `verified`. A separate owner
exception permits online/same-PC key custody at `D:\CVEHarbor-Recovery-Keys\pr270`,
with a separately held passphrase; this is not independent/offline recovery.
See [the exact exceptions, residual risks and local evidence](host-preparation.md).
POSIX chmod is not proof of Windows ACLs. A signed official OpenSSL installation
is available at `C:\CVEHarbor-Recovery\tools\OpenSSL-4.1.0\bin`; use process-local
PATH only. Do not invent custom encryption
or put a private key/passphrase into chat, CI or environment variables.

1. With Approval A, record a fresh Time Travel bookmark and schema/count/integrity
   snapshot privately. Use Cloudflare's supported D1 export tool/API with the exact
   source UUID. Keep the export SQL, raw bookmark and signed download URL private.
   The existing staging recovery runner and checkpoint-29 verifier have fixed
   staging targets and **must not be run or retargeted** for this production backup.
2. Build a private package with export SQL, account/DB/version, capture times,
   baseline schema, counts and independently computed per-table content digests,
   export SHA-256 and bookmark hash. Record SHA-256 over file bytes, not JSON Buffer
   serialization. Bound total retained/imported material to the approved size.
3. Encrypt with `package.mjs`, which reuses the existing
   `staging/recovery/crypto.mjs` CMS AES-256-GCM / RSA-OAEP SHA-256 implementation.
   It validates an approved RSA >=3072-bit certificate fingerprint and refuses an
   existing output. The private key stays encrypted in the approved D: folder.
   Example, after approval only:

   ```text
   node deployment/proposals/production-compatibility/procedure/rehearsal/package.mjs <private-package> <new-private-package.cms> <public-certificate.pem> <approved-fingerprint> <private-storage-evidence.json>
   ```

   The operator must explicitly confirm `REHEARSAL_PRIVATE_STORAGE_VERIFIED=true`.
   The wrapper does not delete plaintext. Record/read back ciphertext SHA-256, move
   a separately encrypted retained copy through the approved private channel, then
   retrieve that retained copy for the restore test. A same-PC copy is not independent
   disaster recovery. Decrypt with established OpenSSL CMS tooling on this explicitly
   excepted owner-controlled PC, prompting locally
   for the key password. Compare the recovered export hash to the approved original.
   A locally generated fresh SQL file is not evidence of backup recovery.
4. Under Approval B only, inspect the success target's empty schema and isolation,
   then import the recovered SQL once using the supported
   [D1 import interface](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/import/):
   `POST /accounts/9706b4d98ad72884e67fd1eb875c8a61/d1/database/<approved-uuid>/import`.
   Persist intent first; use `action:init` with file MD5, upload once to the returned
   private URL, then `action:ingest` with returned filename and matching MD5.
   Preserve SHA-256 as the security pin; MD5 is only the provider transfer field.
   Poll the same returned import bookmark for status; never resubmit ingest after
   an ambiguous outcome. Validate the upload destination before transferring data;
   never forward the API credential to a signed upload URL. Do not use a retrying
   SDK/CLI wrapper for import. If the bookmark/response is lost, stop for supported
   read-only reconciliation or provider assistance, not another import.
5. Independently compare the remote complete baseline, all table counts, private
   content digests, FK check and integrity results with the decrypted package before
   signing a restore receipt. No credentials, application Worker, cron or email
   paths may be attached. Initialize each negative-case target once with the exact
   generated `synthetic.sql` via the same controlled import procedure; its sole user
   is `pr270-fictional@example.invalid`. These seven targets never receive exports.

The adapter intentionally starts at a verified baseline. Creation, export and
import remain separately supervised supported provider operations, not hidden
capabilities of the test runner. An uncertain import or incomplete baseline blocks
`claim`; this adapter never completes/repairs an import automatically.

## Private execution inputs and commands

Generate/verify artifacts locally with `node .../rehearsal/artifacts.mjs` (use the
full directory above). `--write` is source preparation only, never an execution
step. The separate rehearsal manifest pins its adapter, log/encryption wrapper,
synthetic SQL and the unchanged production manifest. All prior rehearsal approvals
become stale if any executable changes.

Prepare `approval.json` in private storage with these exact fields:

```text
version: 1; approval_id: new UUID; source_sha: exact reviewed checkout
account: 9706b4d98ad72884e67fd1eb875c8a61
manifest_sha256: rehearsal artifacts() digest
production_manifest_sha256: 4dd094b957dc21421a0daf35f6e99b28cfac42ae60b26dee15bf2b6b12e5b42c
not_before / expires_at: integer UTC seconds, at most four hours apart
resources: one entry for EACH case listed above, containing:
  uuid, name, creation_receipt_sha256, counts_sha256, isolation_sha256
  fixture_sql_sha256: synthetic manifest hash for the seven fictional cases
recovery_evidence_sha256: independently verified private restore receipt hash
private_destination: C:\CVEHarbor-Recovery\production\pr270
private_storage_verified / no_bindings_or_delivery_credentials: true
storage_evidence: complete approved object described in host-preparation.md
cost_and_quota_checked: true
external_writers_excluded: true (normal policy), OR the exact exception below
max_incremental_usd: 5; max_total_bytes: 1000000000; max_rows_written: 1000000
```

Only for the eight retained PR270 UUIDs and the proposed November 6,
23:25 UTC–November 7, 03:25 UTC window, an owner-approved payload may instead contain:

```text
external_writers_excluded: false
external_writer_exception:
  id: pr270-disposable-test-data-20261107
  accepted_uncertainty: true
  inspected_workflows_do_not_target: true
  assessment_sha256: SHA-256 of the actual reviewed private operator assessment
```

`development-exception.mjs` checks the exact case-to-UUID mapping and window;
the existing approval digest covers this object and assessment hash. It does not
grant approval, alter production policy, or waive any other check. Missing or
mis-scoped exceptions fail before network access. Every exception phase records
accepted uncertainty with `external_writers_excluded:false` in the private journal.
Read-only reconciliation remains available after expiry, as under normal policy.

For inventory-only approval, counts/isolation/recovery hashes may be absent;
UUIDs, creation receipts, source and all other boundaries are still mandatory.
The creation receipt digest is SHA-256 of `JSON.stringify({account,uuid,name,created_at})`
in that field order, with the exact provider metadata timestamp. It is compared
again with live metadata, not accepted merely because it looks like a hash.
Inventory returns only private metadata evidence, not permission to import.
Then prepare the complete mutation approval for independent owner review. Set
`REHEARSAL_APPROVAL_SHA256` to its approved parsed-JSON/JSON.stringify digest from
the independent approval record; the adapter never sets that pin for itself.
This is an operator approval pin, not a digital signature or proof of actual
owner approval. Protect that record and the account-scoped credential in the
approved operator session. `CLOUDFLARE_ACCOUNT_ID` must be the isolated account;
`REHEARSAL_ENABLED=true` is additionally required for mutations. No live environment
variable is configured by this PR, and production reviewer gates remain unchanged.

Use the clean exact reviewed Git checkout. CLI computes its actual HEAD and refuses
tracked modifications. Use an existing private capture subdirectory for logs:

```text
node deployment/proposals/production-compatibility/procedure/rehearsal/adapter.mjs <case> <phase> <private-approval.json> <private-capture-directory>
```

Run one case at a time. Do not wrap commands in a retry loop or continue a script
after failure. The only deliberately parallel requests are the two approved race
requests. Every stage must finish or be reconciled before starting a different case.

| Case | Exact phase sequence after baseline import | Required evidence |
| --- | --- | --- |
| success | `inventory`, `claim`, `install`, `reconcile` | Exact 370 app definitions, 143 original definitions preserved, equal private content/counts, matching receipts, held=1/frozen=1/revision=0, zero leases/context, integrity/FK zero |
| schema | `inventory`, `claim`, `perturb`, `install` (reject), `reconcile` | New `unexpected_after_claim` table persists; no repair objects/installed receipt; all other pre-install definitions/counts unchanged |
| count | same as schema | One fictional remediation insert persists; installation rejected before any repair mutation |
| expiry | `inventory`, `claim`; wait beyond 15-second DB-clock claim expiry; `install` (reject), `reconcile` | Rejection uses actual remote clock. Outer owner approval must still be valid. No mocked remote clock or rewritten installation SQL |
| rejected | `inventory`, `claim` (intentionally omits start), `install` (reject), `reconcile` | Missing start cannot silently select zero rows; baseline preserved, no installed receipt |
| race | `inventory`, `claim`, `install`, `reconcile` | Concurrent exact batch and one fictional insert; preserve both request intervals, provider outcomes and resulting schema/counts. Independent review required for every ordering |
| interrupt | `inventory`, `claim`, `install`, `reconcile` | Client requests cancellation after 1 ms; it may arrive before or after server processing. Observe actual resulting state, never infer server cancellation from AbortError |
| lost | `inventory`, `claim`, `install`, `reconcile` | Deliberately discard the received provider response; reconcile committed/rejected state without another write. This is simulated caller response loss |

`install.sql` is read directly from the production procedure and submitted once,
unchanged, as `{sql,params:[]}` to the same D1 REST `/query` interface. No explicit
transaction wrapper, statement splitting or changed precondition is introduced.
The production target file/executor are untouched. Rehearsal claims are clearly
marked and bind the isolated UUID; they cannot serve as production receipts.

## Isolation, receipts, failure and evidence limits

Pages inventory uses `GET /pages/projects` first, then `?page=N`, leaving page size
to that endpoint. Workers retains its separate listing convention. Every Pages
response must contain an array and complete integer pagination metadata; page,
size, count, total count and total pages must agree. Totals/size must stay stable,
names must be unique, all declared pages must be read, and the final count must
match. Missing metadata, short intermediate pages, duplicates, drift, more than
100 pages or any provider error stop inventory. The request allowlist permits
only this Pages route and positive page numbers, not arbitrary queries or writes.
An empty list alone never proves completeness. Both production and preview
configurations of every project, including later pages, are checked for bindings.

November 6 diagnosis: `page=1&per_page=100` and `page=1&per_page=20` returned HTTP
400/code 8000024 (invalid list options). Independent GETs with no parameters,
`page=1`, `page=2`, `per_page=10` and `page=1&per_page=10` returned 200. This isolates
the observed parameter rejection; it does not establish a universal maximum size.
The current [Pages reference](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/list/)
documents optional page/per_page and response metadata, but no numeric size range;
its example size 20 did not work here. No automatic fallback after an error is used.
See [sanitized comparison and corrected adapter evidence](pages-inventory-evidence.json).

Live validation covered the actual empty Pages account and all eight targets,
using the existing unextended read-only token. Multi-page inventories, later-page
bindings and failures were tested locally with fictional provider responses.
Metadata checks detect incomplete results and count/size drift, but pagination is
not a transactional snapshot: same-count concurrent changes can evade it. Repeat
inventory before each phase and retain the separate external-writer attestation
or this exact owner-approved development exception;
absence of bindings does not prove absence of other account credentials or clients.

Before every phase the adapter checks exact DB name/UUID/size, paginated Workers
settings and active deployed versions, and Pages production/preview configurations.
Any binding to the target, incomplete inventory or changed approved isolation hash
blocks mutation. Under the normal policy, also independently verify no platform-dispatch scripts, indirect
writers, integration tokens, queues, scheduled jobs, restore automation or external
API clients can mutate it. The API inventory is not proof of credential absence or
a distributed lock; these exclusions are explicit operator attestations. Do not
change settings to achieve them without separate approval.
For the scoped development exception, unidentified credential consumers and the
unavailable dispatch inventory remain accepted uncertainties, not verified absences.
Inspected workflows must not target these eight UUIDs, and all live binding and
unexpected-change checks remain mandatory. A new known writer or unexpected change
stops work for reconciliation; no service is disabled without approval.

The private append-only JSONL records source approval/case/phase, request times,
SQL/parameter hashes, HTTP status, CF-Ray and provider usage, plus sanitized schema,
count and receipt hashes. It never logs SQL payloads, customer rows, tokens, raw
provider errors or raw bookmarks. Fsync occurs before each mutation. Exclusive local
phase files plus immutable `d1_pr270_rehearsal_attempts` plan/install claims reject
another installation even from a new process/approval. Losing a claim reply also
stops: do not delete a local claim to continue. Partial bootstrap, receipt mismatch,
failed logging, provider error or ambiguous write means read-only reconciliation.
Reconciliation remains available after approval expiry; it cannot resume or reset.

Preserve raw private provider/audit evidence through supported read-only access.
Compare the `before-install` snapshot with reconciliation, inspect exact definition
sets and ordered receipts, and independently sign case conclusions. The adapter
always reports `remote_atomicity_established:false`: aggregate snapshots and one
successful race are not proof of general isolation. A race that commits the insert
between a passed precondition and installed receipt is a failed safety contract.
Do not approve production if guard rejection leaves repair mutations, or if actual
isolation remains uncertain. Escalate for documented provider guarantees or a revised
execution mechanism. Local tests simulate partial execution without transactions;
they do not force Cloudflare to interrupt inside the unchanged batch.

## Cost, retention and cleanup scope

Combined ceiling: **US$5 incremental spend, 1 GB total restored/fixture/retained
remote data, one million billable rows written** across all eight targets. Check
plan/quota and estimate import/index/trigger costs before creation or upload. Count
provider usage across private logs/import receipts before each next phase. These
are operational ceilings, not provider hard caps; one request may exceed an estimate.
Stop for revised approval if size/cost cannot be bounded. No subscription upgrade,
R2 resource, public storage or credential/security change is included.
[D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/) must be rechecked
at execution; current account allowances are not established by local tests.

Retain encrypted backup/evidence at least 30 days after repair acceptance; review
the isolated databases after 48 hours following independent verification. These
are review dates, not deletion authorization. No automatic expiry or cleanup.
Later cleanup must separately name all eight UUIDs and approved private temporary
plaintext files, confirm evidence/custody retention, and authorize their removal.
Never delete the production database, permanent staging or the Plan Z backup.
