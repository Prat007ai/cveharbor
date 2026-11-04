# Optional R2 staging recovery: separate future review

> Not part of the approved checkpoint 29 → 37 adoption. Retain the original
> private administrator-machine bookmark/export/local-restore procedure and
> `CF_STAGING_RECOVERY_EVIDENCE` at approved commit
> `545a7b46bdcb77b99f2bc35bd1bb938e7add93a7`; see the
> [coordinated execution procedure](permanent-staging-adoption.md#coordinated-execution-of-the-approved-historical-commit).
> The instructions below describe an optional future mechanism, not prerequisites
> for the current adoption. Do not run these operations or configure new resources
> to complete the current adoption.

The current maintenance state is incompatible with this mechanism's starting
assumptions: `recovery-snapshot` requires two associated policies (Allow and
Service Auth), while `recovery-capture`/`recovery-verify` require one explicit
Block/Everyone policy. The owner reports zero associated policies. Do not change
Access to satisfy these checks. Supporting an already-established maintenance
window requires separate code review and tests; any snapshot of that state must
not be mislabeled as the original pre-maintenance configuration. The existing
code remains unchanged. Its signed receipt does not automatically populate
the adoption recovery-evidence secret.

Prepared only. PR #243 stays draft/unmerged. Use the existing `cvie-staging.yml`
and `cloudflare-cvie-staging` environment; no credentials enter Codex. No new
workflow, execution host, Worker binding, Access write, database schema change,
production request, export or bucket creation is authorized by implementation.
The continuation plan and all SQL hashes remain unchanged.

## Operations and sequencing

All four operations run in a **separate recovery job**. The release job excludes
`recovery-*` dispatches and commits marked `[staging-recovery]`. Job guards use
GitHub event/input data, never environment variables unavailable before startup. Both share `cveharbor-permanent-staging` concurrency. Recovery has no
artifact upload, cache, deployment/migration tool or release dispatcher. An initial
push/PR never receives credentials: an exact-source manual dispatch or marked-push
rerun and environment review are required. Source/operation/target authorization
runs before credentials reach the recovery executable. Existing production probe
and hourly publication guards remain unchanged.

1. **recovery-inventory**: account/database identity; metadata inventory of all
   staging buckets except the application intelligence bucket; managed/custom
   exposure and Worker binding checks; original checkpoint-29 read-only SQL;
   current bookmark availability; exact staging Access app/policy IDs, decisions
   and precedence (no email selectors or token IDs in logs). No export, object
   write, policy change or creation. Bucket suitability is a candidate finding:
   privately confirm its intended purpose, retention and other access before reuse.
   Incomplete/unauthorized inventory stops rather than claiming no bucket exists.
2. Review inventory. Approve any required bucket/token creation separately.
3. **recovery-snapshot**: requires approved bucket/recipient. Encrypt full original
   Access app/policies, Worker state and restoration fingerprints directly to a
   unique private R2 object. No export or Access change. Download and decrypt this
   snapshot on the offline key-holder device **before** approving maintenance.
4. Separately approve the exact Access diff against that snapshot. Apply using the
   existing authorized account operator; this executable has no Access-write path
   and does not require broader Access credentials. Record private writer/session
   drain evidence and the bounded maintenance authorization below.
5. **recovery-capture**: verify identity, unchanged Worker fingerprints, exclusive
   Block/Everyone policy, anonymous/service-token denial, administrator evidence
   for existing human sessions/direct API writers/drain, checkpoint 29, current
   bookmark and private snapshot checksum. Export **once**, full schema+data.
   Subsequent POSTs poll the returned export cursor; they are not retries of a
   failed/ambiguous export. Provider messages and signed URLs are never printed.
   Download without API credentials or redirects from the signed R2 endpoint.
   Restore/check SQL locally, then encrypt the SQL, bookmark and private evidence.
   PUT an immutable object (`If-None-Match: *`), GET it and compare ciphertext.
   Recheck checkpoint 29/bookmark and maintenance. Status remains **offline
   decryption/restore pending**; upload success is never sufficient.
6. Download the actual `checkpoint29.cms` object using the existing Cloudflare
   dashboard on the key-holder device. Run the offline verifier below. It receives
   **no Cloudflare or GitHub credentials**. It decrypts the downloaded bytes, checks
   export SHA, restores into isolated temporary SQLite, checks exact schema,
   constraints/index metadata, empty tables, foreign keys and full integrity, then
   signs an exact package/commit/run-bound receipt with the offline key.
7. Put receipt/signature into the same protected GitHub environment, then approve
   **recovery-verify**. It validates the signature with the public certificate,
   matches the ciphertext downloaded from R2, rejects old/cross-account receipts,
   rechecks live checkpoint 29 and unchanged bookmark under isolation, and reports
   recovery readiness. It does not populate migration authorization or execute SQL
   writes. A remote Time Travel restore is **not** tested or authorized.
8. End the export-only maintenance window by restoring Access as described below.
   Do not keep staging blocked indefinitely while waiting for migration approval.
   Adoption/migration remain separate approvals with fresh recovery evidence.

## Storage proposal: inspect before creating

Prefer an existing suitable **dedicated recovery** bucket in staging account
`9706b4d98ad72884e67fd1eb875c8a61`. Never use
`cveharbor-intelligence-staging` or a production bucket. No actual live bucket
inventory has been performed by this implementation.

If inventory finds no suitable bucket, proposed configuration for separate approval:

- Name `cveharbor-recovery-staging`; same existing staging account; R2 Standard
  storage, automatic location (no unsupported jurisdiction change).
- r2.dev managed public access **off**, custom domains **none**, CORS **none**,
  no Worker bindings, no automatic expiry/deletion or event notifications.
- Dedicated **Object Read & Write** R2 credentials restricted to this bucket only;
  no account administration, bucket creation/deletion, other bucket or production
  permissions. R2's bucket-level object token can technically delete objects;
  this executor implements only GET and conditional PUT, never DELETE/list/overwrite.
  Do not reuse/widen publisher credentials. Creation/retention changes remain
  separate approvals. Object storage/request costs require owner acceptance.
- Object names are `recovery/v1/<approved-commit>/<run-id>-<attempt>/snapshot.cms`
  and `.../checkpoint29.cms`. These are encrypted files, not application snapshots.
  No key material is uploaded. Do not use public or pre-signed sharing links.

## Offline key custody is a real prerequisite

Use an owner-held **RSA >=3072-bit encryption/signing certificate**, with a
passphrase-encrypted private key on existing encrypted offline storage. Retain a
second encrypted copy in a separate controlled offline location; retain the
passphrase/recovery instructions independently in the owner's private vault.
Neither the private key nor its passphrase belongs in GitHub, Cloudflare, chat,
Codex, R2 or workflow artifacts. No real recovery key has been generated or custody
confirmed by this implementation. Public certificate/fingerprint alone is not
proof of custody; test the retained key/copy and explicitly confirm custody before
setting the protected confirmation variable.

Example commands **on the key-holder's offline device only** (interactive password
prompts, no passwords in arguments):

```sh
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -aes-256-cbc -out recovery-key.pem
openssl req -new -x509 -sha256 -key recovery-key.pem -out recovery-cert.pem -days 730 -subj '/CN=CVEHarbor staging recovery/' -addext 'keyUsage=critical,digitalSignature,keyEncipherment'
openssl x509 -in recovery-cert.pem -noout -fingerprint -sha256
```

Runner encryption is standard OpenSSL CMS AuthEnvelopedData with AES-256-GCM and
RSA-OAEP/SHA-256 key wrapping, to this public certificate. Offline decryption uses standard
OpenSSL. Preserve the certificate, exact reviewed verifier checkout and recovery
instructions with the offline copies. Loss of the private key/passphrase makes
R2 ciphertext unrecoverable; R2 credentials alone cannot decrypt it.

## Configuration in the existing protected environment

For every operation retain the exact existing staging account and database UUID
`fac61562-fc31-426d-8032-550aba63b7f6`, set `CF_STAGING_APPROVED_COMMIT` to the reviewed
implementation SHA and `CF_STAGING_PROVISION_ACTION` to that one operation.
`recovery-inventory` needs only the existing `CF_STAGING_API_TOKEN` and no R2 keys.
Management permission is metadata/read plus D1 reads/export; the executor's
allowlist does not grant access beyond the token. If denied, stop and report;
never broaden token scope automatically. The current management token's R2
metadata read must permit the inventory; its presence in documentation does not
prove live permission. No Access Edit permission is needed by this workflow.

Additional environment **variables** for later separately approved operations:

- `CF_STAGING_RECOVERY_BUCKET`: approved dedicated bucket.
- `CF_STAGING_RECOVERY_CERT_PEM`: public PEM certificate only.
- `CF_STAGING_RECOVERY_CERT_SHA256`: lowercase 64-hex certificate SHA-256 (no colons).
- `CF_STAGING_RECOVERY_KEY_CUSTODY_CONFIRMED=true`: owner confirmation only after
  offline key retention/copy checks. This is not an automated custody claim.
- `CF_STAGING_RECOVERY_SNAPSHOT_KEY` and `CF_STAGING_RECOVERY_SNAPSHOT_SHA256`:
  exact encrypted snapshot object key/checksum from its private review.

Additional environment **secrets** (never put values in PRs/chat/artifacts):

- `CF_STAGING_RECOVERY_R2_ACCESS_KEY_ID`, `CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY`:
  dedicated bucket-scoped pair.
- `CF_STAGING_RECOVERY_ISOLATION`: private maintenance record below.
- `CF_STAGING_RECOVERY_RESTORE_RECEIPT`, `CF_STAGING_RECOVERY_RESTORE_SIGNATURE`:
  offline verifier's exact JSON bytes and base64 signature.

Existing Access client credentials are used only to confirm maintenance denies
service authentication; they are not sent to any backup/download endpoint.

## Exact Access proposal and restoration

Live IDs and original app/policy fingerprints must come from inventory/snapshot;
there is no assumed/fabricated Access ID. The expected existing app covers only
`cveharbor-site-staging.cveharbor-staging.workers.dev`, with one human Allow and
one Service Auth (`non_identity`) policy. Unexpected additional/path applications,
Bypass paths, public backend ingress, events or writers stop the process.

For a separately approved diff **against that live snapshot**:

1. Preserve the complete original app/policies and ordered policy associations
   privately, including selector contents and session settings. Do not delete or
   edit shared/reusable policy objects.
2. Replace associations on this staging app only with an app-specific temporary
   policy: `decision: block`, `include: [{everyone: {}}]`, `exclude: []`,
   `require: []`. Detach Allow/Service Auth associations; a Block rule alongside
   Service Auth/Bypass is not adequate isolation.
3. Revoke sessions **for this application only**. Verify anonymous, an existing
   human session and the existing service token are all denied. Stop direct D1
   console/API writers, other management clients and pending mutation jobs; verify
   in-flight invocations/background work drained using logs. Access does not block
   management API writers. Empty tables or a quiet bookmark are not proof of drain.
4. After export-only verification (or a safe stop), restore the exact original
   app settings/associations/precedence from the decrypted snapshot. Retain
   protection throughout the transition; never leave the app without protection.
   Remove only the temporary app-specific policy when no longer associated.
5. Read back and compare original effective configuration, ignoring server-generated
   timestamps. Confirm human/service authentication, anonymous/forged-token denial,
   asset protection and API session boundary. Revoked sessions cannot be restored:
   reviewers log in again. If restoration fails, keep the maintenance block and
   report; do not add bypass or expose the backend.

No Access change is implemented by the recovery executable. Exact live IDs/diff
remain a separate approval, not authorization to apply this generic proposal.

The private isolation JSON includes exact account/database/source, snapshot digest,
original Access and Worker fingerprints, evidence hash and application ID:

```json
{
  "account": "9706b4d98ad72884e67fd1eb875c8a61",
  "database_id": "fac61562-fc31-426d-8032-550aba63b7f6",
  "source_sha": "<approved implementation SHA>",
  "snapshot_sha256": "<encrypted snapshot SHA-256>",
  "window_start": "<actual approved RFC3339 start>",
  "window_end": "<actual approved end, no more than 30 minutes later>",
  "observed_at": "<actual fresh observation, at most 15 minutes old>",
  "access_app_id": "<live staging application UUID>",
  "original_access_sha256": "<snapshot original configuration fingerprint>",
  "worker_state_sha256": "<snapshot worker fingerprint>",
  "drain_evidence_sha256": "<private log/operator evidence fingerprint>",
  "non_access_writers_quiesced": true,
  "invocations_drained": true,
  "human_session_denied": true,
  "application_sessions_revoked": true,
  "no_other_mutation_jobs": true,
  "all_ingress_identified": true
}
```

These administrator attestations do not pretend to be independently downloaded
invocation logs. The executor independently checks the observable configuration,
service/anonymous denial, state and bookmark. Missing writer evidence blocks export.

## Secure temporary storage and offline validation

Before recovery credentials are released the isolated hosted job disables swap.
Plaintext is kept under a mode-0700 `/dev/shm/cvie-recovery-*` directory on verified
tmpfs; require at least 512 MiB free and conservative database-size-based headroom.
Abort if unavailable. Private child processes receive no Cloudflare/R2 credentials;
SQLite/OpenSSL temp paths point there too. No plaintext disk fallback exists. Files
are removed on normal/error exit and an `always()` cleanup step; forced runner
termination relies on destruction of its ephemeral memory-backed filesystem.
Cleanup is not advertised as a secure erase of persistent disks. Disable workflow
rerun/debug tracing; the program never prints provider errors, SQL or signed URLs.

On the key-holder device, use an encrypted working volume outside any checkout.
Download the actual object from R2, keep it private, then:

```sh
python staging/recovery/offline-restore.py --package /private/checkpoint29.cms --cert /private/recovery-cert.pem --key /offline/recovery-key.pem --work /encrypted/work --receipt /private/restore-receipt.json --signature /private/restore-signature.txt --encrypted-storage-confirmed
```

The helper prompts locally for an encrypted PEM key password, never passes it in
arguments and has no network code. Restore failure or invalid ciphertext produces
no signed receipt. Keep the SQL/bookmark in the encrypted package; for an approved
future recovery, decrypt with `openssl cms -decrypt -binary -inform DER` on that
device. Any remote Time Travel restore or SQL import needs separate approval.

Maintenance checks run before every management request, before export/poll/download,
before upload, and at the end. Window max 30 minutes; writer observation max 15
minutes; signed restore receipt and capture max 60 minutes. Individual calls have
bounded timeouts; one in-flight call can cross a deadline, so the job stops at its
next check and cannot claim readiness. Never fabricate timestamps or extend a
window while an operation runs. Plan offline transfer/verification within the
window; otherwise stop, restore Access and arrange a new approved window/recapture.
The existing adoption/migration gates still require fresh evidence immediately
before writes. `recovery-verify` does not authorize them or install a hold.

## Local validation

Passed: ten new recovery/security scenarios (real CMS encryption, downloaded-byte
decryption, SQLite restore, encrypted private-key support, altered ciphertext,
receipt forgery/expiry/binding, writer/window failures, routing/credential boundaries
and sanitized failure logs); all 21 staging test files; 31 workflow-policy tests;
workflow policy across 38 files; staging build and bundle checks. All cloud clients
were fixtures. No live bucket inventory, Access change, export or database write
was performed by these tests. Native runtime and Wrangler checks run in credential-free
GitHub preparation; protected recovery/release jobs remain skipped on initial push.
