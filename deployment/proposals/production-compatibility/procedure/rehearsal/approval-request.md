# Proposed isolated rehearsal approvals

Cloud allocation/capture is proposed for owner review only. The owner authorized
local software/folder/certificate preparation and the two narrow exceptions in
[host-preparation.md](host-preparation.md). No cloud resource, export, import,
remote test, cleanup, merge or deployment is authorized by that local preparation.

## Approval A — allocate and capture, then stop

Local preparation is verified in the host record. Approve only the final reviewed
PR #270 commit and rehearsal manifest digest presented with this request; earlier
rehearsal approvals are stale. Recipient certificate SHA-256 is
`a6683aca09909c3e38cc8d2f277499b27df54784db09eb007b07d629f0291807`.
Retained host evidence SHA-256 is
`20a6902714929c42533d051e6e499b37a5e363b7c10c810d8e29937cc2d8dfb9`.
Run within four hours of explicit Approval A, recording the exact UTC start/expiry
before the first cloud operation. Recheck source, quota, storage/certificate and
isolation prerequisites first; changed evidence requires reconciliation/reapproval.

Approve creation in account `9706b4d98ad72884e67fd1eb875c8a61` of these eight **new**
databases, subject to verified existing quota and the combined limits below:

- `cveharbor-prod-repair-restore-pr270`
- `cveharbor-pr270-rehearsal-schema`
- `cveharbor-pr270-rehearsal-count`
- `cveharbor-pr270-rehearsal-expiry`
- `cveharbor-pr270-rehearsal-race`
- `cveharbor-pr270-rehearsal-rejected`
- `cveharbor-pr270-rehearsal-interrupt`
- `cveharbor-pr270-rehearsal-lost`

Approve read-only identity/isolation checks and a fresh Time Travel bookmark and
SQL export of production account `aa99b9b15e0492302e4f6484b8d27bc2`, database
`46710e51-7ca4-4571-b89c-921b9969de0b`, after verifying the pinned Worker/baseline
and an existing quiet window. Do not change live settings to establish that window.
Export can temporarily affect availability; stop if provider limits or source drift
invalidate the capture plan.

Approve private capture to
`C:\CVEHarbor-Recovery\production\pr270\<capture-uuid>\`, only after verifying
owner-only ACLs, verified sync/ordinary-sharing exclusions, trusted administrative
access, sufficient capacity and the approved passphrase-encrypted RSA key custody
at `D:\CVEHarbor-Recovery-Keys\pr270`. Disk encryption remains **unverified**;
the owner explicitly waived it for this PC/test-data rehearsal on November 6.
The separately approved D: custody exception is online/same-PC, not independent
or offline recovery. Preserve both facts in the approved storage evidence.
Use the existing authenticated CMS encryption helper,
an approved RSA >=3072-bit certificate fingerprint and trusted OpenSSL tooling.
Use the signature/hash-verified private OpenSSL installation described in the host
record; prepend its bin directory only in the operator process, not system PATH.
The public certificate fingerprint and successful fictional decryption receipt
must be verified before this request is executable. A pending owner prompt is not
key-custody verification. Inventory temporary plaintext and request exact-file
cleanup later; do not claim ACLs or deletion protect against raw-disk access.
No plaintext, credentials or raw bookmark may enter chat, the repository or CI.

Keep every new database unbound to Workers/Pages and free of cron, queue, email,
application credentials and external writers. Preserve creation metadata and
inventory evidence. **Stop after reporting the allocated UUIDs, encrypted-package
hash and isolation evidence.** This approval does not authorize any import or
rehearsal SQL write.

## Approval B — exact-UUID restore and rehearsal, requested after A

The operator must return a completed, reviewable request containing all eight UUIDs
and creation receipt hashes, actual source commit, rehearsal manifest digest,
backup/export/restore hashes, verified isolation hashes, per-case baseline counts,
cost estimate and an explicit UTC execution window (maximum four hours).
No placeholder UUID is an executable approval.

Then request authorization to decrypt the retained backup copy privately and import
it once into the approved `success` UUID, independently verify private content,
schema/count/FK/integrity digests, and import only the pinned fictional fixture into
the seven negative-case UUIDs. Include any private isolated-copy export needed for
content comparison in that request. Execute only the case/phase matrix in README.md.
The installation batch must remain byte-for-byte pinned to
`2932acfd414c14e850d994b5aa31cc098aea6145ced7f32188c8b9edd18e7c46`.
The production procedure manifest remains
`4dd094b957dc21421a0daf35f6e99b28cfac42ae60b26dee15bf2b6b12e5b42c`.
Obtain the rehearsal digest from its committed manifest verifier, not a handwritten
value. Require independent review of provider evidence before any production request.

The deliberate test mutations are limited to the immutable rehearsal/repair journals,
reviewed repair schema held/frozen, one unexpected fictional table, and fictional
remediation inserts in their named cases. Concurrent/cancellation/lost-response cases
may leave uncertain or partial state. Stop for read-only reconciliation, without
automatic retry, reset, receipt repair, resume or rollback.

## Common bounds and exclusions

Combined ceiling: **US$5 incremental spend, 1 GB total remote data and one million
billable rows written** across all eight targets; check actual plan/quota and
import/index/trigger costs before starting. These are operator-enforced limits,
not a configured provider spending cap. No subscription upgrade or new R2 resource.

Retain encrypted recovery material/evidence at least 30 days after repair acceptance.
Review isolated resource retention after 48 hours following independent verification.
No cleanup is needed between cases. Deletion of any isolated UUID or temporary
plaintext requires a later explicit cleanup approval naming those exact items and
confirming encrypted evidence retention. No automatic expiry or deletion.

Neither approval covers production repair/resume/restore, staging deployment,
customer-only remediation activation, security/settings changes, PR merge, or
modification/deletion of the Plan Z backup. Production remains unrestored.
