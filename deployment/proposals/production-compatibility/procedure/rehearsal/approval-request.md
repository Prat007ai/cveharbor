# Proposed isolated rehearsal approvals

Prepared for owner review only. No resource, export, import, remote test, cleanup,
setting change, merge or deployment has been performed. The current authorization
covers source preparation and local fictional tests only.

## Approval A — allocate and capture, then stop

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
disk encryption, owner-only ACLs, no sync/sharing, sufficient capacity and offline
RSA recovery-key custody. Use the existing authenticated CMS encryption helper,
an approved RSA >=3072-bit certificate fingerprint and trusted OpenSSL tooling.
The required OpenSSL executable is currently unavailable on this host's PATH.
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
