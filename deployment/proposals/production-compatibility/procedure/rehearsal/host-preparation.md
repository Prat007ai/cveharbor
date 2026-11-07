# PR #270 owner-PC recovery preparation — November 6, 2026

This record distinguishes owner authorization, machine observations and pending
verification. It does not authorize cloud allocation, capture, import, SQL writes,
production repair/resume, deployment, merge or cleanup. Plan Z is untouched.

## Explicit owner exceptions

The owner authorized local preparation without requiring or enabling BitLocker or
other full disk encryption because production currently contains only test data.
Record `disk_encryption_status: unverified`, with exception
`pr270-owner-test-data-no-full-disk-encryption-2026-11-06`. Do not describe encryption
as disabled or verified: the prior status query was denied and no setting changed.
This applies only to this PC and this PR's test-data rehearsal, not future customer
data, other environments or the general recovery policy.

The owner separately authorized encrypted key storage on D: instead of offline
custody, after being told it is a fixed drive on the same PC. Record exception
`pr270-owner-test-data-online-d-drive-custody-2026-11-06`, key directory
`D:\CVEHarbor-Recovery-Keys\pr270`, custody `passphrase-encrypted-online-same-pc`,
`offline_key_custody_verified: false` and `independent_custody_copy_verified: false`.
Loss or compromise of this PC can affect both package and key; this is not
independent disaster recovery. A separately retained passphrase remains required.
Revisit both exceptions before using real customer data.

## Observed local preparation

- Created `C:\CVEHarbor-Recovery` and `D:\CVEHarbor-Recovery-Keys` with protected
  owner-only DACLs. The pr270/custody/preparation descendants inherit only that
  owner's FullControl. No broad Users/Everyone/Authenticated Users grant exists.
  These ACLs do not defeat administrators, raw-disk access or malware in the owner
  session. Recheck ACLs and reject reparse points before use.
- Local sharing inventory showed administrative C$/D$/ADMIN$/IPC$ only; no ordinary
  SMB share overlaps the private folders. Administrative shares still exist and
  are not described as absent. Their settings were not changed.
- The observed OneDrive directory is outside both private roots; no registered
  overlapping sync root was found. OneDrive is running. The owner confirmed no
  managed backup/sync inclusion and trusted administrators. This is combined
  machine evidence plus owner attestation, not proof against every background
  agent. D: exclusion is confirmed separately in the owner setup prompt.
- Both private roots and data/custody directories are marked NotContentIndexed.
  This filesystem attribute is not proof that every third-party indexer obeys it.
- Approximately 244 GiB free on C: and 221 GiB on D: at preparation. Recheck before
  capture. No disk encryption, firewall, share or cloud setting changed.

## Trusted software

Installed a private administrative image of official OpenSSL 4.1.0, installer
revision 2, under `C:\CVEHarbor-Recovery\tools\OpenSSL-4.1.0`. MSI administrative
extraction completed with exit 0. This is a private runtime, not a globally
registered installation; system PATH, FIPS settings and existing applications are
unchanged. Use the bin directory in the operator process PATH only.

- [Official release](https://github.com/openssl/installer/releases/tag/publish%2F4.1.0-2)
- Asset: `OpenSSL-x64-hybridCRT-4.1.0.msi`
- Release/observed SHA-256: `59803cf501cf4e643a89310a143e964ec9c0432d83a92f3fc585a4fc5a15dff3`
- MSI, executable and installed DLL Authenticode status: Valid; signer
  `OpenSSL Software Services Czech, s.r.o.`, matching the official release publisher.
- Executable SHA-256: `266a8a13497bc8cb545cc57fff6f798544b6a6d646e1baf7ceb2f5ea1cbba022`
- Runtime: OpenSSL 4.1.0, VC-WIN64A-HYBRIDCRT, built November 4.

An earlier third-party download matched its vendor hash but lacked an Authenticode
signature. It was not executed. No unsigned installation or extra redistributable
was performed. Installed runtime files retain owner-only ACLs.

## Owner-only certificate setup and evidence

`owner-key-setup.ps1` is a local, interactive preparation script, not a remote
executor. Run only in the owner's visible console, never a captured agent PTY,
transcript or redirected session. The launcher must keep the parent session alive.
Its process-local module path avoids PowerShell 7/Windows PowerShell 5.1 module
resolution conflicts; no persistent execution policy or PATH change is needed.

It verifies software/ACLs and refuses existing outputs. OpenSSL generates a new
3072-bit RSA key encrypted with AES-256-CBC directly at
`D:\CVEHarbor-Recovery-Keys\pr270\recipient-key.encrypted.pem`. The owner enters
the passphrase at native prompts; no password argument, environment variable,
transcript or agent input is used. It creates a one-year public certificate at
`C:\CVEHarbor-Recovery\custody\recipient-cert.pem`, then tests authenticated CMS
AES-256-GCM/RSA-OAEP SHA-256 encryption/decryption using fictional text only.

The owner confirms separate passphrase custody, D: exclusions and trusted admin
access. Only public fingerprint, boolean results and non-secret paths are recorded
in `C:\CVEHarbor-Recovery\preparation\recipient-verification.json`. A prompt or
partial file is not successful setup. On failure preserve files, inspect metadata
and reconcile; do not overwrite keys or automatically retry. Private-key bytes and
passwords must never enter chat, GitHub or logs. Do not inspect the key contents to
diagnose a failure. A separate Ed25519 restore-attestation identity is still required
before Approval B; it is not generated or implicitly approved by this RSA setup.

**Verified certificate status:** owner completed setup; receipt time
`2026-11-06T17:42:50.5149453Z`. Public certificate independently parsed as RSA 3072,
valid November 6, 2026 17:42:31 UTC through November 6, 2027 17:42:31 UTC.
SHA-256 fingerprint:
`a6683aca09909c3e38cc8d2f277499b27df54784db09eb007b07d629f0291807`.
Fictional plaintext/recovered-file hashes match. Owner explicitly confirmed D:
exclusions/trusted admins and separate passphrase custody in the local prompt.
Private-key file permissions were checked using metadata only, without exposing
the key or passphrase. Retained private host evidence SHA-256:
`20a6902714929c42533d051e6e499b37a5e363b7c10c810d8e29937cc2d8dfb9`.

The reviewed packaging wrapper also encrypted a separate fictional file using
the unchanged CMS helper and the actual public certificate. Ciphertext SHA-256:
`e8519618debe60a07a693c19059dcc69e2838cbe4c3c2087494342c346181e49`.
That second ciphertext was not separately decrypted; the owner-console roundtrip
above establishes the tested key/algorithm compatibility. No real backup/recovery
or remote D1 behavior was tested. Full local backend suite: 451 passed, zero
failed/skipped, including 14 rehearsal tests. Generator reproduced unchanged
production manifest and installation SQL, with updated rehearsal manifest.

## Required storage evidence

`storage-policy.mjs` is enforced by both the rehearsal authorization and packaging
wrapper. `private_storage_verified=true` alone is insufficient. The private JSON
record must contain `version:1`, exact `destination` from production target.json,
`scope:pr270-test-data-rehearsal-on-owner-pc`, the exception/status/custody fields
above, and all these independently checked booleans true:

```text
owner_only_acl_verified, sync_exclusion_verified,
ordinary_sharing_exclusion_verified, trusted_administrative_access_confirmed,
capacity_verified, encrypted_packages_required, temporary_plaintext_inventory_required,
key_acl_verified, key_sync_and_sharing_exclusion_verified,
passphrase_separate_custody_confirmed, recipient_roundtrip_verified
```

Include the actual public `recipient_fingerprint_sha256` and `private_evidence_sha256`
over retained host/owner evidence. These are operator attestations, not automated
proof of OS settings. The rehearsal approval digest binds this object; the packaging
wrapper also checks the recipient matches. Missing booleans, different paths,
unapproved exceptions, or false claims of disk/offline verification fail closed.
No live authorization variable or production executor was changed.

## Plaintext inventory and cleanup

No production data has been captured. Setup creates only these fictional plaintext
files under the private preparation directory:

- `fictional-roundtrip.txt`
- `fictional-roundtrip-restored.txt`

The packaging-wrapper check also retained
`C:\CVEHarbor-Recovery\production\pr270\local-crypto-check-20261106\fictional.txt`.
All three contain the same fictional sentence only; no production records or
credentials. Their ciphertexts and receipts are retained. Nothing was deleted.

Keep their exact paths in the receipt. After future Approval A, separately inventory
each export SQL, raw bookmark/metadata, archive before encryption and any download
temporary file under the exact private capture UUID directory. Before Approval B,
inventory decrypted archives/SQL and comparison output. Configure process TEMP/TMP
to that private directory; avoid browser downloads into Downloads or synced paths.
Do not use a capture tool whose temporary destinations cannot be controlled.

Never retain unencrypted private keys. No plaintext cleanup runs automatically.
Request explicit exact-file cleanup only after ciphertext readback/hash verification
and required evidence retention. Ordinary deletion on SSD/unencrypted storage is
not guaranteed secure erasure; residual blocks, paging or crash dumps may persist.
The owner disk exception accepts this residual test-data risk, not permission to
disable security or delete Plan Z. Retain encrypted evidence at least 30 days after
repair acceptance; review isolated targets after 48 hours, with separate deletion
approval. New resources are not created by this local preparation.

## Quota and usage observation (not a reservation)

November 6 isolated account `9706b4d98ad72884e67fd1eb875c8a61`: 1/50,000 displayed
database slots, 1.04 MB/5 GB storage, 1.65k/50M writes, 385.31k/25B reads and $0
billable usage. Eight additions fit the observed quota without upgrade. Recheck
at allocation. At 17:20:50 UTC a production aggregate-only SELECT returned 68,419
rows and an index-adjusted import estimate of 192,497 writes. One 54.43 MB source
copy plus seven local fictional fixtures estimates 60.5 MB and 192,574 initial
import writes before repair/journal/provider overhead. Measure actual usage and
stop at the combined US$5/1 GB/one-million-write bounds. No hard spending cap is
configured and this estimate is not a zero-cost guarantee.
