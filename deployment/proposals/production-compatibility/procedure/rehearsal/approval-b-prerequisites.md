# Approval B prerequisites — decisions pending, no execution authority

Approval A completed under reviewed commit `6255b12d89b355f8b4bb203fa1af214abe93edcc`.
Allocation, export and download must not be repeated. This source update does not
invalidate the completed A record or replace its UUIDs/packages. It does require
independent review of the new executable rehearsal digest before Approval B.
Production remains unrestored; staging deployment and customer-only remediation
remain deferred. Production SQL/executor/manifest and Plan Z are unchanged.

## Actual retained inputs

Account: `9706b4d98ad72884e67fd1eb875c8a61`. Names remain those in
[approval-request.md](approval-request.md). API metadata confirms these existing
resources; all were 12,288 bytes on November 6. No remote SQL was used in this check.

| Case | Existing UUID | Exact creation time UTC | Creation receipt SHA-256 |
| --- | --- | --- | --- |
| success | `84dab6e9-9344-4e0f-a79a-4f0b43395754` | `2026-11-06T17:58:39.183Z` | `34c78ed5a56cab10f998a6a2d89c3da534c2b1a32aaac1192ef9451b0a1da720` |
| schema | `9f106efd-f5ae-4401-8c50-a4c80c53b90e` | `2026-11-06T18:00:44.555Z` | `acd9ef076f190846823ae36f8c232f6af234bc377e2a0ddfa70766f25659dff7` |
| count | `5d2e6500-350c-4228-9fe4-48c37f755e7d` | `2026-11-06T18:01:22.407Z` | `781fb49b7c27416984a7527bb356d68cd5ec23f62523743fb74e4adb97fe6107` |
| expiry | `39adff8b-b689-45f6-ba3a-c6005ec86b3f` | `2026-11-06T18:02:05.334Z` | `042ec9f55f69f6c4f1a99485645ab44b21b38e71ed1ee6818b34929dbc14e695` |
| race | `b098f98c-bb9f-4e50-95fc-177ac7c2582f` | `2026-11-06T18:02:36.647Z` | `00f18a03126b41ff7c189682e5686547a9a3dc8c7cc1f62e7dea16a41892753f` |
| rejected | `3ddd25d0-b5c7-4597-9a4c-02bb9ba1c697` | `2026-11-06T18:03:07.407Z` | `05f01fedc380390d9095963802fa489f8dea4081acd49256344bf239b8ce061c` |
| interrupt | `477cb173-2f84-4786-baa1-6bba51fd7937` | `2026-11-06T18:03:25.655Z` | `367b266b2f7657119deaca2d4082e1b443fcfcf93a8ecd7663102147112007e0` |
| lost | `d7eb48ca-2023-420d-a5d3-c9cc0360b49c` | `2026-11-06T18:03:57.164Z` | `cd313284440f86947452186d99f1542ffabebe058d04c801aaa620bf8168311d` |

Retained capture directory:
`C:\CVEHarbor-Recovery\production\pr270\b1217e27-28fb-40ec-9bb4-4addb5c40f40`.
Both encrypted packages are 46,271,099 bytes. Neither is an independent off-PC copy.

- Primary `backup.tar.cms`: `168875f114d0dbf745ae5c5bce53b18ed08540a7ea6cfcecfdd024cd75388eea`.
- Retained `retained/backup-retained.tar.cms`: `16b8ca2e958c6b5bfec96af76839cf1463842aeb81d6fcb97b83625fe01b0987`.
- Export SQL: `f6cc1bf56d48986aad95f890a2fdefdcd1fb5199e215c001598087ac503d92a8`.
- Synthetic SQL: `1ebc87b41db5a6698cf40bcae258ba16c7beda3a2e6c8ffe308e4008f25dfcb6`.
- New rehearsal manifest: `3e1cd5ee644ec79b9aff07d5ee1dfada9048315dcf6fcfbd90a135382a2a211d`.
- Unchanged production manifest: `4dd094b957dc21421a0daf35f6e99b28cfac42ae60b26dee15bf2b6b12e5b42c`.
- Unchanged installation batch: `2932acfd414c14e850d994b5aa31cc098aea6145ced7f32188c8b9edd18e7c46`.
- Live isolation digest for every case: `8543e3bca0a9388107cf785dc2ab63572404fc20792c74c942f6e2ffaec0e4df`.

All 68 original A evidence files reproduced their hashes. See
[sanitized live evidence](pages-inventory-evidence.json) for timestamps, creation
receipts and pagination observations. The eight corrected `client.isolation()` calls
passed on November 6, 19:16:38–19:16:57 UTC. This was 73 GET requests, zero SQL
requests. Full `authorize()` was **not** called with fabricated attestations.
The existing read-only token expires November 6 at 22:30 UTC; no scope/expiry changed.

Local validation: 20 rehearsal tests and 457 total backend tests passed, with no
failures/skips. Generated artifact verification and diff whitespace checks passed.
CI results are reported on the exact updated PR commit; local tests do not prove
remote multi-page behavior or D1 mutation/transaction semantics.

## Decision 1 — external writer attestation

Proposed execution window for review: **2026-11-06 20:30 UTC through
2026-11-07 00:30 UTC** (3:30–7:30 p.m. Toronto, November 6), maximum four hours.
This window is not approved. If review/setup cannot finish before its start, stop
and present a new exact window and token expiration; do not silently move either.

Owner/operator attestation requested for the eight UUIDs above and that exact window:

> I have accounted for other administrators, CI/CD, API clients, restore tools and
> scheduled automation with D1 access to account 9706b4d98ad72884e67fd1eb875c8a61.
> None will write these eight databases during the approved rehearsal window,
> except the separately approved rehearsal operations. No Worker/Pages binding,
> cron, queue, email path, application credential or new writer will be attached.
> I will report any change immediately so execution stops for reconciliation.

Status: **not attested**. API inspection verified two ordinary active Workers;
their settings/active versions do not bind any target. Pages has zero projects.
That cannot exclude account-scoped tokens or external jobs. Workflow references
`CLOUDFLARE_STAGING_API_TOKEN` and `CF_STAGING_API_TOKEN` exist; their values/effective
permissions are not inspected. Dispatch namespace inventory returned HTTP 403,
code 10121: provider says Workers for Platforms access is unavailable. That is not
a verified empty namespace list, and no subscription/permission upgrade is proposed.
No live settings need changing to make this attestation; if writers cannot be
excluded operationally, stop and propose separately reviewed controls.

## Decision 2 — minimum temporary execution credential

Proposed **new**, separate token `CVEHarbor-PR270-rehearsal-20261106`:

- Resource: account `9706b4d98ad72884e67fd1eb875c8a61` only.
- Permissions: **D1 Write, Workers Scripts Read, Pages Read** only. The adapter
  uses one token for D1 operations and its mandatory metadata/binding checks.
  D1 Write is the only added write permission; no redundant D1 Read, Workers/Pages
  Write, token administration, zone, production-account or R2 permission.
- Not before: **2026-11-06T20:30:00Z**. Expires: **2026-11-07T00:30:00Z**.
- Purpose after separate Approval B: one retained-copy import to the success UUID,
  one pinned fictional fixture import to each negative UUID, read-only independent
  verification and the reviewed case matrix. A private export of only the success
  copy, if needed for full content comparison, must be included explicitly in B.
- Custody: masked local input, owner-only Windows DPAPI file under the existing
  private preparation directory; memory-only subprocess transfer. Never chat,
  screenshots, GitHub, CI, command arguments or plaintext token files.

Status: **not created or authorized**. Existing read-only token/OAuth grants remain
unchanged. Token creation alone is not permission to import, query-write or rehearse.
Cloudflare's account-level D1 permission is broader than the eight-UUID approval
(including permanent staging in that account); the adapter's hard denials and
approved UUID/endpoint allowlists are additional local controls, not provider-side
UUID scoping. Owner acceptance of that residual scope is required. No production
account access is requested. Do not perform a test write to check permissions.
If the provider cannot issue this exact scope/window, stop for review.

Sources: [permission reference](https://developers.cloudflare.com/fundamentals/api/reference/permissions/),
[D1 query](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/),
[D1 import](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/import/),
[Pages list](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/list/).
The import reference omits an accepted-permissions list; D1 Write is the D1 write
permission from the permission reference. Do not broaden it based on a failed import.

## Decision 3 — recovery signing identity setup proposal

Approve local preparation of a **separate Ed25519 attestation identity**, not reuse
of the RSA encryption key and not a change to production trust settings:

1. Reverify the installed trusted OpenSSL executable and existing owner-only ACLs,
   sync/sharing exclusions and free space. Use the existing private runtime, no install.
2. Generate an encrypted PKCS#8 Ed25519 private key with OpenSSL `genpkey`, encrypted
   with AES-256-CBC, at
   `D:\CVEHarbor-Recovery-Keys\pr270\attestation-key.encrypted.pem`.
   Reject existing destination files. The owner enters a separate strong passphrase
   only in a local hidden prompt and retains it outside these folders.
3. Write only the public SPKI PEM to
   `C:\CVEHarbor-Recovery\custody\attestation-public.pem` and calculate its
   SHA-256 over DER SubjectPublicKeyInfo bytes. Record that fingerprint privately
   for owner/independent verifier approval; it does not exist yet.
4. Sign a fictional challenge with OpenSSL `pkeyutl -sign -rawin`; verify with
   Node `verify(null, bytes, publicKey, signature)`, matching the production
   verifier's Ed25519 algorithm. Test altered payload/wrong key rejection locally.
   Inventory challenge/signature/public files; no automatic deletion or plaintext
   private-key file. The key is decrypted only in process memory for signing.
5. Keep signing under owner/independent verifier control. After B's restore checks,
   sign exact UTF-8 evidence bytes only after independent comparison of private
   content/schema/count/FK/integrity receipts. Never sign an unverified success.

Status: **not authorized, no key generated**. Explicitly accept the same online,
same-PC encrypted D: custody and unverified disk encryption for this new signing
identity, while acknowledging that same-PC custody is not independent recovery
or separation of duties. The previous exception covers the existing encryption key;
it is not silently extended here. The passphrase and private key must stay private.
No changes to `REPAIR_RECOVERY_PUBLIC_KEY`, GitHub environment secrets, reviewers,
security settings or the production executor are included. Trusting the approved
fingerprint in a future production environment requires a later explicit approval.

## Separate Approval B remains pending

After independent source review, owner attestation, signing preparation and exact
credential authorization, assemble the final B record with the reviewed commit,
new manifest, all UUIDs/creation hashes, retained pins above, approved window,
baseline counts and rechecked isolation/cost/storage evidence. The restore receipt
does not exist before an authorized restore: B permits import/verification first;
only a successful independently verified result supplies `recovery_evidence_sha256`
for the case claims. Do not invent that hash or pre-approve a successful restore.
Record the actual phase approval/payload digest privately before any case mutation.

Combined limits remain US$5, 1 GB and one million billable writes across all eight
targets; recheck allowance/usage and import/index costs before execution. No provider
hard spending cap is implied. The production verifier's separate 24-hour capture
freshness gate remains; an old capture blocks later production approval and does
not authorize a fresh export. Stop on drift, expiry, uncertainty or exceeded limits.
Never automatically retry an uncertain write, reset, resume, roll back or clean up.

Nothing here authorizes imports, remote SQL writes, new exports, production repair,
resume, staging deployment, customer-remediation activation, merge or cleanup.
Both encrypted packages, all execution evidence, existing temporary plaintext and
Plan Z remain retained under the previous explicit retention/cleanup rules.
