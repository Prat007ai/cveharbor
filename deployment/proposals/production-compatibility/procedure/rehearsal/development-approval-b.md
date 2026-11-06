# Revised Approval B — development rehearsal only, pending approval

The owner states that production holds disposable test data and accepts uncertainty
about unidentified consumers of existing account credentials for the eight isolated
rehearsal databases, provided inspected workflows and bindings do not target them.
Record this as **accepted uncertainty**, never verified external-writer exclusion.
This source change prepares that exception; it authorizes no remote mutation.
Production remains unrestored. Its executor, authentication, fixed targets, manifest,
SQL, recovery-evidence verifier and reviewer/runtime protections are unchanged.

## Exact proposed scope and window

The earlier window started before this preparation could complete. Propose
**November 7, 2026, 00:00–04:00 UTC** (November 6, **7–11 p.m. Toronto**).
Approval is requested to update only the existing rehearsal token's validity to
these exact times, preserving its secret, isolated account and permissions. No
change has been made. If the provider cannot preserve it with that validity, stop
and propose a replacement; do not create or broaden another credential silently.

Account: `9706b4d98ad72884e67fd1eb875c8a61`. Existing token:
`CVEHarbor-PR270-rehearsal-20261106`, D1 Write, Workers Scripts Read, Pages Read.
Provider D1 scope includes permanent staging. The eight-UUID restriction remains
an application/approval boundary, not provider UUID scoping.

Only these retained databases may receive the separately approved operations:

| Case | Exact UUID |
| --- | --- |
| success | `84dab6e9-9344-4e0f-a79a-4f0b43395754` |
| schema | `9f106efd-f5ae-4401-8c50-a4c80c53b90e` |
| count | `5d2e6500-350c-4228-9fe4-48c37f755e7d` |
| expiry | `39adff8b-b689-45f6-ba3a-c6005ec86b3f` |
| race | `b098f98c-bb9f-4e50-95fc-177ac7c2582f` |
| rejected | `3ddd25d0-b5c7-4597-9a4c-02bb9ba1c697` |
| interrupt | `477cb173-2f84-4786-baa1-6bba51fd7937` |
| lost | `d7eb48ca-2023-420d-a5d3-c9cc0360b49c` |

Their names and creation-receipt hashes remain those in
[the retained prerequisite record](approval-b-prerequisites.md). No reallocation.
The exception rejects any other case-to-UUID mapping or execution window. The
final private approval must pin the reviewed commit and new rehearsal manifest;
the actual SHA values are supplied with the final request after source preparation.

After explicit Approval B only:

1. Reuse the retained encrypted package and existing RSA custody to decrypt locally
   and verify the recovered SQL hash. Import it **once** to success; import the
   pinned fictional fixture **once each** to the other seven UUIDs.
2. Independently compare baseline schema, all counts, private content digests,
   foreign keys and integrity. Include at most one private export/download of the
   **success copy only**, if needed for full-content comparison. No production export.
3. Reuse the prepared encrypted Ed25519 identity to sign only verified restore
   evidence. Record the actual owner-reviewed phase-approval digest before case
   mutations. Neither restore success nor its future evidence hash is pre-approved.
4. Run the existing success, schema drift, count drift, expiry, race, missing-start,
   interruption and discarded-response case sequences once. Preserve exact SQL,
   live target/binding checks, unexpected-change checks, authentication, private
   credentials and logs. Stop uncertain writes for read-only reconciliation;
   never retry, reset, resume, roll back or clean up automatically.

Excluded: production repair/restore/reset/resume, permanent-staging writes,
deletion, Plan Z, new capture, merge, deployment, security infrastructure or
disabling existing services. Later production work requires its own approval.

## Reused evidence and accepted limitations

Credential and signing preparation are complete. The separate Ed25519 fingerprint
(SHA-256 DER SPKI) is
`21d74029ba7d7bc1a34e5039ea6178b58fb3be01f366438d1c920ec20a8a7f8f`.
Fictional signature verification succeeded; altered payload and wrong key were
rejected. Same-PC encrypted D: custody and unverified disk encryption remain the
explicitly accepted arrangement. No new keys or infrastructure are proposed.

The last completed live inventory covered all eight UUIDs with 73 GET requests,
zero SQL. Two ordinary Workers had no target bindings; Pages had zero projects.
Inspected permanent-staging workflows target their permanent database, not these
eight UUIDs. The owner commits not to modify the eight, attach bindings or start
another writing task during the execution window. Recheck targets and bindings
at execution; changed evidence stops the operation.

One focused connected-GitHub GET on November 6 at approximately 22:42 UTC returned
`total_count:0, workflow_runs:[]` for `status=in_progress`. No running job affecting
the rehearsal was identified. The earlier count of one with no returned details
cannot be attributed retrospectively. This limitation is recorded, not expanded
into a requirement to prove every historical credential consumer absent.

Unknown copies/consumers of the existing staging deploy/export credentials and
other account access remain unknown. Dispatch inventory returned 403/10121
(product access unavailable), not a verified empty list. These are accepted
development uncertainties; `external_writers_excluded` stays **false**. There is no
distributed lock against an unknown account writer, and aggregate schema/count
checks can miss same-count data changes. A newly observed writer, drift or ambiguous
outcome stops work. Successful rehearsal still does not prove general D1 atomicity.

## Completed import/index cost estimate

The pinned retained export is 45,755,487 bytes with 68,419 application rows. From
the retained counts and baseline indexes, the model is **192,497 table/index row
writes**, plus eight system-row INSERT statements, up to 35 sequence updates and
**21** table/index writes for seven fictional fixtures. All 24 exported trigger
definitions follow the data INSERTs, so they do not amplify preceding restored-row
writes. Added repair indexes have no existing rows to populate.

Plan for **500,000 combined writes**, including 307,439 writes of DDL/receipt/case
headroom, **100 million reads**, and **200 MB** combined remote material. Storage
uses four times SQL bytes plus eight installed empty schemas, rounded up; it is an
estimate, not measured D1 allocation. [Current D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)
gives a gross estimate of **US$0.75**, including a full month of 200 MB storage,
without using included allowances. With the last observed allowances, expected
incremental cost is **US$0**. At the existing one-million-write/1 GB caps and the
100-million-read planning allowance, gross cost is US$1.85 for one month.

The last dashboard observation (November 6, about 19:58 UTC) showed 1.65k/50M
writes, 385.31k/25B reads, 1.14 MB/5 GB storage and $0.00 billable usage. Recheck
usage before execution and actual provider usage/sizes after each import and
before the next phase. DDL/import metering can differ from this estimate; storage
beyond one month requires continued review. No provider hard spending cap is
claimed. Existing combined limits remain **US$5 / 1 GB / one million billable
writes**. Stop if projected or observed usage cannot stay within them.

## Unchanged input pins

- Retained ciphertext: `16b8ca2e958c6b5bfec96af76839cf1463842aeb81d6fcb97b83625fe01b0987`.
- Primary ciphertext: `168875f114d0dbf745ae5c5bce53b18ed08540a7ea6cfcecfdd024cd75388eea`.
- Recovered SQL: `f6cc1bf56d48986aad95f890a2fdefdcd1fb5199e215c001598087ac503d92a8`.
- Fictional fixture: `1ebc87b41db5a6698cf40bcae258ba16c7beda3a2e6c8ffe308e4008f25dfcb6`.
- Production manifest: `4dd094b957dc21421a0daf35f6e99b28cfac42ae60b26dee15bf2b6b12e5b42c`.
- Installation SQL: `2932acfd414c14e850d994b5aa31cc098aea6145ced7f32188c8b9edd18e7c46`.

This document is a review request, not authority to import or execute. If review
cannot finish before the proposed start, present another exact window and token
change; do not silently slide the window. Production freshness and verifier gates
remain separate and unchanged.
