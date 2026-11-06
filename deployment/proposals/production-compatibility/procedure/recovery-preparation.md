# Recovery preparation — local preparation authorized; cloud actions pending

The old backup is Plan Z. It is not evidence for the new repair and will not be
restored, overwritten, deleted or moved. Production test data must be preserved.

The [isolated rehearsal runbook](rehearsal/README.md) now makes this proposal
concrete: one restored-copy database plus seven separately named fictional-case
databases, with no between-case cleanup. Its Approval A covers allocation/capture;
Approval B requires the resulting exact UUIDs, recovery evidence and final source
pins before import or test writes. Neither approval has been granted or executed.
The US$5/1 GB/one-million-write ceilings below apply to the combined eight targets,
not independently to each. Production executor targets and its manifest are unchanged.

## Concrete proposed scope

- **Source:** account `aa99b9b15e0492302e4f6484b8d27bc2`, D1
  `46710e51-7ca4-4571-b89c-921b9969de0b`, exact baseline and Worker in `target.json`.
  Capture only after an approved quiet window and read-only identity/integrity checks.
- **Private destination:** owner-controlled administrator machine,
  `C:\CVEHarbor-Recovery\production\pr270\<capture-uuid>\`. This is outside the
  repository and observed OneDrive root. Local folder creation and tooling were
  authorized on November 6. See [host preparation evidence and owner exceptions](rehearsal/host-preparation.md).
  Full disk encryption is **unverified and explicitly waived by the owner** for
  this test-data rehearsal on this PC; it is not a verified control. Owner-only
  ACLs, sync/ordinary-sharing exclusions, trusted administrative access, capacity,
  encrypted packages and a temporary-plaintext inventory remain mandatory.
- **Package:** fresh Time Travel bookmark and full schema/data export, private
  metadata/aggregate checks and a manifest. Encrypt to an owner-held RSA >=3072-bit
  recovery certificate using authenticated CMS AES-256-GCM/RSA-OAEP. The owner
  separately authorized passphrase-encrypted key custody at
  `D:\CVEHarbor-Recovery-Keys\pr270`; this is online, on the same PC, and is **not**
  an independent/offline copy. Keep the passphrase separately under owner control.
  Use a separately controlled Ed25519 attestation key for
  the restore result; its public fingerprint must be approved for the protected
  environment. No keys, plaintext, raw bookmarks, signed download URLs or production
  exports enter GitHub artifacts, this repository, chat or public cloud storage.
- **Isolated remote restore target:** a **new proposed** D1 database named
  `cveharbor-prod-repair-restore-pr270` in the existing separate account
  `9706b4d98ad72884e67fd1eb875c8a61`. UUID is deliberately unassigned until separately
  approved creation. Never substitute permanent staging
  `fac61562-fc31-426d-8032-550aba63b7f6`, production, or an existing database with data.
  No Worker binding, route, cron, application credentials, SMTP key or notification
  path. No Access/security settings need alteration. Verify isolation metadata before
  copying production test data. Scope transfer to this exact resource in the approval.
- **Rehearsal:** download/decrypt the actual retained encrypted package, restore it
  into that isolated target, and verify complete schema, every table count, FK results
  and integrity. Compare private content digests independently before signing the
  receipt. Test this procedure on that separate resource only through an explicitly
  reviewed test adaptation; the production executor intentionally rejects substitute
  targets and must not receive a generic target override. A fresh protected production
  preflight must still match the restored baseline before installation approval.
- **Retention:** keep the encrypted package and signed receipts for at least 30 days
  after successful repair acceptance. Keep the isolated restore target for 48 hours
  after independent verification. These are retention review dates, **not** automatic
  expiry or permission to delete. Any later removal requires explicit scoped approval.
  Never remove the old backup as part of this preparation.

## Cost proposal and bounds

No new paid plan, R2 bucket, hosting service or subscription is proposed. Local
storage has no provider usage charge but needs existing verified capacity. Proposed
initial remote rehearsal ceiling: **US$5 incremental usage**, at most 1 GB restored
and one million billable rows written; inspect measured size/row/index costs first
and stop for a revised approval if those bounds are inadequate. This is an approval
ceiling, not a configured Cloudflare hard spending cap. No spend has been incurred
by resource creation/export/restore in this task.

Cloudflare's published paid D1 rates on November 6 are $0.001/million rows read,
$1/million rows written and $0.75/GB-month above included usage; index/DDL work can
also contribute. Free-plan capacity and existing account usage must be checked
before provisioning. Actual billed cost depends on plan allowances and measured
work; do not promise zero cost. [Cloudflare D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/)

## Evidence to approve later

The operator must produce exact target UUID/isolation evidence, capture time,
encrypted package SHA-256, export SHA-256, private bookmark SHA-256, baseline and
counts hashes, recovery key-custody confirmation, independent restore receipt/hash,
verification time and the signature expected by `verifyRecovery`. Capture and
verification must be completed within the executor's 24-hour freshness requirement.

The separately approved isolated rehearsal must also validate the final installation
batch through the same REST query interface: inject schema and row-count drift after
the start claim, advance past approval expiry before submission, interrupt around
the first assertion and final receipt, and attempt concurrent writes. Record the
observed ordering, failure propagation and DDL isolation/commit behavior. Confirm
that a rejected first assertion creates no repair objects or installed receipt.
Local SQLite tests (including simulated partial writes) do not meet this requirement.
If the remote contract is not established, production stays blocked and the adapter
must be revised for review; do not retry an uncertain write. Do not point this fixed
production executor at the isolated target by changing live inputs: any rehearsal
adapter/target pins need their own review and scoped approval first.

**The exact proposed approval is in the linked runbook; nothing is executed here.** It names the private destination,
source/restore account and exact new resource, export/transfer/restore scope,
retention, budget and operator/key custody. Creating the test target or restoring
production into it is distinct from production SQL installation, resume and any
Plan Z production restore.
