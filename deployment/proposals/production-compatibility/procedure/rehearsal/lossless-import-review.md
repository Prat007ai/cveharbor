# Lossless import correction — preparation only

The approved November 6 attempt submitted the retained SQL once to success
`84dab6e9-9344-4e0f-a79a-4f0b43395754`. Cloudflare returned terminal
`statement too long: SQLITE_TOOBIG`. Read-only reconciliation at 23:29:16 UTC
found zero application objects/rows, a stable bookmark, passing quick/FK checks,
and all eight databases still 12,288 bytes each. No other import, export,
signature or case execution occurred. No reset, retry or cleanup was performed.

## Representation and supported import path

Three single-row INSERTs exceed D1's [100,000-byte statement limit](https://developers.cloudflare.com/d1/platform/limits/).
Splitting files or groups of rows cannot fix those rows. Keep the existing
[SQL file import](https://developers.cloudflare.com/d1/best-practices/import-export-data/)
path: one initialized upload, one ingestion, and status polling of that import
only. No new Worker, binding, parameter transport, service or credential is needed.

`lossless-import.py` changes only those three INSERTs. It creates one ordinary
import-only SQLite table, `__pr270_import_value_8c21b7`, assembles the full values
there using 16 KB-or-smaller literal chunks, then substitutes a scalar SELECT
for the original large literal. Each original application row is inserted once,
complete, in its original position. Constraints and triggers therefore see full
values. Other application statements, including trigger creation and PRAGMAs,
retain their bytes and relative order. The import ends by dropping **only this
new helper table**; this in-import DROP must be explicitly included in the next
approval. It does not delete an existing database/table or authorize cleanup.

TEXT chunks preserve UTF-8 characters and escaped quotes. BLOB assembly uses an
explicit BLOB cast after concatenation. NULLs and numeric literals remain
unchanged. Only single-row literal INSERTs can be rewritten; unsupported large
SQL, helper-name collisions, incomplete SQL and >2 MB values fail closed.
The helper has no application indexes, triggers, bindings or credentials. The
actual backup has no application triggers active during its data INSERTs; tests
also cover pre-existing triggers and constraints that must see complete values.

The output has 35 helper-row INSERT/UPDATE statements, one helper CREATE and one
helper DROP. It is 45,757,901 bytes; its largest statement is 78,610 bytes.
The upload ceiling is 200 MB (stricter than D1's 5 GB file-import limit).
The REST control requests contain only small import metadata; no SQL is sent
in JSON or bound parameters. Production SQL/executor/protections are unchanged.

## Complete offline validation

Both the original and transformed files execute independently into in-memory
SQLite with foreign keys enabled and the original ordering, within an import
transaction. The verifier compares every schema definition, column definition,
row count, SQLite storage type and full field value, including hidden rowids
where available and `sqlite_sequence`. TEXT is compared as exact UTF-8 bytes,
BLOB as bytes, REAL as IEEE-754 bits, and INTEGER/NULL distinctly. Row multisets
are sorted before hashing; no sampling or count-only equivalence is used.
Both FK and integrity checks must pass, and no helper table may remain.

The actual backup comparison passed for 70 application tables / 68,419 rows,
plus `sqlite_sequence` with eight rows. It contains Unicode, quotes, integers
and NULLs. It contains no newline-bearing TEXT, BLOB or REAL values; regression
fixtures separately verify those cases, including invalid UTF-8/NUL bytes in
BLOBs, multiple large columns, deferred foreign keys and trigger ordering.
Local SQLite validation is not proof of remote D1 atomicity.

`import-once.mjs` runs the same byte-counting SQL preflight **before initialization
or upload**, verifies the specifically approved SHA-256 and MD5 transfer checksum,
then persists an exclusive attempt marker. It never retries initialization,
upload, ingestion or a failed poll. Existing target/isolation/custody/budget/window
checks remain required at the caller. An uncertain outcome stops all further
writes for read-only reconciliation; no automatic removal of the helper is allowed.

## Immutable input and output pins

| Item | SHA-256 |
| --- | --- |
| Original retained encrypted package | `16b8ca2e958c6b5bfec96af76839cf1463842aeb81d6fcb97b83625fe01b0987` |
| Original decrypted SQL, unchanged | `f6cc1bf56d48986aad95f890a2fdefdcd1fb5199e215c001598087ac503d92a8` |
| Separate corrected import SQL | `bd540fee93266d264bca0239b80f5a5c97772a91f1b64119d03244e44c278514` |
| Private validation manifest | `0d5cb75c302ea986866405449c6d0322143dfcab80946fad727b0aa1333d0b80` |
| Complete typed content and rowid comparison | `32aa03d9a3309cb06427981526daeec4e465aec8a011acdefdbca6a2f4d3b922` |

Original encrypted and decrypted files are read-only inputs and were rehashed
unchanged. New SQL and detailed validation are retained in existing owner-only
private custody. Only checksums, counts and sanitized evidence enter this PR.
See [machine-readable evidence](lossless-import-evidence.json).

## Revised cost accounting

The failed import returned no completion billing metadata. Its billable writes
remain **unknown**, despite an empty resulting database and zero writes on the
subsequent read-only queries. Reserve **500,000 writes** against the combined
one-million cap for that attempt. This conservative operational reserve is not
a verified provider charge or mathematical billing guarantee; the owner must
accept this explicitly. Any later evidence exceeding it stops the run.

Only 500,000 writes remain available for the corrected import, seven fixtures
and eight cases combined. `import-cost.mjs` adds the failed-attempt reserve to
all subsequent reported writes and rejects operations exceeding that remainder.
The retained model is 192,497 application/index writes, eight system INSERTs,
up to 35 sequence updates and 21 fixture writes. The correction adds 35 helper
INSERT/UPDATEs, three helper-row removals and two helper DDL statements. The
remaining roughly 307,000-write allowance covers DDL, case operations and
metering variation; it is not permission for retries.

Use 100 million reads and 200 MB storage as planning allowances. Counting the
failed reserve plus the entire remaining write allowance gives gross **US$1.25**
including one full month of 200 MB storage, without assuming free allowances.
At the 1 GB storage cap the same model is US$1.85. Retain the combined
**US$5 / 1 GB / one million writes** ceilings. Recheck dashboard allowances,
target sizes and provider usage at execution. There is no provider hard cap.

## One revised Approval B request

The final request must identify the exact corrected commit, generated rehearsal
manifest and the import/checksum pins above. Reuse the existing validity window:
**November 6, 2026, 6:25–10:25 p.m. Toronto** (23:25–03:25 UTC), executing only
after new approval and stopping at 10:25 p.m. No token change is proposed. If
review leaves insufficient time, stop and propose a separately approved window;
do not extend it automatically.

Request one new corrected-file ingestion into success only, including the exact
helper CREATE/INSERT/UPDATE/DROP described above, after fresh proof of emptiness
and unchanged bindings. The original failed attempt remains retained and cannot
be replayed. Then perform the seven still-unattempted fictional imports to their
existing exact UUIDs in [the development approval](development-approval-b.md),
independently verify every restore, allow at most the still-unused one private
success-copy export, reuse the prepared Ed25519 key to sign verified evidence,
record the owner's actual phase-payload digest and run all eight reviewed cases
once. Maintain `external_writers_excluded:false` and accepted credential-consumer
uncertainty. All names, UUIDs, keys and packages are reused.

The request includes the explicit 500,000-write reserve acceptance above. It
excludes another automatic retry, database reset, production/permanent-staging
writes, cleanup beyond that in-import helper DROP, merge, deployment, token
changes and Plan Z. This preparation document grants none of these operations.
