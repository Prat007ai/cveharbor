# Content verification after bookmark movement

## Existing success copy verified, without another import or export

On November 6, 2026 at 7:26:31 p.m. Toronto, the authorized read-only scan of
success `84dab6e9-9344-4e0f-a79a-4f0b43395754` completed. It compared the entire
application schema and column definitions, all 68,419 application rows, SQLite
storage types, full values, row identifiers and eight `sqlite_sequence` rows
against the unchanged retained SQL. Foreign-key, application-integrity and
quick checks passed. `__pr270_import_value_8c21b7` is absent. The scan's two
bookmarks matched; the earlier schema-fixture movement remains unattributed.

Private proof SHA-256:
`7901dad2ea2bbc7730a6cf7a8e3b7ed9e8bf79deb648ab490ee0ba5ff93265ed`.
Reference SQL SHA-256:
`f6cc1bf56d48986aad95f890a2fdefdcd1fb5199e215c001598087ac503d92a8`.
The prepared reference and all 343 successful query responses are retained
privately; every query reported zero writes. The corrected verifier also passes
an offline replay of those complete responses. No new import, export, signing,
case mutation, token change, reset or cleanup occurred during this review.

The one permitted private success export remains unused. Its existing
authorization was still valid during this scan, but the direct typed reads made
an export unnecessary. It is not a prerequisite for signing this complete proof.

## Exact stopped check and correction

The stopped check was the operator helper
`tooling/approval-b-remote-lossless.mjs:55`, in `verifyBaseline`:
`assert.deepEqual(after,before,'Target changed during verification')`.
This was not a production-executor check. It compared whole current Time Travel
bookmark responses after schema/count/integrity queries and treated inequality
as a stop, without testing complete content.

[Cloudflare documents](https://developers.cloudflare.com/d1/reference/time-travel/#bookmarks)
that internal maintenance can advance bookmarks without application SQL writes.
That explains why bookmark inequality alone is insufficient evidence of a data
change. It does **not** establish the cause of this particular event.

`verify-content.mjs` replaces that decision with mandatory complete content
verification. It runs for both equal and unequal bookmarks, since matching
bookmarks and matching row counts are not substitutes for comparing values.
Both bookmarks and the movement flag remain in evidence. Movement with complete
matching content yields `bookmark-moved-content-verified`, never an assertion
that maintenance caused the movement or that external writers were excluded.

The verifier compares schema before and after, column definitions, every typed
field, rowid and sequence value. Integer row keys remain strings/BigInts rather
than lossy JavaScript Numbers. TEXT/BLOB comparisons use their full hex bytes;
NULL is distinct and REAL uses SQLite's round-trip decimal representation. The
retained application data contains no REAL/BLOB values; regression fixtures
cover those types. Known reference pages are bounded to 500 rows and 4 MB, each
followed by strict digest/row-key checks and a final extra-row check per table.
SQL JSON calls stay below 32 arguments, including wide-table queries.

It rejects actual content differences even with unchanged counts/bookmarks,
missing or partial reads, schema/column drift, type/rowid/sequence differences,
integrity failures and a remaining import helper. A known uncertain write
outcome cannot be cleared by matching content. There is no retry or mutation
path in this module. Callers retain authenticated exact-target/binding checks,
zero-write query receipts, source/reference pins, private evidence and budgets.

The operator helper is prepared to call this reviewed verifier and to refuse
both already completed imports (success and schema). Remaining fixture imports
still require fresh emptiness/isolation checks. Signing preparation consumes
the existing complete typed-content proof, so no redundant export is required.
No remote write is enabled by preparing these changes.

## Evidence limits and unchanged protections

These are complete bounded reads, not a distributed lock or a transactional
snapshot spanning the entire scan. They detect observed differences from the
retained reference, but cannot prove no transient or subsequent external write.
The user's accepted credential-consumer uncertainty stays
`external_writers_excluded:false`. Stop on actual drift, incomplete verification
or uncertain writes. Production SQL, executor, authentication and all existing
target/custody/expiry checks remain unchanged. No maintenance cause is claimed.

## Remaining operations, budget and approval

Reported writes remain **193,181** (192,877 corrected success import + 304 schema
fixture import). The earlier failed attempt remains unmetered; retain its
**500,000-write reserve**. Remaining allowance is **306,819 writes**. The scan
brings total recorded reads to 393,016, well below the 100-million read planning
allowance. Last observed aggregate target size is 53,796,864 bytes; the existing
200 MB planning allowance and 1 GB ceiling remain.

Six unattempted fixtures (count, expiry, race, rejected, interrupt, lost) at a
conservative 10,000-write allowance each require 60,000 writes. Eight claims,
eight installation attempts and two perturbations at 10,000 writes each require
180,000. Total remaining plan: **240,000 writes**, leaving **66,819** headroom.
These allowances include provider/index/DDL variation; actual receipts continue
to be charged and a new missing metering result stops work. The two completed
imports are not included again. No retry allowance is added.

The existing US$5 / 1 GB / one-million-write combined ceilings and original
6:25–10:25 p.m. Toronto window on November 6 remain in force. At full write and
read allowances plus one month at the storage ceiling, the existing gross model
is US$1.85. Refresh allowance/size observations before later mutations; no hard
provider spending cap or zero actual charge is asserted.

Still pending: complete typed verification of the already imported schema
fixture; six fixture imports and their verification; existing-key signing;
owner review of the actual phase-payload digest; and all eight reviewed cases.
No success/schema reimport is needed. The previous approval covers their
purpose, targets, caps and window, but pins the old source and old stopped check.
Only approval of the corrected source/manifest and this content-based
continuation criterion is additionally requested. Keep writes paused pending
that review. No new export permission, token change, reset or extension is
requested. Stop at 10:25 p.m.; a later window requires separate approval.
