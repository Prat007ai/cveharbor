# Expression-depth correction and preserved success continuation

Preparation only. No remote write, token change, import, reset or deletion is
authorized by this document. The owner has deferred the seven other scenarios.

## November 6 approved continuation stopped before mutation

The owner approved source `45ef7c2e562b6a58c75b0ed0a7810cd4820b0993` and signed
its pinned continuation inputs. At 8:50 p.m. Toronto the adapter stopped at its
local durable claim: `privateLog.claim` accepted lowercase letters only, rejecting
the new `correct-journal` phase. Offline replay of the saved reads reproduced
this rejection after all preceding adapter checks passed. The earlier continuation
tests used a mock journal and missed the real filesystem validator.

All 431 saved query inputs were read-only; no write intent, claim file or mutation
request was produced. Complete typed-content verification passed before the stop.
Read-only reconciliation at 8:51 p.m. confirmed the original application schema,
counts and integrity, exact original journal definitions, empty receipts and only
the historical plan. No trigger replacement, intent/start insertion or installation
was submitted. The original stopped claim and every attempt record remain intact.

The focused correction permits only the five actual mutating rehearsal phases:
`claim`, `perturb`, `install`, `correct-journal`, `continue-claim`. Exclusive file
creation and fsync are unchanged. Real-filesystem regression tests cover the entire
continuation, duplicate claim rejection, malformed/unknown phase rejection and a
lost correction response without resubmission. Production code and all SQL bytes
are unchanged; only the rehearsal source manifest changes.

No remote retry follows this source correction. A new commit/phase-input approval
is required before submission, with the same target, SQL, scope and stop time.
Reported writes remain 193,195, with both reserves retained and 296,805 available.
Reported reads including this verification/reconciliation are 1,087,909. No new
unmetered mutation occurred. All production blockers listed below remain open.

## Correction and focused evidence

The `install-intent` insertion at source
`12befb50bd605a7525506f6fd206c9549054a8b0` failed with D1 code 7500:
`Expression tree is too large (maximum depth 100)`. Three earlier claim requests
created the immutable rehearsal plan and empty repair journal. Installation was
never submitted. Read-only reconciliation preserved all 68,419 application rows,
types, identifiers and eight sequence rows, schema, foreign keys and integrity.
The complete proof remains pinned at
`3b1319424e5174656a299d578bd682d7c806b2dfc426dfc8546cb38e258722a9`.

`build.mjs` now groups the same `AND` predicates into a balanced expression tree.
`snapshotPredicate` still checks every original table count, complete schema and
all integrity/FK predicates from `noViolations`. SQL NULL semantics are preserved;
the existing `COALESCE(...,0)` rejection boundaries remain. Generated uses in the
receipt trigger, installation assertion and conditional resume UPDATE all use
the correction. Installation checks remain first in the same request as the DDL
and installed receipt. Authentication, target checks, production approval gates,
held/frozen installation and separate resume protections are unchanged.

Eleven Python regression tests execute with expression depth 100, function
arguments 32, parameters 100, statement length 100,000, columns 100 and value
length 2,000,000. They reproduce the exact original trigger failure, pass corrected
claim/install/separate resume, reject every missing/NULL table count and other
missing evidence, reject drift/expiry/invalid operation at installation, preserve
holds on failed resume, and test the guarded journal correction. Three focused
adapter tests cover preserved-state continuation, stale/retargeted authorization,
and an uncertain correction response without resubmission. Existing relevant
procedure/rehearsal/import regression tests pass (54 total at the first run).

One additional offline check used the unchanged retained SQL, all 68,419 real
test rows and eight original sequences. It passed correction, claim and install
at depth 100, verified complete preserved content and held/frozen state, then
passed a **local-only** separate resume with the expected one operational event.
Original values/sequences remained unchanged; resume adds its own event/sequence.
See [the local result](depth-local-validation.json). This is not remote resume
authorization and does not establish D1 REST transaction/rollback behavior.

## Applicable limits and pins

[Published D1 limits](https://developers.cloudflare.com/d1/platform/limits/) include
100,000-byte SQL statements, 100 parameters, 32 function arguments, 100 columns,
2,000,000-byte values/rows, 50 MB results and a 30-second API request duration.
The observed expression-depth limit is additionally enforced in the regression.
Installation SQL is 79,890 bytes; bootstrap 12,725; resume 16,305. The exact
correction is 95,083 SQL bytes and **98,810 serialized request bytes**, below our
conservative 100,000-byte whole-request bound. It has no bound parameters across
its multiple statements; one correctly quoted JSON input is embedded once.
Typed verification queries remain at most 9,070 bytes, <=30 JSON-function
arguments and bounded 4 MB content pages. Local execution times are not a D1
latency guarantee; an uncertain provider result still stops, without retry.

Production manifest:
`6edd08bedf440f00e2d074746c02a7d85e826ec9d5619db43390a67981a75a5a`.
Rehearsal manifest:
`9583e27cc77472a05a58dc288ea12a50e813351557113c9b7107bd7129bf7ae2`.
Exact correction SQL SHA-256:
`470d41e37fea154bf2277589bdaf022658ac9408806def9da56aa4c42b23d1fc`.
Installation SQL SHA-256:
`ad42edc5c52d124550d1bfb0cf1a01fe3250eb7a27ccc358a3f10ff5f448bd3b`.
Resume SQL SHA-256 (local test; not remotely authorized):
`e916f8b39ad2ecc93d92507ce7d4cd8a51343ea481aa80a98f70a4dda98a87e1`.

## Exact proposed continuation

Only account `9706b4d98ad72884e67fd1eb875c8a61`, success database
`84dab6e9-9344-4e0f-a79a-4f0b43395754`. Reuse the completed import, retained
proofs, existing token and replacement signing identity with public fingerprint
`33366643d37c34c4a18a8933bda35a1048fc0df8bc5f244992f9f8ca55ef2258`.
The prior phase approval digest is
`2aed73935ac80452cf0f86d8b672eba89523dc730a66e23d043a7e224858aa89`;
its old source/manifest/plan stay recorded and are not relabelled as new approval.

1. Pin the new commit/manifest, new phase approval and signed continuation
   evidence; recheck target identity, inspected bindings, remaining budget and
   unchanged preserved state. Reuse content evidence; bookmark movement or an
   unexpected observation requires complete verification, never cause attribution.
2. Submit `correct-journal` once: one request checks application schema/counts,
   integrity, clock, exact prior journal definitions, **zero receipts** and only
   the exact historical `plan` row. It then **drops and recreates only**
   `d1_cveharbor_repair_receipts_sequence` with the balanced guard. The old trigger
   hash is `7b4cb413c4e0cfec2b1598b211b5f7b11ac79f85a731964b6445160935c5e4bb`;
   the replacement is `9bc96b66929057fb0a033c93f0b835f11b9c089ad26664cefb5e4bbe3c261273`.
   No table, immutable update/delete trigger, row or attempt record is removed.
3. Verify the corrected journal and unchanged baseline read-only. Submit
   `continue-claim` once: insert the new source/manifest-bound `install-intent`
   and `install-started` receipts. This does **not** recreate the plan or journal
   or replay the original claim. A new private approval/log retains the old log.
4. Submit the unchanged-in-purpose, corrected installation batch once, after its
   durable installation attempt. Verify expected application/journal schema,
   full preserved content/types/identifiers/sequences, integrity, exact receipts,
   empty leases/context and held=1/frozen=1/revision=0. Stop; do not resume.

The adapter permits this continuation only for the exact success UUID and
historical pins. It rejects the original `claim` phase, altered correction bytes,
other scenarios, unexpected journal definitions and an existing attempt.
The replacement's DROP/CREATE request has an uncertain-outcome risk: if the
reply is lost or it fails after DROP, only read-only reconciliation is permitted.
Do not assume REST DDL rollback, repair a partial correction or retry. Accepted
external credential-consumer uncertainty remains `external_writers_excluded:false`.

Reported writes are **193,195**. Reserves remain **500,000** for the earlier
unmetered import and **10,000** for the rejected claim: **296,805 writes remain**.
Budget three mutating phases at 10,000 each: **30,000 planned, 266,805 headroom**.
Actual receipts remain charged; new missing billing requires reconciliation and
a retained reserve. US$5, 1 GB and one-million combined writes are unchanged.
Existing aggregate storage was about 54 MB; refresh size before execution.

The original November 6 **6:25–10:25 p.m. Toronto** window remains available at
preparation time. No token change is needed. Plan to start by **10:05 p.m.** to
leave reconciliation time, and stop absolutely at 10:25. Approval received too
late requires a separately proposed window/token-validity amendment; never extend
automatically. The final request binds the corrected commit and private inputs.

## All currently known production blockers and shortest next steps

* This corrected success continuation has not run. The seven other cases stay
  deferred. Existing documented live-failure evidence is incomplete; local
  depth-100 rejection tests do not establish REST rollback/isolation on failure.
  No extra remote case is added. Before production, the owner must explicitly
  resolve the existing procedural gate: accept the reduced evidence/risk for
  disposable development data, or request a specific test. The risk is partial
  DDL or a changed database after an error/lost response, which could require
  reconciliation rather than restoration by replay. Existing no-retry/held-state
  protections remain. This preparation does not silently waive the gate.
* PR #270 remains draft/unmerged. The protected executor requires a reviewed
  source on `main`, an exact manifest pin and a first-attempt manual run. Merge
  and required existing-environment configuration need approval; no new recovery
  platform or Worker deployment is proposed.
* Current public GitHub reads confirm both `cloudflare-worker-production` and
  `cloudflare-production-audit` have **no required reviewer**, no branch policy
  and administrator bypass enabled. The executor requires owner Prat007ai
  (349078288) as sole reviewer, explicit `main`-only policy and bypass disabled.
  The owner's exact-run environment approval and compatible dispatch arrangement
  are also required. Public reads cannot verify current enable/source variables
  (HTTP 401); do not record them as absent or ready. Protected credential/API
  access and required settings must pass the existing preflight.
* After success, prepare the production-specific signed recovery envelope from
  existing capture/restore evidence, bind the corrected production manifest and
  fresh production schema/count/Worker/binding/queue observations, check the
  capture's 24-hour age limit, and confirm production writer quiescence. Accepted
  isolated-account uncertainty does not satisfy the production executor's writer
  exclusion checks. Do not claim an unverified production quiet window.
* Request **installation approval** for exact production account/database,
  source/run/SQL/evidence/fingerprint and <=30-minute window. Effect: additive
  integrity/recovery objects and receipts, preserved application data, held and
  frozen control. No resume or deployment. On error/lost reply, reconcile only;
  retained backups remain a separately approved recovery option, never automatic
  reset/import/Plan Z.
* After independent held-state verification, request **separate resume approval**
  for its own run/approval, installation receipt, current fingerprint/revision and
  queue effects. Effect: one conditional hold/freeze release, revision/history
  update and resumption of scheduled work/eligible email. A lost response requires
  read-only reconciliation; do not replay release or delivery. Any later re-hold
  or restore is a separate approved action. Revalidate the already deployed
  recovery-aware Worker before proposing any code deployment.

These are the remaining gates together; passing the isolated case will lead
directly to preparing the exact production installation and subsequent resume
requests, not more rehearsal infrastructure.
