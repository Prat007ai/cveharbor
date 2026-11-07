# Production compatibility repair plan

**Draft for review. Not ready for production execution.** No live configuration,
database, hold, deployment, rollback or application record was changed. Staging
deployment remains paused. The original inactive SQL proposal and local rehearsal
are now accompanied by a [protected procedure](procedure/README.md), manual-only
workflow and local/mocked tests. No live operation is enabled or authorized.

**Newly verified blocker:** both existing production GitHub environments currently
lack required reviewers and branch restrictions and permit administrator bypass.
The new executor rejects those settings. Separate security-configuration approval,
fresh recovery preparation and each production operation's approval remain required.

## Recommendation

Repair the current production contract forward, starting **held and frozen**:
add the missing 0031 integrity objects, the complete 0032 recovery objects and
freeze guards for every application table. Keep `RECOVERY_CONTROL_REQUIRED=true`.
Retain current Worker code and existing frontend during this narrowly scoped
repair. Do not activate customer-only remediation, registry or monitoring features.
Restoring admission is a later, separately approved decision after verification.

This is the smallest tested repair that restores the existing release's recovery
and integrity contract. It is not just an `operations_control` table. Applying
upstream 0032 unchanged seeds an **open** row: local tests show health can return
200 while integrity readiness remains 503. That creates an unsafe admission window.
The proposal instead seeds `write_hold=1,database_frozen=1,revision=0` before guards
are installed. No resume statement is included.

## Evidence and scope

Sanitized timestamps, schema hash, configuration and aggregate counts are captured
in [`live-evidence.json`](live-evidence.json); raw customer data is not part of this PR.

- Reviewed source: `1532e732b771f960b6ae7791a9bd2205e1d59390` (PR #269 merge).
- Production account: `aa99b9b15e0492302e4f6484b8d27bc2`; Worker
  `cveharbor-accounts`; bound D1 `46710e51-7ca4-4571-b89c-921b9969de0b`.
- Dashboard rechecked November 6: active version prefix `07055fe8`, source
  Cloudflare Builds/main at that commit. Builds disabled. Worker Logs/Traces
  disabled. A later read-only dashboard inspection resolved the full active version
  to `07055fe8-f1ab-463f-97b2-372b458b6056`; the procedure pins it and rechecks its
  deployment percentage, configuration and database binding before execution.
- Complete live schema SELECT at 14:41 UTC returned all 143 application objects:
  70 tables, 48 explicit indexes, 24 triggers, one view. Every definition was
  token-normalized with `scripts/sql_schema_tokens.mjs`'s algorithm. Combined hash
  `327bab011a4ffe3654aab618f859a8cdaef14aa7d4bbd03c0db96d4f7b0a225d`
  matches the checked-in baseline exactly. No customer rows were exported.
- No table matching `*migration*` or `*schema_history*` exists in production.
  Installed history is established by schema definitions and the November 4 audit,
  not by an assumed native migration ledger. Never run the historical migration
  directory against this database.
- November 4 audit [41909431530](https://github.com/Prat007ai/cveharbor/actions/runs/41909431530),
  captured `2026-11-04T20:44:39.489Z`, archive SHA-256
  `c6f4eac1c2fee433a30a887a521b433d9e36dfb54d6f3bb038f0706c5281c604`,
  independently retrieved and verified, recorded the same absent recovery objects
  and required-control flag. Its source also uses the fail-closed wrapper.
- Read-only integrity aggregates on November 6: all eight predicates in
  `release-integrity-checks.js` were zero; foreign-key violations zero. These are
  point-in-time observations, not permission to migrate or proof of writer quiescence.
- Recovery UI exposes a Time Travel restore window. No raw bookmark was published,
  private backup was taken, or restore was tested. Recovery **availability** is
  observed; recovery **readiness for this repair** remains a blocker.

The verified failure is `SELECT write_hold,revision FROM operations_control WHERE
id=1` -> `no such table: operations_control: SQLITE_ERROR`. At 14:31:01 UTC,
`GET https://api.cveharbor.com/v1/release-readiness` returned 503 with default
`ready=false,held=true,schema_ready=false` and release identity
`80b709c7559a4277d3c791fc0a853aa874104f180ac26c9e5754379f9087f05f`.
At 14:33:57, `/v1/health` and unauthenticated `/v1/me` returned maintenance 503.
The `held` field is a fallback after an exception, not evidence of a stored hold.
No actual recovery control row exists. Silent catches and disabled observability
prevent establishing the exact first failed request or uninterrupted outage length.

## Complete missing-contract inventory

[`missing-contracts.json`](missing-contracts.json) enumerates every missing object
from all uninstalled checked-in application migrations and the customer proposal.
It does not assert that every optional migration should be installed.

| Contract | Missing objects | Current effect / proposed disposition |
| --- | ---: | --- |
| 0031 remediation integrity | 9 | Write-context table and eight guards absent. Required for reviewed finding writes and release readiness. Include in repair. |
| 0032 recovery control | 5 | Three operational tables, history trigger and new-lease trigger absent. Current wrapper stops every protected request and cron handler. Include, with frozen initial state. |
| Per-table recovery freeze coverage | 213 proposed guards | No existing recovery guards. Protect insert/update/delete on all 71 application tables after adding the integrity context table; operational tables deliberately excluded. Include. |
| Customer-remediation proposal | 12 | Two tables, unique context index and ownership/retention/history triggers absent. Customer-only creation/ticket history unavailable; feature reports unavailable. Asset and unassigned paths remain separate. Defer activation. |
| 0023 lifecycle/product monitoring | 22 | Monitoring tables/indexes absent; existing readiness returns unavailable. Product-monitor check/delivery flags unset. Do not enable or migrate as part of incident repair. |
| 0028 CVIE source efficiency | 5 | Snapshot/efficiency metadata absent; source code has a schema-detected fallback. Defer optimization. |
| 0029 CVIE identity registry | 26 | Registry/onboarding contract absent; registry and fast-evidence flags unset. Defer activation. |

The production baseline's older exclusion list names only 0023/0031/0032; it is
not an exhaustive inventory of newer optional proposals. The generated inventory
also covers the later efficiency/registry files and the customer proposal.
The local proposed end-state is **370 objects**, preserving every original
definition. Customer-only activation would additionally require all twelve
customer objects, integrity review of customer-context IDs, recovery guards for
both new tables, a compatible readiness contract and separate acceptance.
The current detached-asset predicate treats unlinked `~` IDs as invalid: customer-
only IDs use that format too. Merely adding their tables to production would not
make populated customer records compatible with the current production integrity
gate. A future customer activation must explicitly extend that predicate to accept
valid customer scopes while rejecting orphan/foreign scopes. This PR defers it.

Live runtime settings retain assignment email/ack/FYI/progress and remediation
workflow enabled; shared CVIE scans and plugin monitoring enabled; manual website
monitoring enabled, scheduled website monitoring disabled. Alert/lifecycle delivery,
product-monitor checks/delivery, registry and fast-evidence flags are unset.
SMTP2GO/TOTP secret bindings exist encrypted; values were not read. Cron schedules
remain every minute, every five minutes and minute five hourly. The wrapper stops
their handlers before application work. Frontend gate/version provenance from the
prior diagnosis is separate from backend health; no frontend update is proposed.

## Alternatives considered

| Option | Evaluation |
| --- | --- |
| Add only control table | Lease operations and integrity/readiness remain broken; tested locally. Reject. |
| Apply unmodified 0032 / disable required-control flag | Opens admission before complete safeguards or bypasses recovery; reject. |
| Roll back to previous Worker `635932b1` / source `df4f12e...` | Its entire account-backend tree is identical to PR #269's parent/merge tree. Same failure. Reject. |
| Audited Nov 4 version `89380b13-b600-4fef-82f4-69b8cc2f2c17`, source `6e05106...` | Audit proves required recovery flag and missing tables; source proves same fail-closed wrapper. Not a compatible recovery release. |
| Older pre-recovery build | No verified compatible, available immutable artifact with current binding/auth/tenant/remediation guarantees was established. Do not guess a rollback target. |
| Full integrated candidate migrations | Includes unrelated schema/features and customer-contract incompatibilities; broadens risk. Defer. |
| Minimal complete frozen forward repair | Preserves current source, existing IDs, relationships, history and recovery requirement. Recommended, subject to blockers below. |

## Proposed SQL, preservation and local evidence

[`proposed-repair.sql`](proposed-repair.sql) is outside every automatic migration
directory. SHA-256 and final schema fingerprint are in
[`local-evidence.json`](local-evidence.json). It adds one integrity context table,
eight integrity guards, three operational tables, two operational triggers and
213 per-table guards. It inserts one new operational control row; it contains no
customer-row backfill, re-keying, status conversion, token replacement, deletion,
notification replay or resume. Trigger bodies enforce future behavior; they do
not rewrite existing customer records during installation.

Run from repository root:

```text
node deployment/proposals/production-compatibility/rehearsal.mjs
node --test account-backend/tests/production-compatibility-plan.test.mjs
npm test --prefix account-backend
```

The rehearsal validates every historical SQL file checksum and exact 143-object
schema before doing anything. All databases are in-memory SQLite with fictional
tenants; no credentials/network clients are present in the proposal module.
Tests cover missing control/lease/guard objects, fallback readiness, upstream
default-open risk, preserved rows/objects, frozen holds, partial installation,
lease drain/stale lease refusal, MFA, unsigned access, tenant isolation, existing
remediation IDs/history and explicitly unavailable optional customer records.
Existing regression tests additionally cover hold races, mail drain, retained
acknowledgement links and cross-customer history. Local backend suite: **414 passed**,
including all nine new tests and the populated customer-only incompatibility case.
Local transaction success is not proof of remote D1 atomicity.

## Queued work and restoration impact

Private read-only aggregate checks at 14:44 UTC found **zero queued/sending/
unconfirmed** status, FYI and progress notifications, and zero currently due
reminder assignments. No email addresses, tokens or customer content were read.
There were **12 due disclosure items, 9 due shared-scan scopes and 2 due source
refreshes**. Eligibility/leases/provider backoff must be rechecked; these counts
do not guarantee every item executes immediately. Plugin monitoring can run at
the hourly tick. Existing sender secrets/flags allow new or newly due status,
FYI and progress emails after restoration. Existing `sent`/`unconfirmed` mail is
not to be replayed or reset. Reminder eligibility can change with time.
The one-time approved test in `monitor-approved-test.js` expired November 3 and
returns before doing work; do not renew it. Alert/lifecycle/product-monitor
delivery flags remain unset. Any resumed queue may incur provider calls/costs.

An explicit resume approval therefore includes normal scheduled processing and
eligible email effects under current settings. If the owner requires HTTP-only
restoration with schedulers/mail still stopped, that needs a separately reviewed
and approved design; the existing single hold does not provide that split.

## Execution prerequisites and interruption handling

The [implemented procedure](procedure/README.md) is reviewable but **not ready for
production execution**. The following prerequisites still require actual evidence:

1. Review the final source/SQL/metadata hashes and immutable live Worker ID, account,
   D1 identity, complete schema and all eight aggregate integrity checks again.
   Verify no competing admin, GitHub or Cloudflare operation/writer. Missing lease
   tables do not prove all writers are drained. Keep Builds and all deployment
   gates as observed; do not modify protections to run this proposal.
2. Obtain approved private recovery evidence: fresh Time Travel point, approved
   encrypted backup/export destination if required, independent verification and
   a restore rehearsal in a separately authorized isolated environment. No raw
   bookmark/customer export goes into this public PR or CI. Recovery availability
   alone is insufficient; a restore could discard later legitimate changes.
3. Review the dedicated protected, exact-target repair executor. Existing
   baseline/ordinary/forward/staging workflows are not this executor: baseline
   paths replay unrelated initialization, forward migration checks require an
   existing open control state, and code-only gates require valid recovery state.
   Do not change those gates or use the staging migration adapter against production.
4. The executor now binds exact source/manifest/SQL hashes, target/Worker version,
   observed schema/configuration/counts, a quiet window, signed recovery evidence and
   a unique approval/run. It uses a dedicated immutable receipt journal and fixed
   REST requests. Conditional claims are separate successful requests before writes.
   This replaces the tentative native-runner design; it never replays a migration
   directory. Review the [final executable checksums](procedure/manifest.json).
5. This procedure does not claim native migration rollback or REST multi-statement
   atomicity. Partial execution remains possible and blocks further writes. Local
   SQLite tests and mocked failures make no provider guarantee. Review the
   [interruption rules](procedure/README.md#durable-receipts-and-interruption).
   D1 recovery retention is plan-dependent:
   [Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/).
6. After installation, service stays held/frozen. Independently verify all original
   definitions and privately approved row-count/digest checks, new empty context and
   lease tables, exact 370-object application schema plus four journal objects,
   complete guard coverage and matching immutable receipts,
   hold revision, all integrity predicates and FK integrity. Do not mark service
   restored because migration exited successfully or readiness reports `held=true`.
7. On interruption, perform SELECT-only reconciliation. Baseline/no receipt means
   investigate before a new approval; exact proposed schema + matching receipt +
   frozen control and successful verification establish installation; partial/unknown state blocks all further
   writes. Never expire leases, rerun a write job, delete receipts, auto-roll back,
   or execute the whole historical migration directory. A recovery correction or
   restore requires its own reviewed plan and approval.
8. Review a fresh queue snapshot and acceptance evidence before separate resume at
   the exact control revision. Then verify authenticated MFA/tenant-safe behavior,
   readiness, existing acknowledgement links without replay, lease cleanup and
   bounded scheduler/provider behavior. Fictional live acceptance writes/emails,
   if needed, require specifically scoped approval. No actual customer test records
   may be reset or deleted under this plan.

The plan adds no production code deployment. A future sanitized diagnostic change
should distinguish confirmed hold from unavailable recovery state without exposing
SQL, credentials or records; any such code deployment needs separate review/approval.

## Decisions and eventual approvals

No production approval is requested with this draft. Required later decisions are:

- **PR review/merge:** exact reviewed repair-plan or executor head; merge is not
  permission to execute SQL or restore service. This test path matches the main
  Worker workflow's trigger: reverify disabled production gates and Cloudflare
  Builds before any eventual merge, without changing them. PR CI has no authority
  to deploy the proposal.
- **Protection configuration:** separately approve the missing owner reviewer,
  main-only branch restriction and disabled administrator bypass on the two existing
  production environments, plus the precise protected procedure configuration.
  No such setting is changed by this PR or by its executor.
- **Recovery preparation:** exact private export/restore-test scope and destination,
  resource/account, retention, any spend and separately isolated test target.
- **Production schema repair:** account/D1 above, final executable SQL checksum,
  approved current source/profile/Worker ID, private recovery evidence hashes,
  quiet window and protected reviewer gate. Scope includes creation of the held
  operational row and dedicated receipt journal; explicitly excludes resume/deploy/data repair.
- **Production resume:** exact installed schema/receipt and control revision,
  zero active leases, integrity/FK success, reviewed queue effects and acceptance.
  This authorizes the state transition and subsequent normal traffic/scheduled work;
  it is not an implicit approval to resend uncertain mail.
- **Any code deployment, feature/schema expansion, policy change or restore:**
  separate exact commit/artifact/SQL/target approval. No blanket rollback permission.

Staging pins remain the previously reviewed PR #269 artifact seal
`2ac05a2a08b6a46a8bb35539dd381439f01cf2fd2e300648210865d9d1e2e454`,
profile `326b693ce22172bf8e41b8c5c6206ef005d39700188b75462d211937a37c9512`,
SQL `4cb409cd1ad836c3e71394e3f054168d99b7896817421d92d795d71235a8977a`,
commit `1532e732b771f960b6ae7791a9bd2205e1d59390`. This PR neither regenerates
that candidate nor authorizes staging status/configuration changes or deployment.
