# D1 migration atomicity investigation

Reviewed 2026-11-05 for PR #268. No live database operations or Cloudflare changes
were performed. Local SQLite simulations establish adapter behavior, not D1's
service-side transaction semantics.

## Authoritative evidence and decision

- [D1 REST query reference](https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/query/)
  documents the batch request format but does not establish all-or-nothing rollback
  across DDL and DML in a generic REST batch. We could not confirm that guarantee.
- [Cloudflare developer-platform issue #79](https://github.com/cloudflare/developer-platform/issues/79)
  remains open; the discussion reviewed contains no Cloudflare staff confirmation
  of generic REST batch rollback. No external support message was sent.
- [Workers D1Database.batch documentation](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch)
  promises transaction rollback for the binding API. That promise must not simply
  be transferred to another API. A migration Worker would also add infrastructure.
- [Official Wrangler migrations apply documentation](https://developers.cloudflare.com/d1/wrangler-commands/#d1-migrations-apply)
  explicitly states: “If applying a migration results in an error, this migration
  will be rolled back”. Previously successful migrations remain applied. The
  [migration guide](https://developers.cloudflare.com/d1/reference/migrations/)
  describes SQL schema migrations and configurable migration directories/journals.

Use this documented **per-migration command contract**, with every guard, CREATE
statement and application receipt in **one file**. SQL migrations contain schema
changes as well as data statements; the documented rollback is for the migration,
without a DDL exclusion. Do not divide this change into multiple migrations. This
is authoritative published documentation, not a new provider support assurance or
an independent live DDL/DML failure experiment.

Wrangler itself uses D1 APIs internally. The safety basis is the documented command
contract, not a claim that changing HTTP transport creates atomicity. The previous
handwritten REST batch submission is removed from this adapter.

## Exact execution and journal boundary

`customer-candidate-migrate.mjs` invokes pinned Wrangler 4.156.0 with a minimal
configuration naming only the existing staging account/database. The isolated
temporary directory contains exactly
`0001_customer_remediation_<approved SQL SHA256>.sql`. It includes the existing
schema/count guards, unchanged approved proposal SQL statements and the existing
staging receipt append. No other migration files are eligible to run. All original
commit/artifact/profile/checksum/environment approvals remain required.

The pinned [apply implementation](https://github.com/cloudflare/workers-sdk/blob/wrangler%404.156.0/packages/wrangler/src/d1/migrations/apply.ts)
and [helpers](https://github.com/cloudflare/workers-sdk/blob/wrangler%404.156.0/packages/wrangler/src/d1/migrations/helpers.ts)
initialize the native migration table before executing files and append the native
receipt to each file's SQL. We use `d1_customer_remediation_migrations` exclusively.
An exact empty journal is therefore allowed with the baseline; a completed
candidate requires precisely the expected native filename receipt plus the
existing exact `staging_schema_history` receipt. An unexpected table definition,
trigger, receipt or partial application schema blocks execution. Provider metadata
is excluded from the application schema fingerprint but this journal is checked
separately; the 143-object production baseline is not changed.

## Failure and reconciliation

The adapter runs the command once, with captured output and a bounded process
timeout. CLI output is never placed in the safe report. Before starting it records
an unknown database outcome. Success requires independent schema, both receipts,
FK and preservation checks; process success alone is insufficient. Errors,
timeouts, lost responses or failed postchecks stop without automatic retries,
rollback, cleanup of database metadata or uploads.

An interrupted client cannot prove that the remote operation stopped. An operator
must establish that it has finished and review fresh read-only status evidence
before granting any new write approval. Exact completed state reconciles without
replaying DDL. Exact baseline/empty journal permits a separately approved retry
only after that investigation. Any partial state requires a separately reviewed
recovery action; this adapter deliberately has no partial-schema repair mode.
The [execution runbook](customer-candidate-execution.md#interrupted-operation-recovery)
contains the operational sequence.

Regression simulations include every committed DDL/DML prefix with rollback
deliberately absent, transaction rollback after DDL, lost responses before/after
commit, successful process exit with partial schema, timeouts and inconsistent
native receipts. They verify fail-closed behavior and preservation of fictional
existing records, not Cloudflare implementation guarantees.

No production resource, customer record, authentication/MFA configuration, Access
policy, credential or existing approval mechanism changes. The only additional
database object proposed for a future approved staging migration is the isolated
native migration journal. Remaining risks are provider contract/implementation
drift, remote operations outliving the client and concurrent writers; keep the
pinned tool, explicit reconciliation and reviewed quiet window.
