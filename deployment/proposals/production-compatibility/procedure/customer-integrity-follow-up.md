# Separate follow-up: customer-only remediation integrity

Status: reproduced, deferred; no activation or runtime fix included in PR #270.

At production commit `1532e732b771f960b6ae7791a9bd2205e1d59390`, the
`detached_asset_records` predicate in `account-backend/src/release-integrity-checks.js`
counts an unlinked, non-retired remediation ID containing `~` as invalid. Valid
customer-only records also use that format. Adding the optional twelve customer
objects and six freeze guards for their two tables therefore does not establish
compatibility: creation can succeed while release readiness subsequently fails.

The last test in `production-compatibility-plan.test.mjs` reproduces the defect
using fictional data and checks that another tenant still cannot read the record.
Do not weaken or remove the integrity check, install customer schema, backfill,
re-key, unlink or reset records as part of production recovery.

A separate PR must define an ownership-aware predicate that accepts valid customer
and environment scopes, rejects orphan and cross-tenant scopes, and remains safe
when optional tables do not exist. Review context uniqueness, immutable associations,
asset/customer exclusivity, retirement, ticket/assignment/status history, existing
acknowledgement links and full recovery coverage. Test populated customer records
with recovery required, not only the optional schema in isolation. Coordinate any
future schema/readiness/backend deployment with separate exact approvals and
staging acceptance. The existing candidate pins are preserved, not endorsed as a
production-ready solution to this defect.
