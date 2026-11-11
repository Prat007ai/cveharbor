# Organization AI allowance and platform usage administration

## Product behavior

Each organization has exactly **USD 20 per UTC calendar month**, shared by every staff member and managed customer. There is no per-user or per-customer extra allowance, rollover, top-up, or automatic overage. Personal workspaces do not receive an AI allowance. Existing organization membership and selected-customer permissions apply to every assistance request, including Viewers; AI does not edit assets or execute remediation.

Organization members open **AI assistance** from their team workspace. The page shows allowance, consumed, reserved and available USD amounts. It sends only the question the user enters: it does not automatically export inventories, prompts from another customer, or conversation history. Answers are plain text for human review and do not imply verified vulnerability applicability or live source retrieval.

The **AI usage administration** link appears under Account & Security only for platform administrators. Organization Owner is not platform administrator. The initial release proposes the existing verified, MFA-enabled `prat@mahendran.tech` account as platform owner. This access grant requires explicit owner approval with the release. That owner can grant/revoke dashboard viewing for other existing MFA-enabled CVEHarbor accounts, pause/enable organizations and reconcile confirmed usage. Delegated dashboard viewers cannot change access, activation, budgets or reconciliation. No Azure management permission is involved.

Reports include monthly organization/staff totals, daily consumption, request states, model/version, token counts, reserved amounts and recorded charges. Staff attribution remains within each organization. Reports are paginated, and totals cover the entire selected month/filter. Requests contain no stored prompts, answers, credentials or raw provider errors. A SHA-256 fingerprint detects conflicting request identifiers; it is not a substitute for encrypting sensitive content. The ledger stores identity/customer metadata and must remain within the existing protected Cloudflare database.

## Hard-stop mechanism

All customer inference goes through `/v1/ai/organizations/:org/assistance`. The existing Azure connection probe performs no inference. Other provider clients or paid AI features must not be exposed without this shared reservation path.

1. Recheck MFA session, origin, organization membership and selected-customer access.
2. Check deployment configuration, current reviewed price card and organization activation. Rate limits are 60 requests/user/hour and 300 requests/organization/hour.
3. In one D1 transaction, create the monthly balance if absent and insert a unique `(organization, request_key)` record. A database trigger reserves funds atomically, and a database constraint prevents `spent + reserved` exceeding USD 20. Parallel Workers cannot reserve the same balance twice.
4. Acquire an Entra token, then recheck customer access, activation and recovery controls before recording dispatch and sending exactly one inference request. Authentication failure before dispatch releases the reservation.
5. Reconcile validated input/output/cached token counts at the immutable request price. Reasoning tokens are already included in completion tokens and are not charged twice. Release unused reservation only after confirmed settlement.
6. Missing usage, timeout, transport failure or an interrupted accounting write retains the reservation. Reusing the identifier never resends inference, even across month boundaries. There is no automatic retry, timeout refund, or expiration of a hold.

The question is limited to 6,000 UTF-8 bytes, plus one fixed instruction and chat framing; there are no tools, images, attachments or history. Reserve conservatively for **32,768 input tokens plus 1,024 completion tokens**, including reasoning. This is deliberately above the byte-level token upper bound of the admitted question plus fixed framing. The reviewed reservation is **USD 0.0321016**. A smaller positive remaining balance can therefore block the next request. Return unused reservation after actual usage is known.

All accounting uses integer picodollars (10^12 units/USD). Monthly rollover creates a new independent balance, retains the old ledger and holds, and does not reset idempotency identifiers. A request belongs to the month in which its reservation was admitted.

This is an application allowance at reviewed USD inference rates, not an Azure subscription spending cap. Azure budget alerts, playground calls, other applications, taxes, exchange rates and negotiated invoice adjustments are outside this ledger. The existing CA$20 resource-group budget is independent and does not stop service.

## Price card and operational prerequisite

Verified against the public [Azure Retail Prices API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices): `serviceName = Foundry Models`, `armRegionName = eastus`, USD, Consumption, product Azure OpenAI GPT5, GPT 5.4 mini Data Zone meters effective March 1, 2026. The companion `docs/reviews/organization-ai-pricing.json` records meter IDs and prices.

| Meter | USD per million tokens |
|---|---:|
| Uncached input | 0.825 |
| Cached input | 0.0825 |
| Output, including reasoning | 4.95 |

The price card accepts `gpt-5.4-mini-2026-03-17` from the existing `gpt-5.4-mini` deployment at `https://cvie-prod.openai.azure.com`. It expires December 12, 2026 UTC; inference then fails closed until a reviewed rate-card update. Reports remain available. An unexpected model or out-of-bounds usage keeps the reservation and pauses that organization.

**Before enabling the first organization**, the Azure owner must confirm that this deployment still uses US Data Zone Standard, this model version and these rates, and select the portal's no-automatic-upgrade policy where available. If the version cannot be pinned, keep organizations paused and review the deployment strategy. A post-response mismatch check cannot undo a provider charge made under an unreviewed model or price. Future model/rate changes require a new reviewed price card before activation; retain old card support for unreconciled historical requests. No Azure settings are changed by this PR.

Sources: [Azure OpenAI pricing](https://azure.microsoft.com/en-us/pricing/details/azure-openai/), [deployment types and processing geography](https://learn.microsoft.com/en-us/azure/ai-foundry/openai/how-to/deployment-types), [D1 batch transactions](https://developers.cloudflare.com/d1/worker-api/d1-database/), [Azure budgets](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets).

## Reconciliation and recovery

The platform owner's Requests & holds view includes the request identifier. Use the reconciliation form only with verified provider usage evidence. Record a non-sensitive evidence reference plus input, output, cached and reasoning counts. The audited transition and balance adjustment occur in one transaction, exactly once. A confirmed zero-charge request can use zero counts; absence of an invoice entry alone is not proof of zero charge.

An abandoned `reserved` or `dispatched` record becomes eligible for owner review after five minutes, but its funds remain held indefinitely until review. An undispatched reservation permits only zero-charge cancellation; the atomic state transition prevents a delayed Worker from dispatching it. A dispatched record requires confirmed usage, just like a hold. An in-flight settlement that loses the reconciliation race fails closed rather than returning an unaccounted answer. If evidence is unavailable, leave the funds reserved. Never edit balances or delete ledger rows manually to free allowance.

Pausing an organization blocks new requests; an already dispatched request may finish and is still accounted. Existing recovery write holds and database freeze protections remain authoritative. If they interrupt settlement, keep the reservation and reconcile after recovery. Use the previous Worker/site versions to roll back application code; retain the additive tables and all accounting records. Do not restore a database snapshot merely to undo this feature, because that could erase charges and grant additional spending capacity.

## Release procedure and owner decisions

This PR prepares a scoped overlay over the verified PR337 serving packages, not a blanket deployment of main. Expected predecessor backend is `8fd3af1d291a2861411ba109256d8fad103ccde550003d5dca7b35c4aa9f2487`; site version `5471b3b6-eb78-4bee-a753-659e8675244f`, deployment `c9beba0a-0541-4da5-bc9d-db98b9ca8f0e`. Stop and re-review if production has moved.

Required approval: this PR merge, the exact additive SQL below, scoped backend/site releases, and the initial platform-owner grant to `prat@mahendran.tech`. No credential changes, Azure management, subscription permission changes, existing inventory writes, or automatic customer activation are included. All organizations start paused; owner activation is separate from deployment verification.

| Item | Reviewed target |
|---|---|
| Cloudflare account | `aa99b9b15e0492302e4f6484b8d27bc2` |
| Production D1 | `cveharbor-accounts`, `46710e51-7ca4-4571-b89c-921b9969de0b` |
| SQL | `deployment/proposals/organization-ai/schema.sql` |
| SQL SHA-256 | `3c0b5033ef4fff437a372c183b450420e3392fbbba71da71047fd59a20951d94` |
| Backend package SHA-256 | See `release/organization-ai-backend.txt` |
| Application commit | Exact approved merged main commit, supplied to all three workflows |
| Execution window | One coordinated release window after owner approval and current checks; stop if credentials or predecessor checks fail |

1. Complete application/security CI, native accounting CI, scoped package and fictional browser checks on the reviewed source. After an approved merge, require successful CI for the exact main commit again.
2. Inspect protected environments: owner eligible reviewer, main-only deployment branches, administrator bypass disabled. Record the owner's delegated approval and scope on each GitHub production approval. Do not alter these controls.
3. Run **Activate production customer assignment storage**, `schema=organization-ai`, exact `reviewed_commit`. Preflight verifies predecessor health, prerequisite schema, foreign keys, recovery controls and a D1 Time Travel bookmark. Apply five additive tables, two indexes and 23 triggers in one transaction; preserve existing schema/data. Save `organization-ai-migration.json`. If an operation times out, inspect receipts/schema before any retry; never rerun initialization.
4. Run the existing backend workflow with `team_release=organization-ai`, `team_commit=<approved main SHA>`, `release_mode=code-only`, all unrelated selectors off. Verify the immutable package pin, reviewed PR, installed SQL, existing MFA owner, unchanged bindings/credentials and recoverable previous Worker version. Save `organization-ai-backend-recovery.json`.
5. Run **session-navigation** with `site_release=organization-ai`, `reviewed_commit=<same SHA>`. Publish only the two existing navigation files and seven new AI assets. Verify served bytes and responsive browser behavior using fictional API fixtures. These fixture tests verify served UI code, not live authenticated accounting.
6. Verify production readiness identity, anonymous API rejection, existing workspace behavior, and the owner-only dashboard with a real authorized session. Confirm organizations remain paused. Then obtain the Azure owner's model/rate confirmation above and explicitly enable Whitecap for an initial fictional customer question. Record the real request ID and balance change; test duplicate suppression and a non-admin denial. Do not spend real money to exhaust an allowance: hard-stop/concurrency exhaustion tests use isolated D1 and a fake Azure provider.

The initial review uses no paid Azure calls and makes no live migration, binding, access or deployment change. Native runtime tests isolate outbound requests to a simulated provider. Broad backend regression, targeted authorization/accounting tests and responsive UI checks are part of the evidence; do not label a production integration as verified until step 6 completes.
