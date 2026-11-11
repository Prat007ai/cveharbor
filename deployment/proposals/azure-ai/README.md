# Azure AI application connection verification

Status is prepared for review. Live application authentication and model calls from this code await approval. The feature is a prerequisite for the backend integration. The existing website and Worker release entry points do not consume this proposal.

## Verified configuration evidence

Owner screenshots on November 10, 2026 show `CVIE-Prod` in East US, deployment `gpt-5.4-mini` version `2026-03-17`, Data Zone Standard (US), 10,000 TPM and 10 RPM. Priority processing is disabled. The configured version policy upgrades when a new default is available. DefaultV2 content filtering is selected.

The owner registered `CVIE-Prod-AI-Backend`, assigned Cognitive Services OpenAI User at the resource scope, and reported saving the role assignment. GitHub screenshots show the four `CVEHARBOR_AZURE_OPENAI_*` variables and the `CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET` environment secret. Secret validity has not been checked. The owner chose a client secret expiring November 9, 2028 and retains Azure administration. Record rotation responsibility with the owner before rollout.

The owner completed one Foundry playground request with 88 input and 172 output tokens. This exercised their portal session. The resource-group budget is CA$20 monthly, with actual-cost email alerts at 50%, 80%, and 100%. It covers the resource group and is independent of the planned shared US$20 customer-organization allowance. Alert delivery and final invoice reconciliation are outstanding.

## Review and execution

The manual `Verify Azure AI application connection` workflow consumes the saved GitHub environment configuration. Credential-free pull-request tests exercise only mocked HTTP responses. There is no push trigger.

After review and authorized merge, verify main checks and the `cloudflare-worker-production` environment protections. The owner must remain an eligible required reviewer, branch restrictions must select main, and administrator bypass must remain disabled. Request approval for the exact merged SHA and run mode. Select `main` and set `reviewed_commit` to that exact commit. A mismatched selection cannot start the protected verification job.

- `access` obtains a Microsoft Entra token and performs the Azure v1 model-list metadata read. This verifies authentication and resource read permission. It does not prove inference permission or Cloudflare connectivity.
- `inference` performs those checks and makes one fixed fictional request with a maximum of 1,024 completion tokens, low reasoning effort, and storage disabled. Authorize up to US$0.01 of model usage per run using the reviewed current rates. There are no automatic retries. A manual rerun is another potential billable request and needs an approved run scope.

Both modes run on GitHub. They do not install secrets into Cloudflare, deploy an application, migrate a database, or create Azure resources. GitHub Actions execution is subject to the repository's normal runner billing.

The artifact `azure-ai-verification.json` reports sanitized status and usage. It excludes credentials, access tokens, prompts and response text. It carries `usage_category=platform_verification` with null organization and application-user IDs. GitHub run identity provides administrative audit attribution. These records must not be assigned to a customer allowance.

Failures after inference starts retain unknown cost until reconciled. A timeout does not establish that Azure stopped processing. Completed response usage survives truncation and content-filter failures where the provider returns normal text and usage. Missing, invalid or contradictory usage fails verification. Model changes invalidate the estimate until rates are reviewed. Reported reasoning tokens are already included in completion tokens and are not charged twice.

## Integration sequence

1. Verify the application identity with the protected workflow and review sanitized evidence.
2. Extend the accounts Worker using the verified client and existing session/MFA, origin and recovery controls. Bind configuration and the client secret through the reviewed release workflow. Test the actual deployed Worker connection with fictional data before declaring Cloudflare connectivity verified.
3. Record each request durably in Cloudflare D1 with a stable request ID, billing organization, authenticated actor, managed customer, AI feature, model/version, timestamps, status, input/output/cache/reasoning usage, rate version and USD estimated cost. Resolve actor and organization server-side. Reuse current `team_visible_customers` authorization and check current Owner/Editor access for generation. Keep usage history attributable when membership changes. Personal-workspace billing needs a defined owner-approved mapping before enabling that path.
4. Implement the US$20 allowance as one shared monthly balance per paying organization across staff, managed customers and features. Reserve cost atomically before upstream calls, settle from reported usage, and retain uncertain reservations for reconciliation. Handle concurrent requests, idempotency, retries, cancellation and the monthly boundary. Define the billing month timezone with the owner and apply the same boundary to dashboard and enforcement. Add an explicit platform-wide spending limit before customer enablement.
5. Build Admin → AI Usage & Costs from those same records. Enforce explicitly granted platform-admin access on every backend read and page. Only the designated platform-owner account can grant dashboard access. Organization Owner/Editor/Viewer roles do not confer platform-admin access. Track grants and revocations. Show totals and filters by organization, user, feature and date, allowance remaining, reserved spend and hard-stop status. Clearly label model-cost estimates in USD and reconcile separately with CAD Azure billing and administrative requests.
6. Test isolation and accounting using fictional data and review the exact schema, release package, administrator grants and activation before live changes. The initial customer feature remains source-grounded remediation advice in the existing CVE details panel.

The new D1 schema, allowance enforcement, dashboard, app routes, credential-installation workflow and customer activation are subsequent work. They are not delivered by this connection-verification proposal. Keep customer AI disabled until these dependencies are tested and approved.

## Local verification

Run `node --test deployment/proposals/azure-ai/verify.test.mjs` with Node 22 or newer. Tests cover valid authentication, form encoding, redirect rejection settings, credential-safe failures, request bounds, missing usage, caching, reasoning, model changes, resource denial and explicit inference selection. No real credentials or paid APIs are used by tests.

## Sources

- [Azure v1 chat API](https://learn.microsoft.com/en-us/rest/api/aifoundry/azureopenai/chat)
- [Microsoft Entra client credentials flow](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow)
- [Microsoft production credential recommendations](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-credentials)
- [Azure retail pricing API](https://learn.microsoft.com/en-us/rest/api/cost-management/retail-prices/azure-retail-prices)
- [Cost Management budget behavior](https://learn.microsoft.com/en-us/azure/cost-management-billing/costs/tutorial-acm-create-budgets)
