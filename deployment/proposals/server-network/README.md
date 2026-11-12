# Server network inventory release

Owner authorization: implement and publish server adapter/IP inventory, handle production approvals, and keep AI paused. Existing Owner/Editor/Viewer permissions are reused without granting access.

## Scope

- Collector 1.2 reads local Windows adapters, IPv4/IPv6 addresses and default routes. It does not probe addresses or upload data. A unique preferred default-route address is only a suggestion.
- The optional sixth CSV column, `Server Network`, carries a bounded JSON snapshot. Existing five-column imports remain supported. Review the snapshot before import.
- Private metadata is keyed by inventory owner, environment and normalized hostname, so matching names in different customers/environments stay separate. An explicitly saved primary survives later imports; an absent address is flagged for review.
- The Customer Security Dashboard shows the primary or suggested address and expandable adapters. Owners and Editors can save a selection; Viewers can read only. IPs do not determine vulnerability applicability and are not sent to AI.

## Release order

1. All required application/security and Windows inventory checks must pass on the reviewed main commit.
2. Dispatch `customer-investigation-schema.yml`, schema release `server-network`, at that commit. Approve the existing protected environment. The script records a D1 recovery bookmark, verifies the serving predecessor, adds one table and three recovery-freeze triggers atomically, and checks unchanged existing schema and foreign keys.
3. Dispatch `deploy-worker-code.yml`, `team_release=server-network`, with the exact reviewed commit and other release modes disabled. It verifies the frozen PR344 predecessor, preserves bindings and Azure credentials, deploys only the inventory route changes, and checks all organizations still have AI disabled.
4. Dispatch `session-navigation.yml`, `site_release=server-network`, at the same commit. It overlays the collector/import/dashboard changes on PR345's website and verifies served assets and fictional browser flows.
5. In production, import fictional adapter addresses, select a primary address, refresh to verify persistence, and confirm AI remains paused. Record PR/run links and resulting versions on the PR.

## Recovery and limits

Retain the previous Worker and website versions. The table is additive and the previous application can ignore it. Do not automatically drop the table or restore the database on failure. An interrupted migration requires inspection of the receipt/schema before retrying.

Snapshots are capped at 32 adapters, 128 total addresses, 64 addresses per adapter and 14,000 JSON characters. CSV parts remain limited to 200 software rows/128 KiB. Oversized network inventory stays in the local collection report with a warning and is omitted from CSV. Address freshness depends on collection time; imported snapshots are not live network monitoring.

No production-server collection is performed during validation. Fictional tests cover multiple adapters, IPv6, scope isolation, role restrictions, duplicate import, stale writes, retained selections, recovery freeze and responsive browser layouts. Windows driver/provider differences still require a customer run on the intended server.
