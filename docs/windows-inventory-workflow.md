# Windows inventory collection and vulnerability assessment

## User workflow

Download the PowerShell collector from **3. Register asset and technology stack**, or from **Import server inventory** in an organization customer workspace. Follow `collectors/README.txt` on each target Windows server. The collector reads OS/build details, installed-software registry records corresponding to Programs and Features, .NET Framework release/version evidence, .NET runtime/SDK installation directories and IIS. It writes local CSV files and a collection report; it does not upload inventory or run a vulnerability scanner.

Review collection warnings and CSV contents before uploading. Choose the customer/environment, upload one numbered CSV, review the preview and confirm the selection. Import saves the rows through the existing authorized asset API and opens **Customer Security Dashboard** for that customer/environment. The dashboard evaluates saved inventory against the available public advisory index. An organization dashboard uses only the current member's customer grants; personal inventory and personal CVIE records are not requested in that flow.

AI is not needed for CSV validation, import or assessment. This release does not invoke Azure, change AI controls or consume an organization's AI allowance. AI remains paused.

## Validation and coverage

- Exact ordered columns: `Asset Name,Asset Type,Technology,Version,Notes`. UTF-8 CSV supports BOM and quoted commas/quotes.
- Each file is limited to 200 entries and 128 KiB. The collector splits larger exports automatically. Names/technologies are limited to 120 characters, versions to 80 and notes to 500.
- Malformed CSV, missing required fields, unsupported asset types, control characters and spreadsheet-formula prefixes are rejected before any writes. Unknown versions remain explicit warnings.
- Exact same asset/type/product/version rows are consolidated or skipped. Side-by-side versions are retained. Import is additive: it never automatically deletes superseded versions or uninstalled products. Imports are sequential, not transactional; a partial error reports saved/skipped counts. Re-upload reads current assets before retrying. Concurrent imports are not a synchronization mechanism.
- Programs and Features coverage includes machine 32/64-bit installation records and the executing user, not every user profile. Portable apps, Store apps, containers, bundled runtimes and custom paths can be missing. Use `-DotNetRoot` for additional local runtime locations and inspect the report.
- The limited advisory index is not exhaustive. Generic installed products require explicit affected-product text plus a source link and remain **Needs verification**. Windows, IIS and .NET Framework require build/patch evidence; their version strings are not treated as proof of affected status. Existing reviewed product/version matching is retained. No match does not mean secure.
- Viewer accounts can inspect authorized results but cannot import. Existing Editor/Owner authorization is enforced by the backend on every write. Customer/environment changes stop a pending import; customer access is checked again when the dashboard loads or regains focus.

## Release scope

The backend change exposes an existing `environment_id` in the authorized organization asset response so imported assets can be deduplicated and assessed within the correct environment. No schema migration or permission changes are included.

`scripts/windows_inventory_release.py` reconstructs the verified PR342 production packages at base `b48e89971106d837fc16acaa82d672f61f4f9725` and overlays only inventory-related changes. It preserves other production differences from main, including the shared-remediation release.

- Serving predecessor backend identity: `ce561b7756d14c874d353470c84b8c9228626e400df8d776dcb83ee03eadeb2a`.
- New backend identity: `release/windows-inventory-backend.txt`.
- Website predecessor version: `ba6e8ba5-cd22-4d49-b95d-0d5ab377c4fa`; deployment: `3d42e375-a8ce-44a2-af09-15feccd484a8`.
- Branch: `feature/windows-inventory-assessment`. Obtain approval for the new PR before merging under the project's existing approval practice.

After merge, wait for application/security CI and both Windows inventory checks on the exact main commit. Deploy the `windows-inventory` backend package using **code-only**, with `team_commit` equal to that commit. Then publish the `windows-inventory` website package with the same `reviewed_commit`. Verify main-only protected environments, eligible reviewer and disabled administrator bypass before using delegated production approval. Record the delegation and run URLs.

The backend pre/post checks require all `ai_organizations.enabled` values to remain zero, verify unchanged Worker bindings, verify release readiness and anonymous access denial, and retain the previous retrievable Worker version in a recovery receipt. The website publisher verifies the predecessor and all served asset bytes, then reruns the browser workflow using served files with intercepted fictional API data. This verifies delivered code, not an actual production customer import.

Final authenticated production verification should inspect the download/import entry and dashboard under the authorized owner account. Any write test must use a fictional customer/environment. Do not run the collector against a real server automatically. Keep AI paused. Recovery requires its separate approval; retain both prior versions and do not automatically delete imported assets or roll back production.

## Validation

- `powershell -NoProfile -File scripts/test_windows_collector.ps1`: fictional exporter fixtures, UTF-8/header/size/row limits, distinct versions, formula escaping and overwrite refusal.
- `node --test scripts/asset_import.test.mjs account-backend/tests/inventory-import.test.mjs`: parser/matching safeguards and real Worker authorization using fictional databases.
- `node scripts/import_workflow_smoke.mjs`: reviewed import, partial retry, scope change, dashboard findings and revoked organization access.
- `node scripts/inventory_browser.mjs`: real browser, fictional responses, import-to-dashboard at 1440/768/390 pixels; no AI inference.
- Full existing application/security checks remain required. The production package is separately tested for unchanged AI/accounting behavior.

The collector's fixture mode validates export and normalization without reading the test host. Actual OS/registry discovery still needs an owner-run trial on a representative Windows server before relying on inventory completeness.
