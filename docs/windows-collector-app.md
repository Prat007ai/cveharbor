# Windows Collector app 1.0

Download the ZIP from **Register asset and technology stack → Download Windows Collector app**. Extract all files together, then open `CVEHarbor-Collector.exe`. This portable evaluation build is unsigned; use your organization's normal software approval process. It does not bypass Windows policy. A trusted signing certificate is needed before distribution as a verified publisher. No certificate, secret or account permission is added by this release.

The app requires Windows x64 Desktop Experience and .NET Framework 4.8 or later. Server Core can continue using the existing PowerShell collector. The app runs with the current user's permissions and does not automatically elevate, install a service or collect on a schedule.

## User flow

1. Confirm the automatically detected hostname and select one or more server roles, such as Web and Application.
2. Select **Collect inventory**. Review any warnings for inaccessible sources.
3. In **Network & primary IP**, review every adapter/address and choose the primary adapter/IP. Leaving it unselected permits a later choice in CVEHarbor. Existing dashboard primary choices are preserved during import.
4. Open **Review & export**. Filter the preview by product/version, read **Coverage & warnings**, and check the review confirmation.
5. Select **Export single CSV** and choose an existing writable folder. A unique inventory folder contains exactly one `cveharbor-assets.csv` and a `collection-report.json`.
6. In CVEHarbor select the correct customer and environment. Upload that CSV, review the preview, and choose **Import reviewed inventory**. The current customer/environment stays selected. Use **Assess in Customer Security Dashboard** to inspect potential vulnerability matches by server.

## Inventory and boundaries

Native read-only discovery covers Windows edition/build, 32/64-bit Programs and Features records, current-user installed products, .NET Framework registry releases, .NET runtime/SDK installation directories, IIS, and adapters with IPv4/IPv6 addresses. Side-by-side product versions remain separate. Identical product/version records are consolidated. Missing versions and inaccessible sources are reported. Product directory identity and affected-version checks remain the dashboard's responsibility.

No HTTP client, upload, AI request, credential collection, MSI repair query (`Win32_Product`), software installation, policy change or subprocess PowerShell execution is used. Folder opening is a user-triggered Explorer action. Coverage is not exhaustive: other users, portable software, containers, Store apps and bundled runtimes can be absent. Imports remain additive; stale versions require review.

CSV limits match the existing importer: 10 MB, 10,000 entries, 32 adapters, 128 addresses total and 64 per adapter. Oversized inventories fail explicitly instead of silently splitting or dropping networking. Formula prefixes are escaped. Network metadata is written once per hostname. An output folder is never reused or overwritten.

## Build and validation

`collector-app/build.ps1` compiles the C# source using the hosted Windows .NET Framework compiler. `collector-app/test.ps1` runs fictional-only export tests; `collector-app/test-import.mjs` imports those exact bytes with CVEHarbor's real parser. Tests cover primary selection, all adapter addresses, multiple roles, side-by-side .NET, duplicate rows, unknown versions, CSV quoting/formula prefixes, UTF-8 BOM, a single file larger than 128 KB, and rejected invalid roles/primary choices/oversized inventories.

The production website workflow builds on an isolated Windows 2022 runner with read-only repository access and no production environment or secrets. The tested ZIP passes to the existing Linux package check and protected publisher in the same run. A commit/hash receipt prevents use of a different revision's artifact. Source changes, package checks, application/security CI and owner-delegated production approval remain required.

This is a website-only release on the verified PR347 website. It adds the app ZIP and instructions, and changes the download section. Database, backend, Azure credentials, customer permissions and AI pause controls are unchanged. Recovery reference: website version `838db59b-fb84-40bc-a286-c6bd91352681`, deployment `4b6413e3-0623-49aa-a60a-d28ef1f55abf`.
