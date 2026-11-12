CVEHarbor Windows inventory collector

1. Download Export-CVEHarborInventory.ps1 into a local folder on the target server.
2. Review the script under your organization's normal script approval policy.
3. Open Windows PowerShell 5.1 or PowerShell 7 and run:
   .\Export-CVEHarborInventory.ps1 -ServerRole 'Web'
   This uses the computer hostname automatically. To override the displayed asset name:
   .\Export-CVEHarborInventory.ps1 -AssetName 'DEMO-WEB01' -ServerRole 'Web'
   Replace DEMO-WEB01 with the server's inventory name. Omit -AssetName to use the computer name.
4. Read collection-report.json and review cveharbor-assets.csv.
5. In CVEHarbor select the customer environment, upload cveharbor-assets.csv once,
   review the rows (use Next rows for larger inventories), and select Import reviewed inventory.
   Keep the page open while the progress indicator advances. The importer saves in
   small batches. You stay on the selected customer/environment after completion.
   Select Assess in Customer Security Dashboard when ready to view the findings.
   If interrupted, check the review confirmation and select Retry remaining inventory.
   After closing/reloading the page, select the same customer/environment and re-upload
   the same CSV. Saved identical rows are skipped. Older numbered files still work.

The script reads local inventory and only writes a new output folder. It does not
upload, call AI, install software, change execution policy, repair MSI packages,
or contact other servers. If your policy blocks scripts, use your approved signing
or execution process; do not bypass it. Access restrictions are reported. Running
with an approved elevated account may improve coverage but is not required to start.

Programs and Features data is read from machine 32-bit and 64-bit installation
records and the current user's records. Some hidden installer components can be
included; review before importing. Other user profiles, Store apps, containers,
portable software and application-bundled runtimes are not exhaustively discovered.
Optional -DotNetRoot accepts additional local .NET installation directories.

Each collector CSV has: Asset Name,Asset Type,Technology,Version,Notes,Server Network.
The optional Server Network column contains structured adapter/IP metadata. Existing
five-column templates still import unchanged.
One UTF-8 CSV is produced per collection, up to 10,000 rows / 10 MB. Network metadata
is included once per server, not repeated on every software row. Collection stops
with a clear error if this export limit is exceeded; rows are never silently dropped.
No secret values, license keys,
connection strings, installed-software command lines or environment dumps are collected.
Names and publisher metadata may still be confidential: review before uploading.
Exact duplicate product/version entries are consolidated. Distinct versions remain
separate rows. Existing matching rows are skipped. This is not inventory synchronization:
remove obsolete versions manually after verifying they are no longer installed.

Assessment uses the available CVEHarbor advisory index. It is not an authenticated
endpoint scan and does not prove exploitability or absence of vulnerabilities.
Unmapped software and missing versions remain explicitly unverified. AI stays paused.

Detection references:
https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations
https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
https://learn.microsoft.com/en-us/dotnet/core/install/how-to-detect-installed-versions

Server names and roles in the Customer Security Dashboard:
- Each server is grouped separately within its customer and environment.
- Optional -ServerRole accepts Web, Database, Application, Active Directory, File,
  Print, Remote Desktop or Other. Use -ServerRole 'Web','Application' for two roles.
- The role is supplied by you, not guessed from the hostname or installed software.
- The role is written at the start of Notes, for example: Server role: Database;
  Existing five-column CSV files remain compatible.
- Existing WEB, Database and Application asset types also supply a role. A generic
  Server entry without role information displays Not recorded.
- To correct an existing role, edit the Notes on all software entries for that server.
  Reimporting identical products does not update Notes. Conflicting roles are flagged.
- Expand a server card to see its installed versions and candidate CVEs. Software
  on another server or environment remains a separate assessment.

Network identification:
- All adapters reported by Get-NetAdapter -IncludeHidden are included, with locally
  assigned IPv4/IPv6 addresses, prefix lengths, connection and address states.
- No remote scan or DNS lookup is performed. Network addresses are not sent to AI.
- A unique preferred source on the lowest-metric default route suggests a primary
  (IPv4 first). Ambiguity leaves it unselected; this is not a management-network guarantee.
- The dashboard shows the primary IP; expand Network adapters & additional IPs
  to see each adapter and select an address. Owners/Editors can save the shared choice.
- Reimport updates network snapshots even when identical software rows are skipped.
  It preserves your primary choice and flags addresses missing from a newer snapshot.
- Same hostname in separate customer environments stays separate. Renaming an asset
  does not migrate its network metadata; recollect/import using its new inventory name.
- Address data is a snapshot, not live discovery. Recollect after network changes.
- Review collection-report.json for incomplete collection or export limits.
https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress
https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netroute
