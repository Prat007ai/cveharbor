CVEHarbor Windows Collector 1.0.0 — evaluation build

1. Extract the ZIP into a local folder on the server. Keep the EXE and its .config together.
2. Open CVEHarbor-Collector.exe by double-clicking it. No PowerShell commands are needed.
3. Choose the server role(s), for example Web and Application. The hostname is automatic.
4. Click Collect inventory. Select the primary adapter/IP or leave it unselected.
5. Open Review & export. Inspect products, versions, Coverage & warnings.
6. Check the review confirmation, click Export single CSV, and choose an output folder.
7. Open the output folder. In CVEHarbor select the customer/environment and upload
   cveharbor-assets.csv. Review and import; then open Customer Security Dashboard.

Windows x64 Desktop Experience; .NET Framework 4.8 or later required. Server Core
does not support this graphical app; use the existing PowerShell collector there.
The app starts with your current permissions and does not request elevation.
Restricted reads appear as warnings. Run under an approved administrator account
only if required by your organization's inventory policy. It does not change policy.

UNSIGNED EVALUATION BUILD: no trusted publisher certificate is included. Follow
your organization's software approval process. Do not disable Windows security,
SmartScreen or application control to run it. Trusted signing is required for a
verified-publisher distribution. SHA256SUMS.txt identifies this specific binary;
an unsigned checksum is not proof of publisher identity.

Collection is local and read-only. The only writes are the output folder you choose.
No background agent, installer, service, scheduled task, telemetry, AI, automatic
upload, external IP lookup, DNS lookup, port scan or software repair is performed.
The app reads OS build, machine 32/64-bit and current-user Programs and Features
records, .NET Framework registry versions, standard .NET directories, IIS and network
interfaces. Other profiles, Store apps, containers, portable programs, bundled runtimes
and nonstandard .NET locations may be missing. Directory presence does not prove usage.
It does not read license keys, credentials, connection strings or uninstall commands.

One UTF-8 CSV (with BOM) plus collection-report.json is written into a unique folder.
Existing exports are not overwritten. Identical product/version entries consolidate;
side-by-side versions remain separate. Maximum 10,000 rows / 10 MB. Exceeding an export
limit stops the CSV export with an error, not a silently truncated inventory.
Network import limits: 32 adapters, 128 total addresses, 64 per adapter, 14KB JSON.
Every detected adapter/address is exported, including disconnected adapters. The
selected primary is a suggestion on first import. An existing primary selection in
CVEHarbor is retained; change it in the dashboard if necessary. No primary is guessed.

Review before uploading: hostnames, installed products and network addresses may be
confidential. Imports are additive; obsolete versions must be reviewed manually.
Vulnerability results are potential advisory matches, not confirmed exploitability.

For a fictional UI walkthrough, launch the EXE with --demo. Automated self-tests use
--self-test <output-folder> and never collect the local machine. AI remains paused.

Sources:
https://learn.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
https://learn.microsoft.com/en-us/dotnet/core/install/how-to-detect-installed-versions
https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations
https://learn.microsoft.com/en-us/dotnet/api/system.net.networkinformation.networkinterface.getallnetworkinterfaces
