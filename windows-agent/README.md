# CVEHarbor Windows Agent — evaluation

This release is **unsigned and intended for testing and demos**. Windows may display an unknown-publisher or Microsoft Defender SmartScreen warning. Follow your organization's software approval policy; do not disable Windows protection to install it.

Requires x64 Windows 10/11 or Windows Server 2016 or later with .NET Framework 4.8. Use an administrator account for installation and enrollment. The running service uses LocalService with its own service identity.

1. In CVEHarbor, choose the customer and environment, then open **Register asset and technology stack → Connect Windows Agent**.
2. Acknowledge the evaluation notice, download the MSI and create a one-time enrollment code. Each device needs its own code; codes expire after 15 minutes.
3. Install the MSI. Open **CVEHarbor Agent Setup** from the Start menu and enter the code. On Server Core, run the installed `CVEHarbor-Agent-Enroll.exe` as administrator; the code is entered interactively, never as a command-line argument.
4. Keep the customer wizard open. The device card appears automatically. Expand it, review the software and assignment, select its primary IP if necessary, then choose **Confirm inventory and assess**.
5. Accepted inventory is refreshed daily while the server is online. **Sync now** queues a request; the device normally checks within five to six minutes. Offline devices retain a bounded, encrypted pending collection and retry after reconnecting.

Collection covers Windows version, machine-wide installed software, .NET runtimes/SDKs, IIS, network adapters and addresses. Per-user installations, portable applications and embedded runtimes may be absent. An incomplete collection retains earlier software observations instead of declaring them removed. Version evidence does not establish that a vulnerability is exploitable or patched.

Suspicious uploads are rejected before changing accepted inventory. Repeated malformed uploads, oversized bodies, authenticated request floods and unexpected mass removal suspend the affected device. Trusted customer security contacts (or the account/organization owners) and CVEHarbor support receive separate email notifications. Provider acceptance is not a delivery guarantee; ambiguous submissions are flagged rather than blindly resent. Review incidents in the device card. If a credential may be compromised, revoke it; after repairing the server, use **Reconnect this device** to preserve its identity/history with a new credential and first-inventory review.

The agent only makes outbound HTTPS requests to `api.cveharbor.com`. It has no inbound listener or remote-command facility. Device credentials cannot read CVEHarbor dashboards or other customer data. A compromised machine can still misreport its own inventory; syntactically valid lies cannot all be detected. Local administrator compromise can also access that device's credential. Revocation and server-side authorization remain necessary.

`C:\ProgramData\CVEHarborAgent\status.txt` contains a bounded latest-status message without credentials or raw inventory. Protected state is encrypted with Windows DPAPI and restricted to administrators, SYSTEM and the service identity. MSI upgrades preserve enrollment and pending inventory; uninstall removes local agent state. There is no automatic binary updater in this version.

## Build and future signing

Run `build.ps1`, `test.ps1`, then `package.ps1 -OutputDirectory <fresh-folder>` in PowerShell on Windows. The package command refuses to overwrite an existing MSI. Installation tests are restricted to disposable GitHub-hosted Windows runners and are never run against a developer/customer service.

When a certificate is available, sign and timestamp each EXE/DLL before packaging, then use `package.ps1 -Production -PublisherThumbprint <thumbprint>`. Sign and timestamp the resulting MSI too, validate all signatures and repeat the installer tests before release. Signing future upgrades does not require rebuilding the customer enrollment design. A trusted signature identifies the publisher; it cannot guarantee that Windows will never warn.
