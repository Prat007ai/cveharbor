# Installed product assessment

Accepted agent collections register their active inventory with the existing CVIE
queue. First inventory approval starts this work; subsequent daily uploads include
newly observed products without requiring an open browser. Source work continues
under existing provider budgets, leases and retry intervals. An inventory upload
does not wait for NVD. Retired agent observations are excluded from subscriptions;
manual entries and source history remain intact.

Exact reviewed display names map automatically. Unknown inventory names receive
one resumable directory lookup. A result is accepted only when the complete lookup
has one family and its vendor/product name matches exactly. Ambiguous, limited or
empty results require identity review; they do not mean that software is safe.
Explicit existing product selections take precedence over repairs.

## Reviewed display-name families

The installer suffix patterns are deliberately product-specific. In particular,
FileZilla Server is not the FileZilla client; WebView2 and Copilot are not Edge;
ESET Management Agent is not Endpoint Security; KeePassXC is not KeePass.
Adobe Acrobat release tracks, Office components, Vantage Service, drivers and
unidentified Windows releases remain subject to exact identity review.

Primary identity evidence:

- [Chrome CPE](https://nvd.nist.gov/products/cpe/detail/7aa7c8f2-9fe2-46b6-a623-3a6d49bcef1d)
- [Edge Chromium CPE](https://nvd.nist.gov/products/cpe/detail/9843e906-6b6b-4fe5-9f5d-6fd049409f5f)
- [Firefox directory](https://nvd.nist.gov/products/cpe/search/results?keyword=cpe%3A2.3%3Aa%3Amozilla%3Afirefox)
- [FileZilla client identity](https://nvd.nist.gov/vuln/detail/CVE-2016-15003)
- [FortiClient Windows CPE](https://nvd.nist.gov/products/cpe/detail/1687588)
- [ESET Endpoint Security identity](https://nvd.nist.gov/vuln/detail/CVE-2023-7043)
- [KeePass identity](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)
- [Notepad++ identity and escaped CPE name](https://nvd.nist.gov/vuln/detail/CVE-2025-15556)
- [AdGuard current Windows family](https://nvd.nist.gov/products/cpe/detail/28767D46-BFEE-43C6-BFB2-21D28EEDA500)
- [OneDrive Windows family](https://nvd.nist.gov/products/cpe/detail/a41dbe10-ee83-4b62-8310-053884b811b4)

Python's existing reviewed family also accepts the exact Windows Core Interpreter
installer name. Assessment uses the runtime release explicitly embedded in that
name only when the observed version agrees with the runtime release or the
[CPython final-release MSI encoding](https://github.com/python/cpython/blob/v3.12.10/PCbuild/python.props), retaining the observed MSI version for display. Other Python installer
components are not assumed to be independently installed interpreters.

## .NET compatibility records

Microsoft documents [the Full Release registry value](https://learn.microsoft.com/dotnet/framework/install/how-to-determine-which-versions-are-installed)
as the .NET Framework 4.5+ version indicator. The existing agent also observes
the v4.0 compatibility key. The backend omits that exact 4.0.0.0 registry artifact
from the assessed projection only when the same collection contains a consistent
Full Release observation. Standalone 4.0, older frameworks, modern .NET runtimes,
other devices and manual inventory are preserved. Original uploads stay in history
and replay validation still hashes the original submitted collection. Existing
devices receive the corrected projection on their next successful complete sync;
no installer replacement is required for this correction.

## Status and limits

Each installed entry shows mapping, queue, progress, source failure, stale results,
missing version, partial coverage or candidate status. No-match wording requires
completed fresh checks and complete loaded results. It describes the selected
history window, not proof of safety. Platform-specific CPE ranges for mobile,
macOS and Linux do not establish exposure on a Windows agent installation.

Agent details expose only product-check metadata for that authorized device's
inventory. Organization-only views must never borrow the signed-in user's personal
CVIE state. Inventory collection, source discovery and installed-version assessment
are separate stages; a successful upload does not imply a completed CVE check.

## Coordinated historical capacity checks

The credential-free security and capacity regression jobs reconstruct PR389 at
84553046ee8313723702a4db24a1df198abbb518, with its historical agent regression test.
They are explicitly historical checks, not approval of a future capacity candidate.
Current-source tests and the dedicated installed-products package checks remain
separate. The capacity cloud workflow and production gate still use the current
capacity builder and must fail closed until its owner rebases the package onto the
then-serving product release. This boundary was coordinated with the active
Locate Azure OpenAI chat; its resources and PR390 remain outside this change.
