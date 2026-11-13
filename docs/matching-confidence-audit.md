# Shared matching and applicability audit

Scope: shared browser assessment rules and their presentation in personal and organization dashboards, inventory, server views, customer reports/print/CSV and workspace AI priorities. This is a code and controlled-reference audit, not an inspection of every customer's servers or a complete vendor-coverage certification.

## Findings and corrections

| Finding | Correction | Verification |
| --- | --- | --- |
| Broad product fallback could reintroduce structured exclusions for custom products | Share the structured-range decision before fallback | Affected/fixed/unknown/pending matrix across 14 named product families |
| Pending/stale original evidence could still exclude or promote candidates outside .NET | Preserve as needs verification consistently | Both inside and outside stored bounds remain reviewable while updates are pending |
| A range in prose could belong to another component or branch | Compare only complete single-product range statements | Compound MySQL/dependency/branch statements remain review candidates |
| CPE `-` and contradictory bounds could look comparable | Treat as unsupported evidence | Not-applicable marker, inverted/empty ranges and unsupported version tests |
| Affected .NET ranges could override explicit unaffected exceptions | Retain ambiguity for verification | Overlapping affected/unaffected CNA fixture |
| Windows, IIS and Framework release numbers could imply patch applicability | Require servicing evidence; retain structured identities even if display aliases differ | No version assertion from generic numeric comparison |
| Mixed-confidence headline counts and inconsistent labels | Central applicability projection used by shared UI surfaces | Personal/organization, report, print, inventory and workspace checks |
| AI could interpret an uncertain candidate as remediation-ready | Include status and missing evidence; verification guide for uncertain findings | Prompt admission/privacy and no automatic verification tests |

## Status contract

- `affected_version` / **Affected version detected**: supported version comparison only. Platform, package provenance, patch state and application prerequisites still require checking.
- `needs_verification` / **Needs verification**: identity, version, servicing or current source evidence is insufficient. Show the reason; do not silently hide the candidate.
- This release does not generate **Applicability verified**, **Fixed**, or **Not applicable** from a version match, AI answer, severity or saved remediation status. A future verified state requires attributable, scoped evidence and freshness/revalidation rules.
- Existing user-recorded remediation states remain separate and unchanged. CSV retains its existing columns and appends applicability and required-verification columns.
- A confirmed incompatible range is excluded from candidate lists, without marking the asset fixed or asserting complete coverage.

## Reference coverage

Synthetic structured-range matrix: PHP, WordPress core/plugins, MySQL, MariaDB, SQL Server, Python, FortiOS, Docker, Kubernetes, OpenSSL, Apache HTTP Server, NGINX and Progress Sitefinity. This exercises shared algorithm behavior, not vendor-specific certification for those products. Additional tests cover Windows/Server/IIS/Framework servicing, modern .NET components and branches, Debian/Ubuntu versus package inventory, vendor package revisions, source freshness, preserved CNA rows and host/environment isolation. Previous PHP versus application/plugin exclusions and Windows Server release tests remain required.

## Limits and next stages

- Numeric ranges cannot evaluate every vendor scheme, Linux backport, architecture, platform or configuration prerequisite. Unsupported evidence stays reviewable; no match is not proof of safety.
- NVD configuration relationships remain source evidence, not independently verified endpoint conditions. No finding is labelled applicability verified by this implementation.
- Current inventory completeness is not source coverage or match accuracy. Existing provisional scores must not be treated as verified risk ratings.
- Background assessment/storage, improved endpoint collection, source-queue recovery and a cross-customer live-data audit are not implemented by this frontend release. Source outages and slow exports require separate investigation.
- AI guide specificity and vendor remediation evidence are a subsequent requested task; this change only establishes the applicability contract.

Reference models: [NVD applicability statements](https://nvd.nist.gov/vuln/Vulnerability-Detail-Pages), [CSAF/VEX product status](https://docs.oasis-open.org/csaf/csaf/v2.1/csaf-v2.1.html). CVEHarbor's version-match state is deliberately weaker than a verified affected assertion.
