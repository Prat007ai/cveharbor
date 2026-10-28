# CVEHarbor.com — hourly vulnerability intelligence website

CVEHarbor is a public vulnerability **advisory index** with 38 technology groups, including thirteen categories identified in public Whitecap service and careers materials. It is entirely separate from Whitecap's Gmail automations and does not read those emails or any Whitecap infrastructure.

## Release status

- The website, browser-side search/filtering, data normalization and hourly publishing workflow are implemented in this package.
- The site is published through GitHub Pages. Each GitHub Actions run should be checked for publication and upstream feed health.
- No connected account or secret is included here.
- The live site uses the personal `Prat007ai/cveharbor` GitHub repository and `cveharbor.com` DNS.
- The collector relies on external feeds, which have their own delays and outages. An hourly schedule is a **target collection cadence**, not guaranteed immediate advisory publication.

## Initial data sources

1. [GitHub Global Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories), including reviewed advisories and malware package advisories. Useful for PyPI, npm, NuGet, Composer and cross-product disclosures.
2. [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for recent and materially modified CVE records, vendor links, CVSS and product identifiers where available.
3. [CISA KEV JSON](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to flag confirmed in-the-wild exploitation. This source is not evidence that a particular customer asset is compromised.

The site uses conservative category mapping and shows **source status**, date last checked and date last successfully refreshed. In case of a partial source failure, the page explicitly warns that the feed is incomplete and retains earlier records. CVE IDs are deduplicated across sources. Dates in advisories remain the vendor/NVD publication and modification dates, not the hour they were first indexed.

### Coverage limitations that matter before public launch

This initial implementation is **not exhaustive** across all 38 categories. It indexes matches from the above three sources; vendor-specific feeds are not yet integrated for Microsoft MSRC, Azure service advisories, Wordfence/Patchstack/WPScan, PHP.net, Python security releases, MariaDB, Oracle MySQL, Fortinet PSIRT, VMware/Broadcom, Ubuntu/Debian/Red Hat, Docker, Kubernetes and other products. Some vendor patch levels are absent in NVD and must be checked via official advisories. Further feeds, QA monitoring, uptime checks and a source review policy are needed before positioning the service as a comprehensive security monitoring service. Do not claim 100% coverage or guarantee one-hour disclosure.

## Install in your personally owned GitHub account

1. Create a **public GitHub repository** called `cveharbor` under your personal GitHub account, not Whitecap's account.
2. The website source and automated collector are committed to `main`. The hourly job is part of `.github/workflows/bootstrap.yml`, so no separate workflow file is needed.
3. In the repository, go to **Settings → Pages → Build and deployment → Source → GitHub Actions**.
4. In **Actions**, select **CVEHarbor setup and hourly sync**, choose **Run workflow**, check the **deploy** input, and run it on `main`. That run executes unit tests, pulls advisories, updates the dataset, and deploys GitHub Pages. Leave **deploy** unchecked only to rerun the one-time source restore.
5. Confirm the workflow succeeds, confirm the public Pages preview URL, and verify **Last success** and individual feed status indicators on the page. If GitHub, NVD or CISA blocks a request, the banner must indicate partial or degraded coverage.
6. For a stable production service, optionally request an NVD API key and store it under **Settings → Secrets and variables → Actions → New repository secret** as `NVD_API_KEY`. Never put API keys in source files. GitHub's automatically generated `GITHUB_TOKEN` is already used for the GitHub advisory API.
7. Enable GitHub Actions failure notifications in the GitHub account, then add a third-party uptime monitor if you want an independent alert when publication stops.

### Automated update logic

`17 * * * *` is **minute 17 of every hour (UTC)**. The nonzero minute avoids GitHub's heaviest scheduler traffic. GitHub may delay or occasionally drop a scheduled run. Public repository schedules may be disabled after 60 days without activity, so operational monitoring is necessary. Triggering **Run workflow** manually does not change the hourly schedule.

During each successful run the workflow:

- Downloads official/public feed records and only categorizes disclosures that appear relevant to the website's technology groups.
- Preserves earlier records and deduplicates matching CVE identifiers.
- Marks exploitation as confirmed only if the CVE is in CISA KEV.
- Carries forward vendor references and patch versions **when present in the source**. Otherwise it says the information is not provided rather than guessing.
- Writes `data/advisories.json` and `data.js`, updates source health and timestamps, commits the state, and publishes GitHub Pages.
- If all sources fail, retains earlier records, marks the dashboard degraded and fails the workflow rather than claiming a new successful collection.

## Connect CVEHarbor.com at GoDaddy

**Only after the Pages site is deployed and assigned in your GitHub repository**, configure the custom domain `cveharbor.com` in GitHub Pages and use its verification instructions. Then, in GoDaddy DNS for `cveharbor.com`, add the GitHub Pages apex records listed in the official [GitHub Pages documentation](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site/managing-a-custom-domain-for-your-github-pages-site):

| Type | Name | Value |
| --- | --- | --- |
| A | @ | 185.199.108.153 |
| A | @ | 185.199.109.153 |
| A | @ | 185.199.110.153 |
| A | @ | 185.199.111.153 |
| CNAME | www | YOUR-GITHUB-USERNAME.github.io |

Use your actual GitHub username for `www`, leave unrelated MX/TXT records unchanged, and follow GitHub's exact domain verification procedure. Enable **Enforce HTTPS** after the certificate provisions. Domain changes may take time to propagate. The repository includes a `CNAME` file with `cveharbor.com`. Keep control of GoDaddy registration, GitHub organization/repository and all secrets in your own accounts.

## Running and testing locally

You need Python 3.12+ and optional Node.js. The collector uses the standard Python library, without installing third-party packages. The hourly schedule and manual deployment entrypoint are configured in `.github/workflows/bootstrap.yml`. GitHub Pages must be enabled first.

```bash
python -m unittest discover -s tests -v
python scripts/update.py
python scripts/build_site.py
python -m http.server 8080 --directory public
```

Browse `http://localhost:8080` after the first sync. Browser JavaScript files and generated JSON are public by design and contain no credentials. The only sample advisory dataset is under `data/demo-advisories.json`, and `build_site.py` explicitly **does not deploy it**.

## Suggested production enhancements

- Add official vendor feed adapters for the products most important to your intended audience, with documented licensing and terms of use.
- Add exact CPE/pURL mapping, a vulnerability review queue, source confidence tags, unit and integration checks, and audit history for changes to exploitation or patch status.
- Introduce alerting when scheduled runs fail or source data is over two hours old, plus uptime checks from a different infrastructure provider.
- Provide an editorial corrections/contact policy and privacy notice before accepting subscriber emails. Avoid collecting any private asset inventory from site visitors without consent.

## Ownership and separation

The website is designed for **personal ownership**, under the `cveharbor.com` domain purchased through GoDaddy. Neither the Whitecap Urgent CVE Alerts task nor its Gmail sending settings is modified by this code. This website pipeline never uses `prat.chatgptai@gmail.com`, never sends mail, and does not access Whitecap client assets.


## Website navigation and categories

The website displays all 38 tracked technologies in four grouped panels. Each technology shows its latest originally published advisories and can be opened to show a filtered list with original disclosure dates. Each panel header also opens the combined section. The advisory view supports card previews and a full list of indexed advisories. The .NET / ASP.NET category is a combined overview, with .NET Core as a modern-runtime subset. Windows Server OS, Windows 11 OS and HyperV have separate filters.


## Additional vendor sections and initial CVE records

Dedicated coverage now includes Progress Telerik, Sitefinity, Veeam Backup & Replication, Sophos Firewall, Windows 11 OS and Exchange Server Subscription Edition. All 38 technologies appear in four grouped panels, with day-specific badges and filters for newly published advisories. A curated vendor baseline at `data/vendor-baseline.json` seeds dated, source-linked advisories for the new sections. Those entries retain their original disclosure and update dates and are never characterized as newly disclosed or verified exploited simply because they were recently indexed. They are supplemented and deduplicated with the automated NVD, GitHub Advisory Database and CISA KEV feeds every hour. This coverage is not a vendor-certified comprehensive vulnerability database; continue reviewing official advisories for urgent patch decisions.

## Whitecap website technology gap analysis (October 27, 2026)

The [Whitecap custom software technologies page](https://www.whitecapcanada.com/services/custom-software-development/), [Whitecap careers](https://www.whitecapcanada.com/careers/), [Whitecap partners](https://www.whitecapcanada.com/partners/), and [Whitecap application modernization](https://www.whitecapcanada.com/services/application-modernization/) provide public evidence of capabilities including Angular, React, JavaScript / TypeScript, Kendo UI, Microsoft SharePoint, Power Platform, Dynamics 365, Fabric / Power BI, Azure AI, NoSQL, and mobile application development; AWS appears in Whitecap modernization materials. These statements describe Whitecap's service and development capabilities, **not a validated inventory of Whitecap or client production systems or versions**.

CVEHarbor expanded from 25 to 38 groups. The 13 additions are Angular, React / Next.js, JavaScript / TypeScript, jQuery / Bootstrap, Kendo UI, SharePoint / SharePoint Server, Microsoft Power Platform, Dynamics 365, Microsoft Fabric / Power BI, Azure AI / AI SDK, NoSQL / MongoDB, AWS, and iOS / Android. Subproducts such as MongoDB or Next.js are examples within broader product families, not independently verified Whitecap production installations.

The dated initial advisories for new groups include Angular CVE-2026-111753, React's October 2026 GHSA-xqc2-xf4c-x3h3 without an assigned CVE, historical React CVE-2025-55182, SharePoint CVE-2026-70266 and CVE-2026-70259, Kendo UI CVE-2025-6725, and MongoDB CVE-2025-14847. Do not count a GHSA without a CVE as a unique CVE. Each record links to original project/vendor advisories, and updates/fixes require confirmation with the latest vendor guidance. For Microsoft managed SaaS services, local patching is generally different from product configuration or connector updates. **A zero category count means no indexed matching advisory, not that a technology was checked exhaustively or is safe.**

Hourly scheduled checks still use GitHub, NVD, CISA KEV, and the separately implemented PHP upstream feed. This is not a complete coverage guarantee for every new category, especially SaaS products, hosted applications, Kendo UI and third party SDKs. Additional vendor API integration should be added before asserting comprehensive, near-real-time security coverage.

## October 28, 2026 verification and source limitations

The dashboard now exposes each scheduled collection's health in the page header and footer. The hourly collector also writes `data/feed-health.json`, which is included as `feed-health.json` in the GitHub Pages site on each successful data publication. It reports per-source success, last attempted and successful timestamps, indexed record counts, and whether the bounded public index has reached its capacity.

Every change to the tracked site files runs automated tests. Pull requests run tests and public build verification before merge. Publishing uses the main branch. After site edits on main, the collector refreshes the feeds before deploying, and scheduled runs continue every hour at minute 17 UTC. GitHub's schedule is best effort and may be late or skipped. A partial source collection is published with a visible warning and the workflow is marked failed so the operator can investigate. Configure GitHub Action failure notifications and an independent uptime and freshness alert before relying on this feed for operational decisions.

The indexed advisories are not exhaustive, and their categories are inferred conservatively from source evidence. The rolling NVD collection windows, public GitHub advisory feed pagination, catalog size limits, vendor coverage gaps and the API providers' own processing delays can all prevent a new vendor disclosure from appearing promptly. Do not substitute the site for Microsoft MSRC, Linux security notices, Fortinet PSIRT, WordPress ecosystem advisories, vendor patch channels or a deployed-version inventory.

## Additional vendor feeds (October 28, 2026)

The hourly collector now also attempts Microsoft Security Update Guide RSS, Fortinet PSIRT RSS, Ubuntu Security Notice RSS, and incremental OSV public data exports. These integrations are tracked separately in feed health and only publish source records with recognized CVE or GHSA IDs. RSS notices without trustworthy original dates or identifiers are skipped rather than being invented. Each successful source is merged into the original four-source dataset with deduplication by advisory ID.

Wordfence Intelligence v3 adapter is available but disabled until the repository owner adds the `WORDFENCE_API_KEY` secret to GitHub Actions. The API key must never be committed. Create the key from the Integrations section of a Wordfence account and confirm its use complies with their current terms. When the secret exists, the hourly collector will attempt the authenticated Wordfence feed. A source marked OK means its endpoint responded, not that all vendor vulnerabilities were captured.

Other requested vendor sources, including Debian, Red Hat, Broadcom/VMware, MySQL, MariaDB, PostgreSQL, Docker/Kubernetes and Patchstack, remain future integrations. Some require authenticated endpoints, custom adapters or access terms. Their absence is not evidence of a safe product. Always check primary vendor guidance before actioning production patches.

## Additional official adapters

Debian Security Advisories, Docker Security Announcements, Kubernetes official CVE JSON feed and MariaDB's upstream GitHub security advisories are configured as separate hourly sources. Feed health must be consulted to confirm live availability. The OSV bulk modified-ID export is temporarily disabled after a size-limit error in production, pending a bounded API implementation. Red Hat, Broadcom, PostgreSQL and the other database sources are still pending vetted adapters. Wordfence remains optional until its API key is supplied.

## Network threat IP intelligence

The site has a separate, review-only page of public IP indicators derived from SANS Internet Storm Center's top observed source IPs and Feodo Tracker's active botnet command and control IP blocklist. Data is collected at most hourly as part of the existing workflow and each source is labeled separately. The public list includes the source, activity classification and actual collection time but never implies source-reported last-seen time without evidence. Validate an address against local logs, cloud-provider infrastructure and trusted scanner allowlists before blocking. This is not a CVE scanner nor a production-ready automatic blocklist. A failed or empty feed is shown as unavailable and never means the network is secure.
