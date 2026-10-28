# CVEHarbor.com — hourly vulnerability intelligence website

CVEHarbor is a public vulnerability **advisory index** with all 15 technology categories requested. It is entirely separate from Whitecap's Gmail automations and does not read those emails or any Whitecap infrastructure.

## Release status

- The website, browser-side search/filtering, data normalization and hourly publishing workflow are implemented in this package.
- It **has not been deployed to the Internet**. Until the first successful collection, the page deliberately displays *Awaiting first sync* and no advisory counts.
- No connected account or secret is included here.
- A GitHub repository owned by you, GitHub Pages and GoDaddy DNS must be configured before `cveharbor.com` will work.
- The collector relies on external feeds, which have their own delays and outages. An hourly schedule is a **target collection cadence**, not guaranteed immediate advisory publication.

## Initial data sources

1. [GitHub Global Security Advisories](https://docs.github.com/en/rest/security-advisories/global-advisories), including reviewed advisories and malware package advisories. Useful for PyPI, npm, NuGet, Composer and cross-product disclosures.
2. [NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) for recent and materially modified CVE records, vendor links, CVSS and product identifiers where available.
3. [CISA KEV JSON](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) to flag confirmed in-the-wild exploitation. This source is not evidence that a particular customer asset is compromised.

The site uses conservative category mapping and shows **source status**, date last checked and date last successfully refreshed. In case of a partial source failure, the page explicitly warns that the feed is incomplete and retains earlier records. CVE IDs are deduplicated across sources. Dates in advisories remain the vendor/NVD publication and modification dates, not the hour they were first indexed.

### Coverage limitations that matter before public launch

This initial implementation is **not exhaustive** across all 15 categories. It indexes matches from the above three sources; vendor-specific feeds are not yet integrated for Microsoft MSRC, Azure service advisories, Wordfence/Patchstack/WPScan, PHP.net, Python security releases, MariaDB, Oracle MySQL, Fortinet PSIRT, VMware/Broadcom, Ubuntu/Debian/Red Hat, Docker, Kubernetes and other products. Some vendor patch levels are absent in NVD and must be checked via official advisories. Further feeds, QA monitoring, uptime checks and a source review policy are needed before positioning the service as a comprehensive security monitoring service. Do not claim 100% coverage or guarantee one-hour disclosure.

## Install in your personally owned GitHub account

1. Create a **public GitHub repository** called `cveharbor` under your personal GitHub account, not Whitecap's account.
2. Upload this package including the hidden `.github/workflows/hourly-update.yml` folder to the `main` branch. GitHub Desktop or regular Git is the easiest way to preserve the complete directory structure.
3. In the repository, go to **Settings → Pages → Build and deployment → Source → GitHub Actions**.
4. In **Actions**, select **CVEHarbor hourly advisory sync**, then choose **Run workflow**. The first run will execute unit tests, pull advisories, update the dataset, and deploy GitHub Pages.
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

You need Python 3.12+ and optional Node.js. The collector uses the standard Python library, without installing third-party packages.

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
