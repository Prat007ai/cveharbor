# Brochure homepage and public intelligence overview

The homepage now presents the approved sample A product illustration, findings
and ticket-reference example, anonymised monitoring preview, platform explorer,
asset registration/import explanation, and marketing for both in-house IT teams
and providers managing clients. The existing public overview is at `/intelligence/`.
Home and Intelligence Overview are separate entries in the shared navigation.

The shared application DOM remains available for the existing scripts. CSS hides
the public statistics on the homepage and shows them on the intelligence route.
Private account, inventory, report and remediation APIs are unchanged. Customer
record labels remain where they identify actual application features.

Old `/#dashboard` and `/#methodology` bookmarks redirect to the new page. Overview
metrics and technology chart links preserve the selected scope, technology and
period when opening `/vulnerabilities/`.

## Public demonstration data

Homepage findings, counts, scores and ticket numbers are explicitly labelled
samples. Advisory description text was supplied during design review and is not
presented as verified exposure. The Bitwarden example identifies the product and
Entity Framework context, rather than attributing the issue to .NET generally.
Finding controls are disabled and cannot write private records. Actual findings
and reports remain in the signed-in application.

The monitoring image was generated locally with `Demo Customer` and
`https://demo.example/` and intercepted demo API responses. It contains no private
customer details. It shows demo reputation results while retaining the notice that
automated monitoring is not enabled. The platform explorer image is a local public
data snapshot; the surrounding caption explains that its counts may differ from
production. Both preview images are static, lazy-loaded assets. Feature links open
the real application pages.

## Validation

- 84 Python tests, 14 Worker test files, and all existing browser/customer smoke
  scripts passed.
- Local build and production preflight include `/` and `/intelligence/`.
- Playwright passed at 1366×768, 1920×1080, 2560×1440 and 390×844: no horizontal
  page/table overflow, sample controls disabled, images loaded, reduced-motion
  handling, auth link destinations, and no public demo API writes.
- Browser checks cover overview visibility, critical and technology chart
  drill-down filters, legacy overview bookmarks and both homepage advisory links.
- Screenshots are retained at `/workspace/production-review/`.

Build with `python3 scripts/build_site.py`, serve `public/` on local port 8080,
then run:

```sh
CVEHARBOR_PLAYWRIGHT_MODULE=/workspace/cveharbor-browser-tools/node_modules/playwright \
CVEHARBOR_CHROMIUM=/usr/bin/chromium \
CVEHARBOR_SCREENSHOTS=/workspace/production-review \
node scripts/homepage_visual_smoke.cjs
```

The optional module and browser overrides use external review tooling rather than
adding application runtime dependencies. Existing CI validates the build and core
browser smoke scripts; the Playwright regression is run in the prepared environment.
