# Homepage design review

Development branch: `design/homepage-hero`, based on GitHub main at `e14b175`.
This change has not been pushed, merged, or deployed.

The supplied approved mockup guides the composition: headline at left, orbital
shield and floating labels in the middle, angled severity card at right, dotted
wave below, and six capability links. The implementation uses responsive vector
artwork and one scoped homepage stylesheet. The historical hero selectors were
removed from the shared stylesheet; route visibility rules remain there.

Existing navigation, authentication links, capability destinations, and headline
are preserved. Sidebar and header screenshots were pixel-identical to the baseline
at all three desktop resolutions. The reference's sample severity counts are
intentionally absent: this decorative card does not claim to show live counts.
Source-backed wording is retained rather than claiming every advisory is verified.
The illustration approximates the mockup using scalable vector artwork; it is
not a pixel-identical reproduction of its rendered lighting and texture.

## Validation

Passed in the published development environment, using local committed data:

- 84 Python tests and 14 Worker test files.
- Existing browser, customer security, and customer score smoke scripts.
- Site build and production preflight (local generated files only).
- Playwright at 1366×768, 1920×1080, 2560×1440, and 390×844.
- No horizontal page overflow, clipped card, labels obscuring the card, or card
  overlapping capabilities. Six columns and both buttons share a row on desktop.
- Reduced-motion behavior, asset loading, severity and authentication link targets,
  primary button navigation, and no uncaught browser errors.

Screenshots are retained outside the checkout at
`/workspace/homepage-review/after/home-{1366,1920,2560,390}.png`.
Baseline screenshots are in `/workspace/homepage-review/before/`.
Visual review was against the supplied mockup; a separate production reference
image was not supplied. External requests are blocked in the visual tests so live
authentication and third-party services cannot affect the captures. No customer
records, production databases, email services, or live feeds were modified.

## Repeat locally

```sh
cd /workspace/cveharbor
python3 scripts/build_site.py
python3 scripts/verify_production.py --preflight
python3 -m http.server 8080 --bind 127.0.0.1 --directory public
```

In a second terminal, with Playwright and Chromium installed:

```sh
cd /workspace/cveharbor
CVEHARBOR_PLAYWRIGHT_MODULE=/workspace/cveharbor-browser-tools/node_modules/playwright \
CVEHARBOR_CHROMIUM=/usr/bin/chromium \
CVEHARBOR_SCREENSHOTS=/workspace/homepage-review/after \
node scripts/homepage_visual_smoke.cjs
```

Alternatively install `playwright` in your normal tooling location and omit the
module override; omit the Chromium override to use Playwright's installed browser.
Use the supported execution approval mechanism if the sandbox blocks local sockets
or browser processes. Keep application manifests and lockfiles unchanged when
installing external screenshot tooling.
