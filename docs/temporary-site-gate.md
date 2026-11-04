> **Current operations:** Follow [the administrator checklist](reviews/phase1-administrator-checklist.md) and its approval sequence. The frontend gate remains unchanged; do not remove it or redeploy merely to configure staging.

# Temporary development access

The temporary frontend gate uses browser-native HTTP Basic authentication.
Username: `cveharbor`. Its password is supplied through the `cloudflare-site-production` GitHub environment
secret `CVEHARBOR_SITE_GATE_PASSWORD` (mapped to process/runtime `SITE_GATE_PASSWORD`), then stored as an encrypted Cloudflare Worker
secret. No real password is included in source, browser JavaScript or artifacts.

Every page, script, data file and download passes through `cveharbor-site` before
the static asset binding. Missing/incorrect credentials return HTTP 401 with the
password challenge; missing configuration fails closed with HTTP 503. HTTP and
www requests canonicalize to HTTPS on the apex. Protected responses are private,
not cached, and marked noindex.

The existing account API (`api.cveharbor.com`), authentication, database and email
settings are separate. Before the approved R2 cutover, digests retain the legacy committed GitHub source.
After cutover, digests and lifecycle notifications read the private R2 binding
directly, independently of the frontend gate; the eight-hour/three-day limits remain. The gate does not change GitHub repository visibility.

## Activation requirements

- `CVEHARBOR_PROD_ACCOUNT_ID` in the protected site environment.
- Dedicated `CVEHARBOR_PROD_SITE_TOKEN` environment secret, scoped to the account
  containing cveharbor.com, with Account / Workers Scripts / Edit and Account /
  Account Settings / Read; and to that zone with Zone / Zone / Read, Zone / DNS /
  Edit, and Zone / Workers Routes / Edit. Backend deployment uses separate protected `CVEHARBOR_PROD_WORKER_TOKEN`; no fallback is allowed.
- `CVEHARBOR_SITE_GATE_PASSWORD`: the existing single-line password of at least 16 characters. Enter
  this only through GitHub's encrypted secrets UI, not chat or a committed file.

The normal deployment workflow checks credentials and reads routing first. An
initial deployment verifies a protected staging Worker before frontend changes.
It installs asset-backed routes and proxies only existing apex/www DNS records;
their origin addresses remain intact. Mail, TXT and api records are not changed.
Recurring releases update the same Worker without withdrawing its live routes.

Production verification authenticates with the encrypted CI password and checks
application assets against the build; R2 data exports are verified at a single
immutable feed version rather than compared with the checkout snapshot. Only after
that verification is the old public GitHub Pages application retired, preventing
direct-origin access around the website gate. If GitHub requires administrator
permission to unpublish Pages, its content is replaced with a small retirement
notice containing only a link to the protected site. Pages-write permission is
retained solely for that cleanup. No full-site public Pages artifact is uploaded.

The read-only `Check temporary site gate hosting` development workflow reports
token permissions and password readiness as booleans, without secret values.
It does not deploy feature-branch code to production. Production publishing
continues through the normal main-branch workflow.

## Removing the gate when ready

Change `SITE_GATE_ENABLED` to the string `"false"` in `site-gate/wrangler.json`
and run the normal deployment workflow. The same frontend becomes public without
moving or changing customer data. Backend account login is still required for
private customer functions. Do not simply delete the password while the gate is
enabled: that intentionally leaves the frontend unavailable rather than public.

## Validation

Node gate tests cover credentials, malformed/incorrect headers, UTF-8 passwords,
all asset paths, HEAD/POST, HTTPS redirects, disabled mode and fail-closed
configuration. Python deployment tests cover safe routing, staging failure,
recurring updates, credential redaction and origin-scoped CI authentication.

Local Workers-runtime testing uses a fixture password, never the real secret:

```sh
python3 scripts/build_site.py
npx --yes wrangler@4.156.0 dev --config site-gate/wrangler.json --local --infer-origin-from-routes=false --ip 127.0.0.1 --port 8899 --var SITE_GATE_PASSWORD:fixture-only-strong-password
```

Do not expose this fixture server publicly. Local validation confirmed 20
canonical pages/assets/downloads are denied anonymously and the original bytes
are served after successful authentication. The production gate is not active
until its deployment and anonymous/authenticated verification both succeed.
