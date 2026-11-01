# Temporary development access

The temporary frontend gate uses browser-native HTTP Basic authentication.
Username: `cveharbor`. Its password is supplied through the GitHub repository
secret `SITE_GATE_PASSWORD`, then stored as an encrypted Cloudflare Worker
secret. No real password is included in source, browser JavaScript or artifacts.

Every page, script, data file and download passes through `cveharbor-site` before
the static asset binding. Missing/incorrect credentials return HTTP 401 with the
password challenge; missing configuration fails closed with HTTP 503. HTTP and
www requests canonicalize to HTTPS on the apex. Protected responses are private,
not cached, and marked noindex.

The existing account API (`api.cveharbor.com`), authentication, database and email
settings are separate. Scheduled alerts read the existing committed public
advisory snapshots directly from GitHub so a frontend password does not interrupt
delivery. The gate does not change GitHub repository visibility.

## Activation requirements

- Existing `CLOUDFLARE_ACCOUNT_ID` repository secret.
- Dedicated `CLOUDFLARE_SITE_API_TOKEN` repository secret, scoped to the account
  containing cveharbor.com, with Account / Workers Scripts / Edit and Account /
  Account Settings / Read; and to that zone with Zone / Zone / Read, Zone / DNS /
  Edit, and Zone / Workers Routes / Edit. Backend deployment retains its original
  `CLOUDFLARE_API_TOKEN`.
- `SITE_GATE_PASSWORD`: a single-line password of at least 16 characters. Enter
  this only through GitHub's encrypted secrets UI, not chat or a committed file.

The normal deployment workflow checks credentials and reads routing first. An
initial deployment verifies a protected staging Worker before frontend changes.
It installs asset-backed routes and proxies only existing apex/www DNS records;
their origin addresses remain intact. Mail, TXT and api records are not changed.
Recurring releases update the same Worker without withdrawing its live routes.

Production verification authenticates with the encrypted CI password and checks
the exact pages, scripts and feed exports against the built files. Only after
that verification is the old public GitHub Pages origin disabled, preventing
direct-origin access around the website gate. Pages-write permission is retained
solely for that cleanup. No full-site public Pages artifact is uploaded.

The read-only `Check temporary site gate hosting` development workflow reports
token permissions and password readiness as booleans, without secret values.

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
