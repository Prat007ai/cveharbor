# Native Cloudflare redirect handling

[Run 43049684872](https://github.com/Prat007ai/cveharbor/actions/runs/43049684872)
deployed PR339 successfully and verified the runtime identity and preserved bindings.
Serving package: `fc616f9638ee264a5ff28dfc5f9a116ec02e0c61fdf6fba16ee0c0bbf5436635`.
Worker version: `41283e33-513c-478d-a5a3-fd83baa9095f`.
The final probe returned HTTP 503 / `authentication_request_failed`.

Native workerd reproduces this before any outbound request: the Azure client used
`redirect: 'error'`, which Workers does not support. The earlier injected fetch tests did
not construct a native outgoing Request and missed this incompatibility.
[Cloudflare's Request documentation](https://developers.cloudflare.com/workers/runtime-apis/request/)
specifies `manual` or `follow`; `error` throws during construction.

Use `manual`. The existing non-2xx response check rejects every redirect. Credentials
are never automatically forwarded to a redirected destination. No retry, destination,
credential, permission or inference behavior is added.

The new CI runtime test executes the real global fetch implementation inside workerd,
routing every outbound request to another isolated local Worker. It verifies two calls
for successful fictional authentication/access and exactly one call when authentication
redirects. Unsigned and nonempty requests remain blocked. No Azure traffic or real
credentials are used. Node tests cover 301/302/303/307/308 at both authentication and
resource access and ensure diagnostic output omits redirect destinations.

Validation: 22 focused tests, 49 tests on the reconstructed production package, native
workerd success/redirect cases and Wrangler 4.156.0 dry run passed.
Candidate identity: `3e7311dc8ffb33a06324b3e7f601f801139b6ea74f5d39323f5dbff221169991`.
The release requires the serving predecessor above and preserves installed bindings and
the Azure client secret, refreshing only the 15-minute signed deployment probe.

Require specific owner PR merge approval and fresh exact-main/protected production
checks. Verify the deployed backend authenticates and reads Azure model metadata;
do not claim connectivity until both succeed. No database migration or customer AI
activation is included. Retain the predecessor version for separately authorized recovery.
Keep the coordinated daily-history deployment held until live handoff.
