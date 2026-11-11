# Cloudflare empty-request verification fix

Production run [43044126176](https://github.com/Prat007ai/cveharbor/actions/runs/43044126176)
successfully deployed the reviewed Azure connection backend, then failed its signed access check.
The deployed package is `f903b738021362b5a008a8b9704481699af4b9cc41c49d2f8ae75503d8d87abc`,
Worker version `2903d394-c38d-4f8b-8e63-0bc8b2253379`. Readiness remained healthy.
The Azure credential was installed; the failed check does not establish an Azure authentication failure.

## Reproduction and correction

Cloudflare workerd presents an empty HTTP POST as a non-null empty body stream.
The original probe rejected that request before authentication with Azure. Node's bodyless
Request constructor concealed this difference in the original unit test.

The probe now validates its existing release-bound, expiring HMAC before reading at most
one body chunk. Only EOF is accepted. Any chunk, including whitespace, is rejected without
calling Azure. Host, path, timestamp, signature, recovery-hold and destination checks remain.

The successor release accepts only the already-serving package above. It requires all
installed Azure bindings to match, preserves the installed Azure client secret and other
bindings, and refreshes only the 15-minute encrypted deployment probe. It checks the
retrievable predecessor version before upload and verifies runtime identity and bindings
afterward. The sanitized receipt additionally records probe HTTP status and an allowlisted
error category, never provider bodies or credentials.

Candidate package: `fc616f9638ee264a5ff28dfc5f9a116ec02e0c61fdf6fba16ee0c0bbf5436635`.
The historical package assembler remains unchanged; only the Azure probe source changes
the serving package. No database migration, customer AI enablement, inference, Azure
management action, or permission change is included.

## Validation before production

- 21 focused Azure verification and diagnostic tests passed.
- 49 tests passed against the reconstructed production package, covering Azure, Team &
  Access, CVIE evidence and shared scans.
- Wrangler 4.156.0 dry run succeeded with the candidate identity.
- Local workerd 1.20261023.1 (Wrangler 4.156.0 / Miniflare) reproduced the original 404 for
  an empty POST. The corrected code returned 200 for both direct dispatch and actual
  localhost HTTP. Unsigned requests, whitespace and fictional prompt bodies returned 404.
  Azure responses and credentials in these local checks were fictional; no Azure calls occurred.

Require fresh PR/main checks, specific owner approval to merge this PR, and the protected
main-only production approval before release. Verify authentication and resource access
from the deployed Worker, with no inference. Preserve the prior version for an explicitly
authorized recovery if needed; do not automatically roll back or repeat deployment.
Coordinate the successor identity with the pending daily-history release before releasing
the shared production hold.
