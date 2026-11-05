Staging QR rendering and pending MFA regeneration
===============================================

The staging build vendors the existing qrcodejs 1.0.0 bytes and MIT notice,
verifies the original SHA-512 integrity value, and rewrites the CDN reference to
`/assets/vendor/qrcodejs-1.0.0.min.js`. CSP and production assets are unchanged.

The exposed setup key remains valid until the pending enrollment is invalidated.
Do not complete enrollment with that key. No reset has been performed by this PR.

After code review and explicitly approved staging deployment:

1. Close other enrollment tabs and stop submitting codes from the old setup.
2. Use the existing human Cloudflare Access session at `cveharborstage.com`.
   The verified Access email must already be in `STAGING_ADMIN_EMAILS` and must
   be the same email as the pending application account. Service tokens and
   browser-supplied identity headers cannot authorize this operation.
3. In that origin's browser developer console, invoke the action once:

```js
(async () => {
  if (location.origin !== 'https://cveharborstage.com') throw new Error('Open staging first.');
  const response = await fetch('/__staging/mfa/pending/reset', {
    method: 'POST', credentials: 'same-origin', redirect: 'error',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({confirm: 'invalidate-pending-mfa'})
  });
  const result = await response.json();
  console.log({status: response.status,
    pending_enrollment_invalidated: result.pending_enrollment_invalidated === true,
    sign_in_required: result.sign_in_required === true});
})();
```

4. Proceed only after HTTP 200 and both flags are true. Reload `/workspace/`,
   request a fresh email code, verify it, and scan the newly generated QR with
   the authenticator. Enter its code to complete normal enrollment. Save the
   recovery codes privately and avoid capturing the new key/QR in screenshots.

The action has no target-email field. It can invalidate only the requesting
Access administrator's **pending** (`enabled=0`) factor. An active factor returns
409 and remains intact; this is not an MFA-disable or account-recovery endpoint.
403 means the existing authorization/origin requirements were not met; do not
change Access policies or add credentials to work around it. On 409, stop and
review the account state rather than repeatedly resetting. On 503, no partial
write should have committed; investigate before retrying.

Every write is conditional on the same pending encrypted record and executes
in one D1 batch. It invalidates outstanding email codes, pending MFA challenges
and sessions for that account, then removes only the pending factor. Other
accounts, enabled factors and recovery-code records are not changed. The
normal email-proof flow generates the replacement secret; the reset response
never includes a secret, OTP URI, challenge token or recovery code. No schema
changes, encryption-key rotation or new infrastructure are required.
