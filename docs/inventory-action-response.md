# Responsive inventory actions

Repeated Remove customer/environment/asset clicks previously stacked independent
confirmation dialogs. A local browser reproduction created eight dialogs for
eight rapid clicks. Confirming one exposed the next, while successful deletions
gave no pending feedback until inventory refresh finished.

The inventory module now initializes once per page, permits one removal flow at
a time, and retains the confirmation while the request is pending. It displays
Removing…, disables repeat submission, keeps keyboard focus inside the pending
dialog, and offers an inline error/retry on failure. A successful removal followed
by a failed inventory refresh is reported separately, so it is not presented as a
failed deletion.

Browser regression uses fictional API responses at 1440, 768 and 390px. It covers
single-click expand/collapse/edit/cancel, duplicate initialization, repeated
activation, a delayed DELETE, failure/retry, keyboard behavior and completion.
The original module fails the repeated-click test (eight dialogs instead of one).
Existing CSV import and retained customer/environment tests run in the release
workflow, including against the downloaded production assets after publication.

The `inventory-actions` release changes only `inventory.js` on the verified PR348
production package. The published Windows collector from run 43264633230 is
retained with pinned file hashes and its original commit receipt. Required main
application/security CI, protected production approval, exact live baseline and
served-byte verification remain mandatory. Windows local historical package
reconstruction encounters an existing line-ending merge incompatibility; Linux
CI must pass package reconstruction before merge/publication.

No database migration, customer-data removal, backend deployment, credential
change or AI activation is included. AI remains paused. Recovery reference:
version `ce792e97-478f-452b-ad3f-ee1367226854`, deployment
`35237c71-bc0d-47d1-8634-12cd8673b44d`.
