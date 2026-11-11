# Azure backend credential retry

PR #334 run 43027286806 stopped at cloudflare_database_identity with HTTP 401 before any Worker upload. The owner authorized a replacement two-hour token with the same D1 Read and Workers Scripts Edit permissions scoped to CVEHarbor.com, installation in CVEHARBOR_PROD_WORKER_TOKEN, and a fresh deployment with delegated production approval.

Website PR #336 advanced main to 6a1d9b5a31e71b5712c8dcd5e65b57ed424aadb1. This release-only follow-up binds the existing exact-merged-PR check to release/azure-worker-retry. All environment, exact-main, approval, first-attempt and package checks remain in place.

The runtime package remains f903b738021362b5a008a8b9704481699af4b9cc41c49d2f8ae75503d8d87abc. Expected prior serving package is d075a90fa2afd00deb5d500e0beb7129daf343d2deed0127bc94fa4f4f4b9f6e. No application, schema, Azure settings, customer AI activation or model inference changes are included. Verification authenticates from Cloudflare and reads Azure model metadata only. Production success must be established from the sanitized workflow artifact and live readiness.
