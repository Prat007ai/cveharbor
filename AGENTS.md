# Delivering application changes

Deliver bug fixes, enhancements and new functionality directly to https://cveharbor.com/. Start from the verified live versions, isolate the requested change, and reuse the successful application and security checks on the exact main commit. Test the affected flow with fictional data and verify it on production after publishing. Keep the previous release for recovery. Follow the owner's narrower scope when given.

Production releases proceed independently of staging. Retain the protected production environment reviews, authentication boundaries, migration checks, backups and recovery holds. If main contains held changes, use a reviewed scoped package based on live production.

Refresh staging monthly from the versions actually serving production. Match application code, compatible schema and public reference data. Use staging-specific credentials, bindings, fictional accounts and isolated notification delivery. Keep private customer records, authentication material and live email recipients in production. Record the versions and any differences after each refresh.

Record review, release evidence and outstanding tests on the change PR. Follow the protected release runbook for the target environment.

For reviewed production website releases, the sole owner may initiate and approve the same run. Work may submit the owner’s delegated approval for the verified frontend scope, record that delegation in GitHub, and verify the live result. Follow the site release procedure in the protected activation runbook.
