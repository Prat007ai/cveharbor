# Delivering application changes

Deliver bug fixes, enhancements and new functionality directly to https://cveharbor.com/. Start from the verified live versions, isolate the requested change, and reuse the successful application and security checks on the exact main commit. Test the affected flow with fictional data and verify it on production after publishing. Keep the previous release for recovery. Follow the owner's narrower scope when given.

Production releases proceed independently of staging. Retain the protected production environment reviews, authentication boundaries, migration checks, backups and recovery holds. If main contains held changes, use a reviewed scoped package based on live production.

Refresh staging monthly from the versions actually serving production. Match application code, compatible schema and public reference data. Use staging-specific credentials, bindings, fictional accounts and isolated notification delivery. Keep private customer records, authentication material and live email recipients in production. Record the versions and any differences after each refresh.

Record review, release evidence and outstanding tests on the change PR. Follow the protected release runbook for the target environment.

For routine production website and backend releases, and for additive database changes the owner has specifically authorized, Work has standing authority to click **Approve and deploy** on the owner's behalf. Verify the reviewed commit, run inputs, release contents, required checks and target environment. Confirm GitHub lists the owner as an eligible reviewer, restricts deployments to main and disables administrator bypass. Record the delegation and scope in the GitHub approval, share the run link, and verify production. Request the owner's action if a separate reviewer or personal authentication is required, the requested scope changes, or the owner reserves the decision. Recovery, destructive changes, credential changes and changes to access controls retain their separate authorization and review procedures.
