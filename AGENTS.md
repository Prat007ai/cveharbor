# Delivering application changes

Work owns implementation and release. An implementation request authorizes review, merge, staging verification and production promotion of the requested change under the owner's project instructions. Honor any narrower scope. Verify release contents and the target environment before every promotion.

Use the [staging delivery runbook](deployment/proposals/customer-remediation/protected-activation.md). Record the task criteria, review, release evidence and outstanding tests on its PR. The proposed routine staging operation requires separate adoption. Use the existing protected workflows until then. Preserve required platform reviews, independent identities and safeguards for migrations and recovery.

## Catalogue-only production releases

When the sole owner asks Work to deploy an identified catalogue-only update, that request authorizes Work to submit the owner's GitHub deployment approval for that release. Work verifies the reviewed main commit, the signed-in staging save/reload result, the production baseline and the pending environment before approving. Use the owner's authorized GitHub identity and record the delegation, run ID and commit in the approval comment.

For each release, pin its own candidate, staging evidence and production baseline in the reviewed release configuration. Use the protected catalogue publisher with owner review, main-only deployment and administrator bypass disabled. Send the live run link, monitor publication, verify the live assets and traffic, and record the result on the PR. A prior run's approval applies only to that run. Follow any later instruction that reserves the approval click for the owner.
