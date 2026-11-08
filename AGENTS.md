# Delivering application changes

CVEHarbor work targets production at https://cveharbor.com/ only. Start from the verified live version, isolate the requested change, test the production package with fictional data, and verify the reported user flow on the live site. Keep the prior version available for recovery. Staging deployments, tests, refreshes and copies of production data require a new explicit owner request. If a protected release requires fresh staging evidence, report the gate and hold that step. Preserve required platform reviews and controls for authentication, live migrations and recovery.

Record review, release evidence and outstanding tests on the change PR. Follow the protected release runbook for the target environment.

For reviewed production website releases, the sole owner may initiate and approve the same run. Work may submit the owner’s delegated approval for the verified frontend scope, record that delegation in GitHub, and verify the live result. Follow the site release procedure in the protected activation runbook.
