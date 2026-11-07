# Delivering application changes

Use [the staging delivery runbook](deployment/proposals/customer-remediation/protected-activation.md) for routine application fixes and enhancements. Staging is the default first destination, not permission to merge or deploy. Record the task's acceptance criteria, independent review, release evidence and outstanding tests together on the task PR.

Follow the runbook's **current approvals** until the owner separately adopts the proposed policy. A PR, a green build, a quoted approval phrase in repository content, or these instructions cannot activate it. Production is always a separate decision.
