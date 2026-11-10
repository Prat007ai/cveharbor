# Organization Team & Access

This proposal covers the accounts Worker, the Account & Security and My Workspace pages, and the additive D1 schema in this directory. The Worker serves team APIs only when its server-side TEAM_ACCESS_ENABLED variable is exactly true. The existing customer ownership and MFA routes continue to use the signed-in person's identity.

## Inventory ownership

An organization can start with a separate inventory. Its storage identity uses a reserved, non-sign-in address. An active Owner can promote another member to Owner and then be restricted or removed. The last active Owner is protected inside the database transaction. Pending invites do not count toward that check.

An Owner can instead explicitly share their existing personal inventory. The original account retains access through the existing application and therefore stays an Owner. No original record is copied or re-keyed. Other Owners can manage the team's membership. Unassigned personal remediations and monitoring preferences remain personal. Pending invitations expire after seven days. Reissuing replaces the token. An email scanner opening a link cannot accept it. Only an authenticated session for the invited address can accept the reviewed membership revision.

## Production review

1. Verify the current running site and Worker identities, exact release package, and main checks. The site needs the team UI modules, CSS and artwork listed by the site builder. The Worker needs the new modules and the existing mail configuration. Use the protected publication runbook. Keep unrelated changes out of a scoped release.
2. Obtain separate owner approval for the production D1 change, the Worker access-control change, the site publication and enabling TEAM_ACCESS_ENABLED. Identify the target database, exact SQL digest, resource versions, change window, protected workflow and backup/recovery evidence. This SQL is outside automatic migrations.
3. Verify existing inventory, session creation timestamps, customer remediation scopes, asset finding links, workflow integrity and recovery controls. Inspect the actual schema and active hold, and confirm the backup and prior release are retrievable. Apply the reviewed SQL through the approved migration path once. Record the receipt and check table, view and trigger definitions, recovery guard coverage, preserved record counts and foreign-key integrity. New tables need the normal recovery guard set.
4. Verify the existing SMTP2GO sending identity, click-tracking and BCC/archive policy for invitation links, and disposition of test recipients. Confirm the reviewed frontend and Worker with the feature disabled first. After activation, verify the two email/MFA journeys, customer scope, immediate revocation, last sign-in, report and optimistic-write conflict in an authorized fictional tenant.
5. If verification fails, disable the team feature through the authorized configuration process. Leave the additive storage intact. Existing team members and pending invitations must be reconciled before reactivation. Restoring a D1 backup, deleting an organization or sending invitation emails to real users requires its own scope.

## Local verification

Run the account backend test suite with Node 22.13 or later. The team route tests use real SQL transactions against fictional users with a captured mail transport. Build the site with the existing Python site builder before browser checks.

For the invitation browser regression, install the project's existing staging Playwright dependency, build the public site, and run `node scripts/team_access_browser.mjs`. Set `TEAM_TEST_CHROME` to a local Chrome or Chromium executable if using an existing browser installation. The test intercepts browser requests and captures every verification and invitation email in memory. It covers the Owner preview, new-user authenticator enrollment and recovery codes, existing-user sign-in, and the assigned Viewer dashboard.
