// Only this reviewed GitHub job entrypoint arms the staging mutation helper.
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { TARGET, databaseId } from '../target.mjs';
import { root } from './configure.mjs';
import { preflight } from './preflight.mjs';
import { runCloud } from './cloud.mjs';
import { probeAccess } from './probe-access.mjs';
import { failure, safeFailure } from './errors.mjs';
import { migrate, loadMigrationPlan, STAGING_DATABASE_ID } from './migrate.mjs';

export function authorize(env, event, checkout) {
  if (env.GITHUB_REPOSITORY !== 'Prat007ai/cveharbor' || env.GITHUB_REF !== 'refs/heads/codex/cvie-core-phase012') throw Error('Repository/branch not approved');
  const sha = env.CF_STAGING_APPROVED_COMMIT;
  if (!/^[a-f0-9]{40}$/.test(sha || '') || env.GITHUB_SHA !== sha || checkout !== sha) throw Error('Reviewed commit must match run and checkout exactly');
  const action = env.CF_STAGING_PROVISION_ACTION;
  if (!['create-database', 'deploy-workers', 'deploy-frontend', 'migrate-schema'].includes(action)) throw Error('Explicit staging operation required');
  const requested = env.GITHUB_EVENT_NAME === 'workflow_dispatch'
    ? event.inputs?.provision_action === action && ![true, 'true'].includes(event.inputs?.check_credentials)
    : env.GITHUB_EVENT_NAME === 'push' && Number(env.GITHUB_RUN_ATTEMPT) > 1 && event.head_commit?.id === sha && event.head_commit?.message?.includes('[staging-provision]');
  if (!requested) throw Error('Explicit dispatch or manually rerun marked preparation run required; initial pushes cannot provision');
  if (env.CF_STAGING_ACCOUNT_ID !== TARGET.account) throw Error('Dedicated staging account required');
  if (action === 'create-database' && env.CF_STAGING_D1_DATABASE_ID) throw Error('Creation requires an unset staging D1 UUID');
  if (action !== 'create-database') databaseId(env.CF_STAGING_D1_DATABASE_ID);
  if (action === 'migrate-schema' && (env.CF_STAGING_D1_DATABASE_ID !== STAGING_DATABASE_ID || !/^[a-f0-9]{64}$/.test(env.CF_STAGING_SCHEMA_PLAN_SHA256 || '') || !/^(0|[1-9]\d*)$/.test(env.CF_STAGING_SCHEMA_RESUME_STEP || ''))) throw Error('Exact staging UUID, reviewed schema digest and explicit resume step required');
  return { action, source_sha: sha, account: TARGET.account };
}

export function acceptPreflight(report, attestation) {
  if (report.account !== TARGET.account || report.blockers.length || !report.read_only_checks_passed) throw Error('Fresh read-only preflight failed');
  if (report.checks.find(c => c.name === 'service_token_matches_policy_and_client')?.status !== 'pass') throw Error('Service-token linkage must pass');
  const manual = attestation.evidence_type === 'manual_account_owner_verification' && attestation.account_id === TARGET.account && attestation.scope_confirmed === 'Restricted exclusively to the CVEHarbor Staging account'
    && ['Workers Scripts Write', 'D1 Write', 'Account Settings Read', 'Access Apps and Policies Read', 'Access Service Tokens Read'].every(p => attestation.permissions_confirmed?.includes(p));
  const grants = report.checks.find(c => c.name === 'token_permission_grants');
  const scope = report.checks.find(c => c.name === 'token_staging_only_scope');
  if (!(grants?.status === 'pass' && scope?.status === 'pass') && !(manual && grants?.metadata_available === false && grants?.http_status === 403 && scope?.metadata_available === false)) throw Error('Token grants/scope lack accepted evidence or conflict with owner attestation');
}

export async function provision(env, event, checkout, { check = preflight, cloud = runCloud, probe = probeAccess, migration = migrate, migrationPlan = loadMigrationPlan, record = () => {} } = {}) {
  let operation = 'authorization';
  try {
  const approved = authorize(env, event, checkout);
  const plan = approved.action === 'migrate-schema' ? migrationPlan(env) : undefined;
  operation = 'preflight';
  const report = await check(env, undefined, { existingDatabase: approved.action !== 'create-database', workerState: ['deploy-frontend', 'migrate-schema'].includes(approved.action) ? 'deployed' : 'empty' });
  record('preflight', report);
  operation = 'preflight.accept';
  const attestation = JSON.parse(fs.readFileSync(path.resolve(root, '../docs/cvie-evidence/staging-owner-attestation.json'), 'utf8'));
  acceptPreflight(report, attestation);
  if (approved.action === 'migrate-schema') {
    operation = 'migration';
    return await migration({ ...env, STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY' }, { plan, record });
  }
  operation = 'cloud';
  const result = await cloud(approved.action === 'deploy-workers' ? 'deploy' : approved.action, { ...env, STAGING_CHANGE_APPROVED: 'PR243-STAGING-ONLY' }, undefined, () => {});
  record('provision', { ...approved, ...result, completed_at: new Date().toISOString() });
  if (approved.action !== 'create-database') {
    operation = 'access.probe';
    const access = await probe(env); record('access', access);
    if (!access.passed) throw Error('Post-deployment Access check failed; preserve fail-closed settings');
  }
  return result;
  } catch (error) {
    const wrapped = failure(operation, 'validation', {}, error);
    record('failure', { status: 'stopped', ...safeFailure(wrapped), resources_may_exist: true, next: 'Inspect staging inventory; no automatic retry or deletion.' });
    throw wrapped;
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const destination = path.join(root, 'artifacts');
  const record = (name, result) => { fs.mkdirSync(destination, { recursive: true }); fs.writeFileSync(path.join(destination, name + '.json'), JSON.stringify(result, null, 2) + '\n'); };
  try {
    const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
    const checkout = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).stdout.trim();
    if (process.argv[2] === '--check') { const approved = authorize(process.env, event, checkout); if (approved.action === 'migrate-schema') loadMigrationPlan(process.env); console.log('Exact source and operation gates passed; no cloud requests.'); }
    else { await provision(process.env, event, checkout, { record }); console.log('Approved staging operation completed; see sanitized artifact.'); }
  } catch (error) {
    // Third-party errors can contain request data; never serialize them.
    record('failure', { status: 'stopped', stage: 'provisioning', ...safeFailure(error), resources_may_exist: true, next: 'Inspect sanitized evidence and staging inventory before retrying; no automatic retry or deletion.' });
    console.error('Staging provisioning stopped: ' + JSON.stringify(safeFailure(error)) + '; no automatic recovery attempted.'); process.exitCode = 1;
  }
}

