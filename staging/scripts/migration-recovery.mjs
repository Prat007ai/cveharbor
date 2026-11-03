// Required private administrator recovery evidence for the separately approved
// migration phase. The original-state adoption has its own independent gate.
import { TARGET } from '../target.mjs';
import { hash, STAGING_DATABASE_ID } from './migrate.mjs';
import { failure } from './errors.mjs';
export function migrationRecoveryEvidence(env, plan, now = Date.now()) {
  let proof;
  try { proof = JSON.parse(env.CF_STAGING_RECOVERY_EVIDENCE || ''); }
  catch { throw failure('migration.recovery', 'missing'); }
  if (!proof || typeof proof !== 'object') throw failure('migration.recovery', 'invalid_or_stale');
  const step = Number(env.CF_STAGING_SCHEMA_RESUME_STEP), checkpoint = plan.checkpoints[step];
  const age = now - Date.parse(proof.captured_at);
  if (!checkpoint || proof.operation !== 'migrate' || proof.account !== TARGET.account || proof.database_id !== STAGING_DATABASE_ID ||
      proof.source_sha !== env.GITHUB_SHA || proof.execution_plan_sha256 !== env.CF_STAGING_SCHEMA_PLAN_SHA256 ||
      proof.start_step !== step || proof.start_schema_sha256 !== checkpoint.schema_sha256 ||
      proof.writers_quiesced !== true || proof.export_validated !== true || proof.restore_available !== true ||
      !Number.isFinite(age) || age < 0 || age > 3600000 || !/^[a-f0-9]{64}$/.test(proof.export_sha256 || '') ||
      typeof proof.bookmark !== 'string' || proof.bookmark.length < 6 || proof.bookmark.length > 512 ||
      typeof proof.private_export_reference !== 'string' || !proof.private_export_reference.trim() || proof.private_export_reference.length > 1000)
    throw failure('migration.recovery', 'invalid_or_stale');
  return { evidence_sha256: hash(env.CF_STAGING_RECOVERY_EVIDENCE), export_sha256: proof.export_sha256,
    captured_at: proof.captured_at, bookmark_sha256: hash(proof.bookmark), administrator_attested: true, start_step: step };
}
