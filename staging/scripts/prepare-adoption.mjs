// Local review artifacts only. No credentials or network operations.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { root } from './configure.mjs';
import { loadAdoption, ADOPTION_SHA256 } from './adopt-schema.mjs';
import { guardSQL, hash } from './migrate.mjs';
export function prepareAdoption() {
  const pinned = JSON.parse(fs.readFileSync(path.join(root, 'adoption.v1.json')));
  const { adoption, plan, reference, statements } = loadAdoption({
    CF_STAGING_ADOPTION_SHA256: ADOPTION_SHA256, CF_STAGING_SCHEMA_PLAN_SHA256: pinned.execution_plan_sha256 });
  const guards = guardSQL(reference, 29, []), sql = [...guards.map(x => x.sql), ...statements].join('\n');
  const counts = step => plan.schemas[plan.checkpoints[step].schema_sha256].objects.reduce((a, o) => ({ ...a, [o[0]]: (a[o[0]] || 0) + 1 }), {});
  const result = { local_only: true, adoption_sha256: ADOPTION_SHA256, ...adoption,
    guarded_batch_sha256: hash(sql), guard_statements: guards.length, adoption_statements: statements.length,
    after_bridge: { checkpoint: 37, schema_sha256: plan.checkpoints[37].schema_sha256, objects: counts(37) },
    final: { checkpoint: plan.checkpoints.length - 1, schema_sha256: plan.checkpoints.at(-1).schema_sha256, objects: counts(plan.checkpoints.length - 1) },
    continuation: plan.files.slice(2).map(f => ({ file: f.file, sha256: f.sha256, from: f.start, to: f.end, statements: f.statements.length })) };
  const out = path.join(root, '.build/schema'); fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'adoption-batch.sql'), sql);
  fs.writeFileSync(path.join(out, 'adoption-review.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ local_only: true, adoption_sha256: ADOPTION_SHA256, guarded_batch_sha256: result.guarded_batch_sha256, target_checkpoint: 37, final: result.final.objects }));
  return result;
}
if (process.argv[1] === fileURLToPath(import.meta.url)) prepareAdoption();
