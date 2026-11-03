// Read-only state inspection shared by migration verification and diagnostics.
import { createHash } from 'node:crypto';
import { failure, safeFailure } from './errors.mjs';
export const hashState = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
export const quoteIdentifier = name => '"' + name.replaceAll('"', '""') + '"';
export const countSQL = name => 'SELECT count(*) AS n FROM ' + quoteIdentifier(name);
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
export const STATE_LIMITS = Object.freeze({ objects: 2000, tables: 150, seed_rows: 1000 });

export async function inspectSchemaState(plan, query, record = () => {}, label = 'diagnostic', { countBatch } = {}) {
  // Publish a NEW incomplete observation before the first request. Never reuse a
  // previous checkpoint when a schema/count/seed request fails halfway through.
  const actual = { inspection: label, observed_at: new Date().toISOString(), status: 'in_progress', complete: false,
    schema_sha256: null, objects: [], counts: [], counts_complete: false, rows_verified: false, matching_steps: [] };
  const publish = () => record(structuredClone(actual));
  publish();
  try {
    const schema = await query(plan.schema_sql, 'schema');
    if (!Array.isArray(schema) || schema.length > STATE_LIMITS.objects || schema.some(r => !r ||
      !['table', 'index', 'trigger', 'view'].includes(r.type) || typeof r.name !== 'string' || typeof r.tbl_name !== 'string' ||
      !(r.sql === null || typeof r.sql === 'string'))) throw failure('schema.state.schema', 'result_shape');
    const objects = schema.map(r => [r.type, r.name, r.tbl_name, r.sql]);
    actual.schema_sha256 = hashState(objects);
    actual.objects = objects.map(([type, name, table, sql]) => ({ type, name, table, definition_sha256: hashState(sql) }));
    publish();
    const tables = objects.filter(o => o[0] === 'table').map(o => o[1]).sort();
    if (tables.length > STATE_LIMITS.tables || new Set(tables).size !== tables.length) throw failure('schema.state.tables', 'inspection_limit');
    // Each SQL remains a one-table SELECT. The migration runner may transport
    // at most five independent reads in one D1 batch; diagnostics keep singles.
    async function counts(prefix, visit) {
      const width = countBatch ? 5 : 1;
      for (let i = 0; i < tables.length; i += width) {
        const names = tables.slice(i, i + width);
        const values = countBatch ? await countBatch(names, prefix + i) :
          (await query(countSQL(names[0]), prefix + i)).map(r => r?.n);
        if (!Array.isArray(values) || values.length !== names.length || values.some(n => !Number.isSafeInteger(n) || n < 0))
          throw failure('schema.state.' + prefix + i, 'result_shape');
        names.forEach((name, offset) => visit(name, values[offset], i + offset));
      }
    }
    await counts('counts.', (name, value) => { actual.counts.push([name, value]); publish(); });
    actual.counts_complete = true; publish();
    const candidates = plan.checkpoints.map((c, step) => ({ c, step })).filter(({ c }) =>
      c.schema_sha256 === actual.schema_sha256 && same(c.counts, actual.counts));
    const rows = [];
    if (candidates.length) {
      const nonempty = new Set(actual.counts.filter(([, n]) => n > 0).map(([name]) => name));
      if (actual.counts.reduce((sum, [, n]) => sum + n, 0) > STATE_LIMITS.seed_rows) throw failure('schema.state.seeds', 'inspection_limit');
      for (const [i, table] of plan.schemas[actual.schema_sha256].tables.entries()) {
        if (!nonempty.has(table.name)) continue;
        const values = await query(table.row_sql + ' LIMIT ' + (STATE_LIMITS.seed_rows + 1), 'seeds.' + i);
        if (!Array.isArray(values) || values.length > STATE_LIMITS.seed_rows || values.some(r => typeof r?.value !== 'string'))
          throw failure('schema.state.seeds.' + i, 'result_shape');
        rows.push(...values.map(r => [table.name, r.value]));
      }
      actual.rows_sha256 = hashState(rows); actual.rows_verified = true;
    }
    // Bound consistency checks: schema and counts must be unchanged across the
    // read sequence. No transaction state, lock or metadata row is written.
    const after = await query(plan.schema_sql, 'schema_after');
    if (!Array.isArray(after) || hashState(after.map(r => [r.type, r.name, r.tbl_name, r.sql])) !== actual.schema_sha256)
      throw failure('schema.state.consistency', 'state_changed');
    await counts('counts_after.', (_name, value, i) => {
      if (value !== actual.counts[i][1]) throw failure('schema.state.consistency', 'state_changed');
    });
    actual.matching_steps = candidates.filter(({ c }) => c.rows_sha256 === actual.rows_sha256).map(({ step }) => step);
    actual.status = 'complete'; actual.complete = true; actual.completed_at = new Date().toISOString(); publish();
    return { actual, rows };
  } catch (error) {
    actual.status = 'failed'; actual.complete = false; actual.matching_steps = []; actual.rows_verified = false;
    actual.failure = safeFailure(error); actual.completed_at = new Date().toISOString(); publish(); throw error;
  }
}
