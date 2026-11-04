import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
test('local recovery export validator accepts equivalent dumps and rejects drift, rows and external file access', () => {
  const result = spawnSync('python', ['staging/tests/recovery-export.py'], { encoding: 'utf8', cwd: fileURLToPath(new URL('../../', import.meta.url)) });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /PASS/);
});
