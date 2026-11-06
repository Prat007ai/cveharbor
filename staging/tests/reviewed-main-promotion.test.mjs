import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash} from 'node:crypto';

const project = new URL('../../', import.meta.url);
const read = file => fs.readFileSync(new URL(file, project), 'utf8');

test('staging selects reviewed main without changing its production schema profile or origin', () => {
  const profile = JSON.parse(read('staging/application-release.json'));
  assert.deepEqual(profile, {
    source_mode: 'reviewed-main',
    schema_profile: 'production-baseline-209',
    origin: 'https://cveharborstage.com'
  });
  const build = read('staging/scripts/build.mjs');
  assert.match(build, /const pinned=production&&releaseProfile.source_mode==='production-baseline'/);
  assert.match(build, /const source=pinned\?path\.join\(repository,'release\/\.build\/production-source'\):repository/);
  assert.match(build, /const frontend=pinned\?path\.join\(repository,'release\/\.build\/production-frontend'\):repository/);
});

test('current reviewed main preserves every checked production baseline schema file', () => {
  const baseline = JSON.parse(read('release/baseline.json'));
  assert.equal(baseline.version, 2);
  assert.equal(baseline.application_schema_files.length, 29);
  for (const entry of baseline.application_schema_files) {
    const digest = createHash('sha256').update(read(entry.path)).digest('hex');
    assert.equal(digest, entry.sha256, entry.path + ' requires a separately approved schema profile');
  }
  assert.equal(baseline.schema_sha256.length, 64);
});

test('main staging release and production promotion have separate approval and receipt gates', () => {
  const staging = read('.github/workflows/cvie-staging.yml');
  const backend = read('.github/workflows/deploy-worker-code.yml');
  const frontend = read('.github/workflows/bootstrap.yml');
  const receipt = read('scripts/require_staging_release.mjs');
  assert.match(staging, /vars\.SIMPLE_STAGING_ENABLED == 'true'/);
  assert.match(staging, /environment: cloudflare-cvie-staging/);
  assert.match(backend, /environment: cloudflare-worker-production/);
  assert.match(frontend, /name: cloudflare-site-production/);
  for (const workflow of [backend, frontend]) {
    assert.match(workflow, /needs: staging-ready/);
    assert.match(workflow, /node scripts\/require_staging_release\.mjs/);
  }
  assert.match(receipt, /assert\.equal\(run\.head_sha,sha\)/);
  assert.match(receipt, /assert\.equal\(receipt\.status,'passed'\)/);
  assert.match(receipt, /assert\.equal\(receipt\.source_sha,sha\)/);
});
