import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {directoryHash, hash, output} from './customer-candidate-artifact.mjs';
import {repository} from './customer-remediation-profile.mjs';
import {TARGET} from '../target.mjs';

// The sealed catalogue from staging run 42411365289 differs only in public/app.js.
export const catalogueRelease = Object.freeze({
  baseline: '366a44bcf5dc2c877f59a3a800e08acead7d0871',
  catalogue: '49a7e29fc06cfe82f933004bd9432516e6ab722c',
  backendVersion: 'de1ccda0-37c0-4e1e-9ccd-1cc5664417c7',
  frontendVersion: 'ab005295-1875-4cc9-ae05-8e5c3b5ef958',
  assets: '5ef0df62ebbf24852c7ed6302ca2b69d5e26e885470fc8b2595ccdae1b58aa59',
});

export function prepareCatalogueRelease(directory = output) {
  const assets = path.join(directory, 'public');
  const manifestPath = path.join(directory, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  assert.equal(manifest.origin, TARGET.origin);
  assert.equal(manifest.application_profile, 'customer-remediation-candidate');
  assert.equal(manifest.schema_sha256, '9db275d5b7baddbd372146eae2b6fd50e782776285c6bae98fbbedb599c0cf5a');
  assert.equal(hash(fs.readFileSync(path.join(directory, 'api.mjs'))), 'f8109baac6901c5458a015dc6dab7654060e7bb8c8b9a8ef569f92b3044eb799');
  assert.equal(hash(fs.readFileSync(path.join(directory, 'site.mjs'))), '2b7bf33e958af52e32058f63045a2c654c7f49b511c604eed5d58fd98d46baf9');
  assert.equal(directoryHash(assets), 'f95c037e562d41c189750234b4f87a8aac34c79755675bcdf160f8e9157c5278',
    'The candidate no longer matches the reviewed package');
  for (const filename of ['customer-remediation-ui.js', 'operations.js']) {
    const original = execFileSync('git', ['show', 'df4f12e7a04346411535ab204dd3c87df5a577ca:' + filename],
      {cwd: repository, encoding: 'utf8'});
    const staged = original.replace(/https:\/\/(?:api\.|confirm\.|www\.)?cveharbor\.com/g, TARGET.origin);
    fs.writeFileSync(path.join(assets, filename), staged);
  }
  assert.equal(directoryHash(assets), catalogueRelease.assets, 'Isolated catalogue asset set changed');
  manifest.catalogue_release = catalogueRelease;
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  prepareCatalogueRelease();
}
