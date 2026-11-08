import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {directoryHash, hash, output} from './customer-candidate-artifact.mjs';
import {repository} from './customer-remediation-profile.mjs';
import {TARGET} from '../target.mjs';

// The sealed assets from runs 42146739057 (live baseline) and 42409289536
// (catalogue candidate) were compared before preparing this one release.
export const catalogueRelease = Object.freeze({
  baseline: 'df4f12e7a04346411535ab204dd3c87df5a577ca',
  catalogue: '9d58ba4cd635cc4250efae6d58f8fb1eb885eb83',
  backendVersion: '8de40d1b-b7ae-41ff-b547-43afef4da020',
  frontendVersion: '795663c2-f609-4eb2-871a-d1dc0053f814',
  assets: '543ee9a4aaef637148635911e4dda7117718e90f863775c661c6dc65937d081b',
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
  assert.equal(directoryHash(assets), 'c798d6942e8fc88ee6609f1326123b1bed30631bf953d9b0cd5bd9c128a646f5',
    'The candidate no longer matches the reviewed package');
  for (const filename of ['customer-remediation-ui.js', 'operations.js']) {
    const original = execFileSync('git', ['show', catalogueRelease.baseline + ':' + filename],
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
