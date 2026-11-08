// Local-only candidate profile. No Cloudflare client or migration execution.
import fs from 'node:fs';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {execFileSync} from 'node:child_process';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {fileURLToPath} from 'node:url';
import {backendIdentity} from '../../scripts/build_release_identity.mjs';
import {canonical,digest,schemaSQL} from '../../scripts/production_schema_baseline.mjs';
export const repository=fileURLToPath(new URL('../../',import.meta.url));
export const profilePath=path.join(repository,'deployment/proposals/customer-remediation/candidate-profile.json');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
export function candidateBackend(){
 return process.env.CANDIDATE_SCOPE==='assignment-291'?path.join(repository,'release/.build/investigation-backend'):repository;
}
export function candidateProfile(){
 const base=JSON.parse(fs.readFileSync(path.join(repository,'release/baseline.json'))),proposal='deployment/proposals/customer-remediation/schema.sql';
 const files=execFileSync('git',['ls-files','-z'],{cwd:repository,encoding:'utf8'}).split('\0').filter(f=>f&&(
  f==='scripts/build_site.py'||f==='staging/scripts/build-assets.py'||f.startsWith('staging/vendor/')||['data/demo-advisories.json','data/lifecycle-products.json'].includes(f)||
  (!/^(?:\.|account-backend\/|staging\/|deployment\/|release\/|scripts\/|tests\/|docs\/|data\/|public\/|work\/|node_modules\/)/.test(f)))).sort();
 const adapterFiles=['staging/api-entry.mjs','staging/api-wrapper.mjs','staging/production-runtime.mjs','staging/transport.mjs','staging/blocked-fetch.mjs','staging/frontend.mjs','staging/target.mjs','staging/scripts/build.mjs','staging/scripts/customer-remediation-profile.mjs'];
 const adapter=createHash('sha256');for(const f of adapterFiles){adapter.update(f+'\0');adapter.update(fs.readFileSync(path.join(repository,f)));adapter.update('\0');}
 const frontend=createHash('sha256');for(const f of files){frontend.update(f+'\0');frontend.update(fs.readFileSync(path.join(repository,f)));frontend.update('\0');}
 const db=new DatabaseSync(':memory:');try{
  db.exec(fs.readFileSync(path.join(repository,'staging/schema.sql'),'utf8'));
  for(const f of base.application_schema_files){const bytes=fs.readFileSync(path.join(repository,f.path));assert.equal(hash(bytes),f.sha256,'Baseline schema file changed');db.exec(bytes.toString());}
  const before=db.prepare(schemaSQL).all();assert.equal(digest(canonical(before.filter(r=>!r.name.startsWith('staging_')))),base.schema_sha256);
  db.exec(fs.readFileSync(path.join(repository,proposal),'utf8'));
  const rows=db.prepare(schemaSQL).all();
  return {profile:{version:1,name:'customer-remediation-candidate',origin:'https://cveharborstage.com',activation:'separate-approval-required',baseline_schema_sha256:base.schema_sha256,migration:proposal,migration_sha256:hash(fs.readFileSync(path.join(repository,proposal))),backend_identity:backendIdentity(candidateBackend()),frontend_inputs_sha256:frontend.digest('hex'),staging_adapter_sha256:adapter.digest('hex'),schema_sha256:digest(canonical(rows)),schema_objects:rows.length},rows};
 }finally{db.close();}
}
export function verifyCandidateProfile(){const actual=candidateProfile();const expected=JSON.parse(fs.readFileSync(profilePath));
 if(process.env.CANDIDATE_SCOPE==='assignment-291'){
  expected.backend_identity=JSON.parse(fs.readFileSync(path.join(repository,'release/assignment-291.json'))).backend_identity;
 }
 assert.deepEqual(actual.profile,expected,'Candidate inputs changed; review and regenerate the inactive profile');return actual;}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.includes('--write')){fs.writeFileSync(profilePath,JSON.stringify(candidateProfile().profile,null,2)+'\n');console.log('Inactive candidate profile written locally.');}
 else {verifyCandidateProfile();console.log('Candidate source/schema pins verified locally.');}
}
