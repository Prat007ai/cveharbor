// Credential-free artifact sealing and verification for the protected adapter.
import fs from 'node:fs';import path from 'node:path';import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';import {execFileSync} from 'node:child_process';import {fileURLToPath} from 'node:url';
import {verifyCandidateProfile,repository,profilePath} from './customer-remediation-profile.mjs';
export const output=path.join(repository,'staging/.build/customer-remediation-candidate');
export const hash=x=>createHash('sha256').update(x).digest('hex');
export function directoryHash(dir){const items=[];function walk(folder){for(const e of fs.readdirSync(folder,{withFileTypes:true})){assert.ok(!e.isSymbolicLink(),'No artifact symlinks');const f=path.join(folder,e.name);if(e.isDirectory())walk(f);else {assert.ok(e.isFile());items.push(path.relative(dir,f));}}}walk(dir);const h=createHash('sha256');for(const name of items.sort()){h.update(name+'\0');h.update(fs.readFileSync(path.join(dir,name)));h.update('\0');}return h.digest('hex');}
export function artifact(){
 assert.equal(execFileSync('git',['diff','--name-only','HEAD'],{cwd:repository,encoding:'utf8'}).trim(),'','Seal only a clean reviewed checkout');
 const {profile,rows}=verifyCandidateProfile();const manifest=JSON.parse(fs.readFileSync(path.join(output,'manifest.json')));
 const commit=execFileSync('git',['rev-parse','HEAD'],{cwd:repository,encoding:'utf8'}).trim();
 assert.equal(manifest.commit,commit);assert.equal(manifest.backend_source_sha,commit);assert.equal(manifest.frontend_source_sha,commit);
 assert.equal(manifest.application_profile,profile.name);assert.equal(manifest.source_mode,'reviewed-customer-candidate');assert.deepEqual(manifest.candidate_profile,profile);assert.equal(manifest.backend_identity,profile.backend_identity);assert.equal(manifest.schema_sha256,profile.schema_sha256);
 const api=hash(fs.readFileSync(path.join(output,'api.mjs')));assert.equal(api,manifest.api_sha256);
 const sql=fs.readFileSync(path.join(repository,profile.migration),'utf8');assert.equal(hash(sql),profile.migration_sha256);
 // Python's SQLite parser preserves trigger bodies; no semicolon splitting.
 const statements=JSON.parse(execFileSync('python',['-c',`import sqlite3,json,sys
sql=sys.stdin.read(); pending=''; statements=[]
for line in sql.splitlines(True):
 pending+=line
 if sqlite3.complete_statement(pending):
  statements.append(pending); pending=''
assert not pending.strip()
print(json.dumps(statements))`,],{input:sql,encoding:'utf8'}));
 assert.match(statements.shift(),/PRAGMA foreign_keys=ON;/);assert.ok(statements.every(s=>/^\s*CREATE (TABLE|UNIQUE INDEX|TRIGGER)\b/.test(s)));
 const seal={version:1,commit,profile_sha256:hash(fs.readFileSync(profilePath)),sql_sha256:profile.migration_sha256,schema_sha256:profile.schema_sha256,api_sha256:api,frontend_sha256:directoryHash(path.join(output,'public')),manifest_sha256:hash(fs.readFileSync(path.join(output,'manifest.json')))};
 return {seal,profile,rows,statements,seal_sha256:hash(JSON.stringify(seal))};
}
export function verifyArtifact(){const a=artifact();assert.deepEqual(JSON.parse(fs.readFileSync(path.join(output,'seal.json'))),a.seal);return a;}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){const a=artifact();fs.writeFileSync(path.join(output,'seal.json'),JSON.stringify(a.seal,null,2)+'\n');console.log(JSON.stringify({commit:a.seal.commit,artifact_sha256:a.seal_sha256,profile_sha256:a.seal.profile_sha256,sql_sha256:a.seal.sql_sha256}));}
