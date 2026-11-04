import fs from 'node:fs';
import assert from 'node:assert/strict';
import {TARGET,databaseId} from '../target.mjs';
export function resourceManifest(){return validateResources(JSON.parse(fs.readFileSync(new URL('../resources.v1.json',import.meta.url),'utf8')));}
export function validateResources(m){
 assert.equal(m.version,1);assert.equal(m.account_id,TARGET.account);
 assert.equal(m.permanent_database.name,TARGET.database);assert.equal(m.permanent_database.uuid,'fac61562-fc31-426d-8032-550aba63b7f6');
 assert.equal(m.intelligence_bucket,'cveharbor-intelligence-staging');assert.ok(Array.isArray(m.disposable_databases));
 const names=new Set([m.permanent_database.name]),ids=new Set([m.permanent_database.uuid]);
 for(const d of m.disposable_databases){assert.deepEqual(Object.keys(d).sort(),['name','uuid']);assert.match(d.name,/^cveharbor-phase1-staging-[a-z0-9-]+$/);databaseId(d.uuid);assert.ok(!names.has(d.name)&&!ids.has(d.uuid));names.add(d.name);ids.add(d.uuid);}
 return m;
}
export function checkDatabases(rows,{existing=true,permanentId,manifest=resourceManifest()}={}){
 validateResources(manifest);assert.ok(Array.isArray(rows)&&rows.length<100,'Unbounded database inventory');
 if(existing)assert.equal(permanentId,manifest.permanent_database.uuid,'Unapproved permanent UUID');
 const expected=[...(existing?[manifest.permanent_database]:[]),...manifest.disposable_databases];
 assert.equal(rows.length,expected.length,'Unknown or missing database');
 for(const d of expected)assert.equal(rows.filter(r=>r.name===d.name&&r.uuid===d.uuid).length,1,'Exact approved database identity required');
 return true;
}
