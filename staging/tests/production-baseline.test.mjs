import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import {DatabaseSync} from 'node:sqlite';
import {canonicalDDL} from '../../scripts/sql_schema_tokens.mjs';
import {expectedBaseline,canonical,digest,schemaSQL,auditBaseline} from '../../scripts/production_schema_baseline.mjs';
import {productionBaselinePlan,verifyProductionBaseline} from '../scripts/production-baseline.mjs';
import {simpleRelease} from '../scripts/simple-release.mjs';import {FullDB} from './helpers/full-db.mjs';import {TARGET} from '../target.mjs';
const baseline=JSON.parse(fs.readFileSync(new URL('../../release/baseline.json',import.meta.url)));
const {plan,endStep}=productionBaselinePlan(baseline);
function installed(step=37){const DB=new FullDB({empty:true});for(const f of plan.files)for(const s of f.statements.slice(0,Math.max(0,Math.min(step,f.end)-f.start)))DB.sql.exec(s);return DB;}
test('SQL comparison ignores whitespace only between tokens, preserving real SQL changes',()=>{
 assert.equal(canonicalDDL("CREATE TABLE t ( id TEXT, value TEXT DEFAULT 'a  b' );"),canonicalDDL("CREATE TABLE t(id TEXT,value TEXT DEFAULT 'a  b')"));
 for(const [a,b] of [["DEFAULT 'a  b'","DEFAULT 'a b'"],['"a b"','"ab"'],["DEFAULT X'AB'","DEFAULT X 'AB'"],['NOT NULL','NOTNULL'],['a < = b','a <= b'],['SELECT 1 --x\n+2','SELECT 1 --x +2'],['UNIQUE(a,b)','UNIQUE(b,a)'],['ON DELETE CASCADE','ON DELETE RESTRICT'],['CHECK(x>0)','CHECK(x>=0)']])assert.notEqual(canonicalDDL(a),canonicalDDL(b));
 assert.throws(()=>canonicalDDL("DEFAULT 'unterminated"));
});
test('reviewed production source/profile yields exactly 143 application objects and excludes uninstalled migrations',()=>{
 const expected=expectedBaseline(new URL('../..',import.meta.url).pathname);assert.equal(expected.schema_sha256,baseline.schema_sha256);
 assert.equal(expected.objects.length,143);assert.equal(expected.backend_identity,baseline.backend.identity);
 assert.equal(plan.checkpoints[37].counts.length,22);assert.equal(endStep,209);assert.equal(plan.checkpoints.at(-1).counts.length,74);
 assert.equal(plan.files.length,30);assert.ok(!plan.files.some(f=>/0023_|0031_|0032_|recovery-guards/.test(f.file)));
});
test('production-only initialization preserves adopted objects and receipts, verifies final state and never deploys',async()=>{
 const DB=installed();let called=0;const original=DB.sql.prepare('SELECT * FROM staging_schema_history ORDER BY rowid').all();
 const env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:'a'.repeat(40),SIMPLE_STAGING_ENABLED:'true',SIMPLE_STAGING_OPERATION:'initialize',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6'};
 try{
 const r=await simpleRelease(env,{baseline,DB,get:async()=>({bookmark:'private'}),initialize:async(e,options)=>{called++;assert.equal(e.CF_STAGING_SCHEMA_RESUME_STEP,'37');assert.equal(options.endStep,209);for(const f of options.plan.files.filter(f=>f.start>=37))await DB.query(f.statements.join('\n'));return {status:'complete',last_verified_step:209};},deploy:()=>assert.fail('Must not deploy')});
 assert.equal(r.continued_to_candidate,false);assert.equal(r.workers_deployed,false);assert.equal(called,1);
 assert.deepEqual(DB.sql.prepare('SELECT * FROM staging_schema_history ORDER BY rowid LIMIT 2').all(),original);
 assert.equal(DB.sql.prepare('PRAGMA integrity_check').get().integrity_check,'ok');assert.equal(DB.sql.prepare('PRAGMA foreign_key_check').all().length,0);
 await assert.rejects(simpleRelease(env,{baseline,DB,get:async()=>({bookmark:'private'}),initialize:()=>assert.fail('Already initialized')}));
 await verifyProductionBaseline(DB,baseline);
 DB.sql.exec('CREATE TABLE staging_unreviewed(id TEXT)');await assert.rejects(verifyProductionBaseline(DB,baseline));
 }finally{DB.close();}
});
test('a failed initialization cannot report success or continue to a candidate release',async()=>{
 const DB=installed();try{await assert.rejects(simpleRelease({GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:'a'.repeat(40),SIMPLE_STAGING_ENABLED:'true',SIMPLE_STAGING_OPERATION:'initialize',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6'},{baseline,DB,get:async()=>({bookmark:'private'}),initialize:async()=>({status:'stopped',last_verified_step:37}),deploy:()=>assert.fail('Must not deploy')}));}finally{DB.close();}
});
test('audit verifies both pinned versions, allows formatting and remains SELECT-only',async()=>{
 const expected=expectedBaseline(new URL('../..',import.meta.url).pathname);const DB=installed(endStep);let posts=0,frontendDrift=false,sqlDrift=false;
 const transport=async(url,init)=>{
  const p=new URL(url).pathname;let result;
  if(init.method==='POST'){posts++;assert.deepEqual(JSON.parse(init.body),{sql:schemaSQL});result=[{success:true,results:DB.sql.prepare(schemaSQL).all().filter(o=>!o.name.startsWith('staging_')).map(o=>({...o,sql:sqlDrift&&o.name==='users'?o.sql.replace('NOT NULL','NULL'):(o.name==='users'?o.sql.replaceAll(',',', '):o.sql)})),meta:{rows_written:0}}];}
  else if(p.endsWith('/content/v2'))return new Response('var releaseIdentity="'+baseline.backend.identity+'";',{headers:{ETag:'"fixture"','Content-Type':'text/javascript'}});
  else if(p.includes('/versions/'))result={id:baseline.backend.version_id,resources:{script:{etag:'fixture'}}};
  else if(p.endsWith('/deployments')){const x=p.includes('cveharbor-site')?baseline.frontend:baseline.backend;result={deployments:[{id:x.deployment_id,versions:[{version_id:frontendDrift&&x===baseline.frontend?'different':x.version_id,percentage:100}]}]};}
  else result={uuid:baseline.production_database_id,name:'cveharbor-accounts'};
  return Response.json({success:true,result});
 };
 const env={CLOUDFLARE_AUDIT_ACCOUNT_ID:'f'.repeat(32),CLOUDFLARE_AUDIT_API_TOKEN:'fixture'};
 try{let r=await auditBaseline(env,expected,{transport});assert.equal(r.status,'verified');assert.equal(r.backend.source_sha,baseline.backend.source_sha);assert.equal(r.frontend.source_sha,baseline.frontend.source_sha);assert.equal(posts,1);assert.equal(r.rows_written,0);assert.equal(r.customer_records_read,false);
 frontendDrift=true;r=await auditBaseline(env,expected,{transport});assert.equal(r.status,'blocked');assert.equal(r.frontend_verified,false);
 frontendDrift=false;sqlDrift=true;r=await auditBaseline(env,expected,{transport});assert.equal(r.status,'blocked');assert.equal(r.schema_verified,false);
 }finally{DB.close();}
});

test('production profile cannot fall through into an integrated candidate migration or Worker deployment',async()=>{
 const DB=installed(endStep);
 const env={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_SHA:'a'.repeat(40),SIMPLE_STAGING_ENABLED:'true',SIMPLE_STAGING_OPERATION:'release',CF_STAGING_ACCOUNT_ID:TARGET.account,CF_STAGING_D1_DATABASE_ID:'fac61562-fc31-426d-8032-550aba63b7f6'};
 try{await assert.rejects(simpleRelease(env,{baseline,DB,get:async()=>({bookmark:'private'}),initialize:()=>assert.fail('No migration'),runner:()=>assert.fail('No native migration'),deploy:()=>assert.fail('No Worker activation')}),/one-time administrator approval/);
 await assert.rejects(simpleRelease({...env,SIMPLE_STAGING_OPERATION:'resume'},{baseline,DB,get:async()=>({bookmark:'private'})}));
 }finally{DB.close();}
});
