// Local D1 emulator only. Never reads credentials or opens a Cloudflare account.
// Install Miniflare separately; set CVIE_MINIFLARE_MODULE to its absolute entry if needed.
import fs from 'node:fs';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {observeCvie} from '../account-backend/src/cvie-metrics.js';
import {subscribeProducts} from '../account-backend/src/cvie.js';
import {combinedPage} from '../account-backend/src/cvie-records.js';
import {immediateEvidence,evidencePageSql} from '../account-backend/src/cvie-onboarding.js';
import {refreshEvidence} from '../account-backend/src/cvie-evidence.js';
const {Miniflare}=await import(process.env.CVIE_MINIFLARE_MODULE||'miniflare');
const root=fileURLToPath(new URL('../',import.meta.url));
const mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("local only")}}',d1Databases:['BASE','NEW']});
const oldSource=spawnSync('git',['show','3b9dfce:account-backend/src/cvie-evidence.js'],{cwd:root,encoding:'utf8'});if(oldSource.status)throw Error('Baseline commit unavailable');
const baselineCode=oldSource.stdout.replace(/from '\.\//g,"from '"+new URL('../account-backend/src/',import.meta.url).href);
const {refreshEvidence:baselineRefresh}=await import('data:text/javascript;base64,'+Buffer.from(baselineCode).toString('base64'));
const total=Number(process.env.CVIE_BENCHMARK_CVES||10000);if(![10000,100000].includes(total))throw Error('Use a bounded 10k or 100k local fixture');
const relevant=total/10;
const results={baseline_commit:'3b9dfce',environment:'local Miniflare D1; not Cloudflare staging or billing',timestamp:new Date().toISOString(),workload:{public_cves:total,relevant_cves:relevant,accounts:50,synthetic_inventory_rows:5000,page_limit:100},samples:{}};
function split(sql){const r=spawnSync('python',['-c',`import sqlite3,json,sys
sql=sys.stdin.read(); out=[]; buf=''
for ch in sql:
 buf+=ch
 if ch==';' and sqlite3.complete_statement(buf):
  out.append(buf);buf=''
print(json.dumps(out))`],{input:sql,encoding:'utf8'});if(r.status)throw Error(r.stderr);return JSON.parse(r.stdout);}
async function migration(db,name){for(const sql of split(fs.readFileSync(root+'account-backend/migrations/'+name,'utf8')))await db.prepare(sql).run();}
async function measured(env,label,fn){let metric;const start=performance.now();const value=await observeCvie({...env,CVIE_METRICS_ENABLED:'true',CVIE_METRIC_SINK:m=>metric=m},label,fn);return {value,metric:{...metric,wall_ms:performance.now()-start}};}
const stats=values=>{const sorted=key=>values.map(v=>v[key]).sort((a,b)=>a-b),p95=key=>sorted(key)[Math.ceil(values.length*.95)-1];return {runs:values.length,rows_read_p95:p95('rows_read'),rows_written_p95:p95('rows_written'),duration_ms_p95:p95('duration_ms'),wall_ms_p95:p95('wall_ms'),metadata_complete:values.every(v=>v.metadata_complete)};};
try{
 for(const name of ['BASE','NEW']){
  const db=await mf.getD1Database(name);await db.exec('CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT);\nCREATE TABLE inventory_assets(user_id TEXT,technology TEXT);\nCREATE TABLE user_stack(user_id TEXT,technology TEXT);\nCREATE TABLE user_technology_catalogue(user_id TEXT PRIMARY KEY,preferences_json TEXT,updated_at INTEGER);');
  for(const m of ['0019_cvie.sql','0020_cvie_evidence.sql','0022_cvie_shared_scans.sql',...(name==='NEW'?['0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql']:[])])await migration(db,m);
  await db.batch(Array.from({length:50},(_,i)=>db.prepare('INSERT INTO users VALUES(?,?)').bind('u'+i,'synthetic')));
  await db.prepare("WITH RECURSIVE n(x) AS(SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<4999) INSERT INTO inventory_assets SELECT 'u'||(x%50),'PHP' FROM n").run();
  const env={DB:db,CVIE_SHARED_SCANS_ENABLED:'true',...(name==='NEW'?{CVIE_REGISTRY_ENABLED:'true',CVIE_FAST_EVIDENCE_ENABLED:'true'}:{})};
  const first=await measured(env,'onboard',e=>subscribeProducts(e,'u0',[{name:'PHP'}]));results.samples[name+'_cold_identity_save']=first.metric;
  const p=await db.prepare("SELECT * FROM cvie_products WHERE user_id='u0'").first(),scope=await db.prepare('SELECT id FROM cvie_shared_scopes').first();
  let writes=0;const now=new Date().toISOString();
  for(let start=0;start<total;start+=100){const records=Array.from({length:100},(_,i)=>{const k=start+i,id='CVE-2026-'+(10000+k),target=k<relevant;return {id,target,record:{id,published:now,updated:now,cvss:7.5,severity:'high',sources:[],affected_cpes:[],categories:[target?'PHP':'Other'],cvie_identities:[]},affected:[{vendor:target?'php':'other',product:target?'php':'other',defaultStatus:'unaffected',versions:[{version:'1',lessThan:'9',versionType:'semver',status:'affected'}]}]};});
   const payload=JSON.stringify(records);
   const r=await db.batch([
    db.prepare("INSERT INTO cvie_disclosures SELECT json_extract(value,'$.id'),'PUBLISHED',?,?,json_extract(value,'$.record'),? FROM json_each(?)").bind(now,now,Date.now(),payload),
    db.prepare("INSERT INTO cvie_disclosure_products SELECT json_extract(value,'$.id'),CASE WHEN json_extract(value,'$.target') THEN ? ELSE 'name:other:other' END,'affected',json_extract(value,'$.affected') FROM json_each(?)").bind('cpe:'+p.cpe,payload),
    db.prepare("INSERT INTO cvie_shared_advisories SELECT ?,json_extract(value,'$.id'),?,json_extract(value,'$.record'),'fixture' FROM json_each(?) WHERE json_extract(value,'$.target')").bind(scope.id,now,payload)
   ]);writes+=r.reduce((n,r)=>n+r.meta.rows_written,0);
  }
  results.samples[name+'_fixture_ingestion_rows_written']=writes;
  const samples=[],saves=[];
  for(let i=0;i<20;i++){
   const sample=await measured(env,'evidence',e=>name==='BASE'?combinedPage(e,'u0','2026-01-01T00:00:00Z','',p.id):immediateEvidence(e,'u0',p.id));
   if(sample.value.advisories.length!==100)throw Error('Invalid result count');samples.push(sample.metric);
   saves.push((await measured(env,'onboard',e=>subscribeProducts(e,'u0',[{name:'PHP'}]))).metric);
  }
  results.samples[name+'_100_result_page']=stats(samples);results.samples[name+'_identical_save']=stats(saves);
  if(name==='NEW'){
   results.query_plan=(await db.prepare('EXPLAIN QUERY PLAN '+evidencePageSql).bind('php','2026-01-01T00:00:00Z','~','~',101).all()).results;
   const start=performance.now();await Promise.all(Array.from({length:49},(_,i)=>subscribeProducts(env,'u'+(i+1),[{name:'PHP'}])));results.concurrent={accounts:50,duration_ms:performance.now()-start,scopes:(await db.prepare('SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n};
  }
  {
   const t=Date.now(),items=Array.from({length:1766},(_,i)=>({cveID:'CVE-2026-'+(10000+i),dateAdded:'2026-01-01',vendorProject:'PHP',product:'PHP'}));
   await db.prepare("UPDATE cvie_sources SET next_attempt_at=? WHERE id='cve_program'").bind(t+1e9).run();
   const feed=async()=>Response.json({dateReleased:new Date(t).toISOString(),count:items.length,vulnerabilities:items});
   results.samples[name+'_kev_first']=(await measured(env,'disclosure_dispatch',e=>(name==='NEW'?refreshEvidence:baselineRefresh)(e,feed,t))).metric;
   results.samples[name+'_kev_unchanged']=(await measured(env,'disclosure_dispatch',e=>(name==='NEW'?refreshEvidence:baselineRefresh)(e,feed,t+16*60000))).metric;
   if(name==='NEW')results.target_met_local=results.samples.NEW_100_result_page.rows_read_p95<=1000&&results.samples.NEW_100_result_page.rows_written_p95===0;
  }
 }
 const out=process.argv[2];if(out)fs.writeFileSync(out,JSON.stringify(results,null,2)+'\n');console.log(JSON.stringify(results,null,2));
}finally{await mf.dispose();}
