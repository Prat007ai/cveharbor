// Local-only attribution for shared scope creation and long-tail stored-index hydration.
import fs from 'node:fs';import path from 'node:path';import os from 'node:os';import {spawnSync} from 'node:child_process';
const root=path.resolve(process.env.CVIE_PROFILE_ROOT||'.'),{Miniflare}=await import(process.env.CVIE_MINIFLARE_MODULE||'miniflare'),{build}=await import(process.env.CVIE_ESBUILD_MODULE||'esbuild');
const dir=fs.mkdtempSync(path.join(os.tmpdir(),'cvie-hydration-'));
await build({stdin:{resolveDir:root,contents:`import {registerVerifiedCpe} from ${JSON.stringify(root+'/account-backend/src/product-registry.js')};
import {subscribeProducts} from ${JSON.stringify(root+'/account-backend/src/cvie.js')};
import {observeCvie} from ${JSON.stringify(root+'/account-backend/src/cvie-metrics.js')};
export default {async fetch(req,env){const data=await req.json();let metric;const e={...env,CVIE_REGISTRY_ENABLED:'true',CVIE_FAST_EVIDENCE_ENABLED:'true',CVIE_SHARED_SCANS_ENABLED:'true',CVIE_METRICS_ENABLED:'true',CVIE_METRIC_SINK:m=>metric=m};const value=await observeCvie(e,'onboard',measured=>data.cpe?registerVerifiedCpe(measured,data.cpe):subscribeProducts(measured,data.user,[{name:'PHP'}]));return Response.json({value,metric});}};`},bundle:true,format:'esm',platform:'browser',outfile:dir+'/worker.mjs'});
let external=0;const mf=new Miniflare({modules:true,script:fs.readFileSync(dir+'/worker.mjs','utf8'),compatibilityDate:'2026-08-06',d1Databases:['DB'],outboundService:()=>{external++;throw Error('No provider requests allowed');}});
function split(sql){return JSON.parse(spawnSync('python',['-c',`import sqlite3,json,sys
out=[];buf=''
for ch in sys.stdin.read():
 buf+=ch
 if ch==';' and sqlite3.complete_statement(buf):out.append(buf);buf=''
print(json.dumps(out))`],{input:sql,encoding:'utf8'}).stdout);}
const summarize=rows=>{const values=k=>rows.map(r=>r.metric[k]).sort((a,b)=>a-b),p95=k=>values(k)[Math.ceil(rows.length*.95)-1];return {requests:rows.length,p95_ms:p95('duration_ms'),p95_rows_read:p95('rows_read'),total_rows_read:rows.reduce((n,r)=>n+r.metric.rows_read,0),total_rows_written:rows.reduce((n,r)=>n+r.metric.rows_written,0),total_statements:rows.reduce((n,r)=>n+r.metric.statements,0)};};
const out={environment:'local Miniflare Worker service operations; no remote staging',scope_creation:null,hydration:[]};
try{const db=await mf.getD1Database('DB');await db.exec('CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT);\nCREATE TABLE inventory_assets(user_id TEXT,technology TEXT);\nCREATE TABLE user_stack(user_id TEXT,technology TEXT);\nCREATE TABLE user_technology_catalogue(user_id TEXT PRIMARY KEY,preferences_json TEXT,updated_at INTEGER);');
 for(const f of ['0019_cvie.sql','0020_cvie_evidence.sql','0022_cvie_shared_scans.sql','0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql'])for(const s of split(fs.readFileSync(root+'/account-backend/migrations/'+f,'utf8')))await db.prepare(s).run();
 await db.batch(Array.from({length:50},(_,i)=>db.prepare('INSERT INTO users VALUES(?,?)').bind('fixture-'+i,'synthetic@example.test')));
 const request=async data=>{const r=await mf.dispatchFetch('http://local.invalid',{method:'POST',body:JSON.stringify(data)});if(!r.ok)throw Error(await r.text());return r.json();};
 out.scope_creation={...summarize(await Promise.all(Array.from({length:50},(_,i)=>request({user:'fixture-'+i})))),shared_scopes:(await db.prepare('SELECT COUNT(*) n FROM cvie_shared_scopes').first()).n};
 for(const concurrency of [1,10,50]){
  const cpe='cpe:2.3:a:example:profile_tool_'+concurrency+':*:*:*:*:*:*:*:*',ids=Array.from({length:105},(_,i)=>'CVE-2026-'+(7000000+concurrency*1000+i)),date=new Date().toISOString();
  await db.batch([db.prepare("INSERT INTO cvie_disclosures SELECT value,'PUBLISHED',?,?,json_object('id',value),0 FROM json_each(?)").bind(date,date,JSON.stringify(ids)),db.prepare("INSERT INTO cvie_disclosure_products SELECT value,?,'affected',? FROM json_each(?)").bind('cpe:'+cpe,JSON.stringify([{vendor:'example',product:'profile_tool_'+concurrency,versions:[{version:'1',status:'affected'}]}]),JSON.stringify(ids))]);
  const results=await Promise.all(Array.from({length:concurrency},()=>request({cpe}))),identity=results[0].value.id;
  out.hydration.push({concurrency,...summarize(results),jobs:(await db.prepare('SELECT COUNT(*) n FROM cvie_identity_index_jobs WHERE identity_id=?').bind(identity).first()).n,indexed_records:(await db.prepare('SELECT COUNT(*) n FROM cvie_identity_evidence WHERE identity_id=?').bind(identity).first()).n,checkpoint:(await db.prepare('SELECT cursor_json,complete,failed FROM cvie_identity_index_jobs WHERE identity_id=?').bind(identity).first())});
 }
 out.external_requests=external;if(external||out.scope_creation.shared_scopes!==1||out.hydration.some(r=>r.jobs!==1||r.indexed_records<100||r.indexed_records>105))throw Error('Shared work or bounded hydration invariant failed');
 fs.writeFileSync(process.argv[2]||'/tmp/cvie-hydration.json',JSON.stringify(out,null,2)+'\n');console.log(JSON.stringify(out,null,2));
}finally{await mf.dispose();fs.rmSync(dir,{recursive:true,force:true});}
