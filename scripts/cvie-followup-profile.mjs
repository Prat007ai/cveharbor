// Synthetic, local-only Worker/D1 profiling. No credentials or remote Cloudflare API.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const root=path.resolve(process.env.CVIE_PROFILE_ROOT||'.');
const {Miniflare}=await import(process.env.CVIE_MINIFLARE_MODULE||'miniflare');
const {build}=await import(process.env.CVIE_ESBUILD_MODULE||'esbuild');
const temp=fs.mkdtempSync(path.join(os.tmpdir(),'cvie-profile-'));
const summary=rows=>{const metric=k=>{const a=rows.map(r=>r[k]).sort((a,b)=>a-b);return {p50:a[Math.ceil(a.length*.5)-1],p95:a[Math.ceil(a.length*.95)-1],max:a.at(-1)};};return {samples:rows.length,...Object.fromEntries(['foreground_ms','total_ms','rows_read','rows_written','rpc_calls','d1_ms'].map(k=>[k,metric(k)]))};};
const instrument=`
function profileDB(db,events){
 const classify=sql=>{if(/sessions JOIN users/.test(sql))return 'authentication';if(/cvie_shared_scopes|cvie_product_scopes|cvie_shared_seeds/.test(sql))return 'shared_scope';if(/cvie_identity_evidence/.test(sql))return 'evidence_page';if(/cvie_kev|cvie_disclosure_queue/.test(sql))return 'kev_queue';if(/cvie_product_identities|cvie_identit/.test(sql))return 'identity_binding';if(/user_technology_catalogue/.test(sql))return 'catalogue';if(/cvie_products|cvie_subscriptions/.test(sql))return 'private_products';return 'other';};
 const wrap=(s,sql)=>({inner:s,sql,bind(...v){return wrap(s.bind(...v),sql)},async all(){const t=performance.now(),r=await s.all();events.push({group:classify(sql),kind:'statement',ms:performance.now()-t,read:r.meta.rows_read,write:r.meta.rows_written,d1:r.meta.duration,statements:1});return r;},async run(){return this.all()},async first(){return (await this.all()).results[0]||null}});
 return {prepare(sql){return wrap(db.prepare(sql),sql)},async batch(stmts){const t=performance.now(),r=await db.batch(stmts.map(s=>s.inner));events.push({group:[...new Set(stmts.map(s=>classify(s.sql)))].sort().join('+'),kind:'batch',ms:performance.now()-t,read:r.reduce((n,x)=>n+x.meta.rows_read,0),write:r.reduce((n,x)=>n+x.meta.rows_written,0),d1:r.reduce((n,x)=>n+x.meta.duration,0),statements:stmts.length});return r;}};
}
`;
const entry=`import worker from ${JSON.stringify(root+'/account-backend/src/index.js')};
import {subscribeProducts} from ${JSON.stringify(root+'/account-backend/src/cvie.js')};
${instrument}
export default {async fetch(request,env){
 const input=await request.json(),events=[],background=[],stages=[],start=performance.now();
 const e={...env,DB:profileDB(env.DB,events),CVIE_UNWRAPPED_DB:env.DB,CVIE_SHARED_SCANS_ENABLED:'true',CVIE_REGISTRY_ENABLED:'true',CVIE_FAST_EVIDENCE_ENABLED:'true'};
 const context={waitUntil(p){background.push(p)}};
 const call=async(method,url,body)=>{const t=performance.now();const response=await worker.fetch(new Request('https://local.invalid'+url,{method,headers:{Origin:'https://cveharbor.com',Cookie:'cvh_session='+input.token,'Content-Type':'application/json'},...(body?{body:JSON.stringify(body)}:{})}),e,context);const data=await response.json();if(!response.ok||data.cvie?.ready===false)throw Error('Profile request failed: '+url+' '+JSON.stringify(data));stages.push({route:url.split('?')[0].replace(new RegExp('products/[a-f0-9-]{36}'),'products/:id'),ms:performance.now()-t});return data;};
 if(input.service){await subscribeProducts(e,input.user,[{name:'PHP'}]);}
 else{
  await call('PUT','/v1/technology-catalogue',{defaults:[],products:[{name:'PHP',version:'8.3'}]});
  const state=await call('GET','/v1/cvie?view=bounded&scope=catalogue');
  const evidence=await call('GET','/v1/cvie/products/'+state.products[0].id+'/evidence?scope=catalogue');
  if(evidence.advisories.length!==100||evidence.coverage!=='indexed_partial')throw Error('Missing immediate stored evidence');
 }
 const foreground_ms=performance.now()-start;await Promise.all(background);
 return Response.json({foreground_ms,total_ms:performance.now()-start,stages,events,rows_read:events.reduce((n,e)=>n+e.read,0),rows_written:events.reduce((n,e)=>n+e.write,0),rpc_calls:events.length,d1_ms:events.reduce((n,e)=>n+e.d1,0)});
}};`;
await build({stdin:{contents:entry,resolveDir:root,sourcefile:'local-profile-worker.mjs'},bundle:true,format:'esm',platform:'browser',conditions:['workerd','worker','browser'],external:['node:*'],outfile:temp+'/worker.mjs'});
let outbound=0;
const mf=new Miniflare({modules:true,script:fs.readFileSync(temp+'/worker.mjs','utf8'),compatibilityDate:'2026-08-06',d1Databases:['DB'],outboundService:()=>{outbound++;return new Response('Synthetic provider unavailable',{status:503});}});
function split(sql){const r=spawnSync('python',['-c',`import sqlite3,json,sys
out=[]; buf=''
for ch in sys.stdin.read():
 buf+=ch
 if ch==';' and sqlite3.complete_statement(buf):out.append(buf);buf=''
print(json.dumps(out))`],{input:sql,encoding:'utf8'});if(r.status)throw Error(r.stderr);return JSON.parse(r.stdout);}
const result={environment:'local Miniflare Worker HTTP + D1; not remote staging or browser rendering',source_revision:spawnSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).stdout.trim()||'snapshot a2e4597',source_state:'Profiled source files at the supplied root; source_revision is the parent commit if the worktree is dirty',compatibility_date:'2026-08-06',started_at:new Date().toISOString(),scenarios:[]};
try{
 const db=await mf.getD1Database('DB');
 await db.exec('CREATE TABLE users(id TEXT PRIMARY KEY,email TEXT);\nCREATE TABLE sessions(id TEXT PRIMARY KEY,user_id TEXT,token_hash TEXT UNIQUE,expires_at INTEGER);\nCREATE TABLE user_totp(user_id TEXT PRIMARY KEY,enabled INTEGER);\nCREATE TABLE inventory_assets(user_id TEXT,technology TEXT);\nCREATE TABLE user_stack(user_id TEXT,technology TEXT);\nCREATE TABLE user_technology_catalogue(user_id TEXT PRIMARY KEY,preferences_json TEXT,updated_at INTEGER);');
 for(const file of ['0019_cvie.sql','0020_cvie_evidence.sql','0022_cvie_shared_scans.sql','0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql'])for(const sql of split(fs.readFileSync(root+'/account-backend/migrations/'+file,'utf8')))await db.prepare(sql).run();
 const {subscribeProducts}=await import('file://'+root+'/account-backend/src/cvie.js');
 await db.prepare("INSERT INTO users VALUES('seed','synthetic@example.test')").run();
 await subscribeProducts({DB:db,CVIE_SHARED_SCANS_ENABLED:'true',CVIE_REGISTRY_ENABLED:'true'},'seed',[{name:'PHP'}]);
 const scope=await db.prepare('SELECT id FROM cvie_shared_scopes').first(),now=new Date().toISOString();
 const total=Number(process.env.CVIE_PROFILE_CVES||10000);if(![10000,100000].includes(total))throw Error('Bounded fixture required');
 result.public_cves=total;
 const ingestion=[];
 for(let i=0;i<total;i+=100){const rows=Array.from({length:100},(_,j)=>{const n=i+j,id='CVE-2026-'+(10000+n);return {id,relevant:n<total/10,record:{id,published:now,updated:now,cvss:7.5,severity:'high',sources:[],affected_cpes:[],categories:['PHP'],cvie_identities:[]},affected:[{vendor:'php',product:'php',versions:[{version:'1',lessThan:'9',versionType:'semver',status:'affected'}]}]}}),payload=JSON.stringify(rows);
  const operations=[['disclosures',db.prepare("INSERT INTO cvie_disclosures SELECT json_extract(value,'$.id'),'PUBLISHED',?,?,json_extract(value,'$.record'),? FROM json_each(?)").bind(now,now,Date.now(),payload)],['affected_relationships',db.prepare("INSERT INTO cvie_disclosure_products SELECT json_extract(value,'$.id'),CASE WHEN json_extract(value,'$.relevant') THEN 'cpe:cpe:2.3:a:php:php:*:*:*:*:*:*:*:*' ELSE 'name:other:other' END,'affected',json_extract(value,'$.affected') FROM json_each(?)").bind(payload)],['nvd',db.prepare("INSERT INTO cvie_shared_advisories SELECT ?,json_extract(value,'$.id'),?,json_extract(value,'$.record'),'fixture' FROM json_each(?) WHERE json_extract(value,'$.relevant')").bind(scope.id,now,payload)]];
  const out=await db.batch(operations.map(o=>o[1]));out.forEach((r,k)=>ingestion.push({operation:operations[k][0],read:r.meta.rows_read,write:r.meta.rows_written}));
 }
 result.ingestion=Object.fromEntries(['disclosures','affected_relationships','nvd'].map(k=>[k,ingestion.filter(x=>x.operation===k).reduce((a,x)=>({read:a.read+x.read,write:a.write+x.write}),{read:0,write:0})]));
 // Representative KEV catalogue, already verified stored disclosures. No external fetch needed.
 const kev=Array.from({length:1766},(_,i)=>({cveID:'CVE-2026-'+(10000+i),dateAdded:'2026-01-01',vendorProject:i<10?'PHP':'Unrelated',product:i<10?'PHP':'Unrelated'}));
 await db.prepare("INSERT INTO cvie_kev(cve_id,date_added,vendor,product,record_json,checked_at) SELECT json_extract(value,'$.cveID'),'2026-01-01',json_extract(value,'$.vendorProject'),json_extract(value,'$.product'),value,0 FROM json_each(?)").bind(JSON.stringify(kev)).run();
 await db.prepare("UPDATE cvie_shared_scopes SET status='ready',recent_complete_at=?,history_complete_at=?,last_success_at=?,next_attempt_at=?").bind(Date.now(),Date.now(),Date.now(),Date.now()+86400000).run();
 await db.prepare('UPDATE cvie_sources SET next_attempt_at=?').bind(Date.now()+86400000).run();
 let userNumber=0;
 for(const concurrency of [1,10,50]){
  const samples=[],repeats=concurrency===1?20:concurrency===10?5:3;
  for(let wave=0;wave<repeats;wave++){
   const accounts=Array.from({length:concurrency},()=>{const user='synthetic-'+(++userNumber),token=createHash('sha256').update(user).digest('hex');return {user,token};});
   await db.batch(accounts.flatMap(a=>[db.prepare('INSERT INTO users VALUES(?,?)').bind(a.user,'synthetic@example.test'),db.prepare('INSERT INTO user_totp VALUES(?,1)').bind(a.user),db.prepare('INSERT INTO sessions VALUES(?,?,?,?)').bind(a.user,a.user,createHash('sha256').update(a.token).digest('hex'),Math.floor(Date.now()/1000)+86400)]));
   await Promise.all(accounts.map(async a=>{const t=performance.now(),r=await mf.dispatchFetch('http://local.invalid/profile',{method:'POST',body:JSON.stringify(a)});if(!r.ok)throw Error(await r.text());const data=await r.json();samples.push({...data,host_roundtrip_ms:performance.now()-t});}));
  }
  const groups={};for(const sample of samples)for(const e of sample.events){const g=groups[e.group]||={calls:0,statements:0,elapsed_ms:0,d1_ms:0,read:0,write:0};g.calls++;g.statements+=e.statements;g.elapsed_ms+=e.ms;g.d1_ms+=e.d1;g.read+=e.read;g.write+=e.write;}
  const stages={};for(const s of samples)for(const stage of s.stages){(stages[stage.route]||=[]).push(stage.ms);}for(const k in stages){const a=stages[k].sort((a,b)=>a-b);stages[k]={p50:a[Math.ceil(a.length*.5)-1],p95:a[Math.ceil(a.length*.95)-1]};}
  result.scenarios.push({concurrency,waves:repeats,...summary(samples),groups,stages});
 }
 result.scopes=(await db.prepare('SELECT COUNT(*) AS n FROM cvie_shared_scopes').first()).n;result.provider_requests=outbound;
 if(result.scopes!==1||outbound)throw Error('Warm onboarding must reuse intelligence without external requests');
 fs.writeFileSync(process.argv[2]||temp+'/results.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}finally{await mf.dispose();fs.rmSync(temp,{recursive:true,force:true});}
