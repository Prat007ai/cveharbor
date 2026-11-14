// Fictional outage rehearsal inputs. Never read customer data or call a provider.
import fs from 'node:fs';
import assert from 'node:assert/strict';
export const extraSchemas=['agent-schema.sql','migrations/0019_cvie.sql','migrations/0020_cvie_evidence.sql','migrations/0022_cvie_shared_scans.sql','remediation-schema.sql','software-upgrade-history-schema.sql','customer-score-schema.sql','alert-schema.sql','lifecycle-schema.sql','migrations/0016_website_monitor.sql','migrations/0023_lifecycle_monitoring.sql','../scripts/fixtures/capacity-read-compatibility.sql'];
export function addOutageSchema(fixture){
 for(const file of extraSchemas)fixture.sql.exec(fs.readFileSync(new URL('../account-backend/'+file,import.meta.url),'utf8'));
 fixture.sql.exec('CREATE TABLE IF NOT EXISTS user_technology_catalogue(user_id TEXT PRIMARY KEY,preferences_json TEXT,updated_at INTEGER)');
}
export async function seedOutage(fixture,cvie,now=Date.now()){
 addOutageSchema(fixture);
 const env={DB:fixture.DB,CVIE_SHARED_SCANS_ENABLED:'true',AGENT_INVENTORY_SCHEMA:'1'};
 const cpe='cpe:2.3:a:microsoft:.net_core:*:*:*:*:*:*:*:*';
 for(let i=0;i<50;i++){
  const id=(900000+i).toString(16).padStart(8,'0')+'-1111-4111-8111-111111111111';
  fixture.sql.prepare('INSERT INTO cvie_products(id,user_id,name_key,name,cpe) VALUES(?,?,?,?,?)').run(id,'owner-'+i,'.net runtime','.NET Runtime','');
  await cvie.subscribeProducts(env,'owner-'+i,[{name:'.NET Runtime',cpe}],'inventory');
 }
 const scope=fixture.sql.prepare('SELECT * FROM cvie_shared_scopes').get();assert.ok(scope);
 // Saved evidence is intentionally present before the unavailable provider is exercised.
 const date=new Date(now-86400000).toISOString();
 for(let i=0;i<200;i++){
  const raw={id:'CVE-2026-'+(800000+i),published:date,lastModified:date,vulnStatus:'Analyzed',descriptions:[{lang:'en',value:'Fictional .NET Runtime vulnerability for an isolated load test.'}],metrics:{cvssMetricV31:[{cvssData:{baseScore:8.1}}]},configurations:[{nodes:[{cpeMatch:[{vulnerable:true,criteria:cpe,versionStartIncluding:'8.0.0',versionEndExcluding:'8.0.2'}]}]}]};
  const record=cvie.normalizeNvd(raw,scope);
  fixture.sql.prepare('INSERT INTO cvie_shared_advisories VALUES(?,?,?,?,?)').run(scope.id,raw.id,date,JSON.stringify(record),'outage-fixture');
 }
 fixture.sql.prepare('UPDATE cvie_shared_scopes SET last_success_at=?,recent_complete_at=?').run(now-86400000,now-86400000);
 return {env,epoch:now,advisories:200};
}
export function outageAdapter(worker,runCvieStep,epoch,controlKey){
 const reads=new Set(['/v1/me','/v1/inventory/page','/v1/inventory/status','/v1/inventory/software-history','/v1/customer-score-history','/v1/cvie','/v1/cvie/progress','/v1/cvie/advisories','/v1/finding-assignments','/v1/team/organizations','/v1/workspace/items','/v1/workspace/summary','/v1/workspace/trend']);
 return {async fetch(req,env,ctx){
  const url=new URL(req.url);
  if(url.pathname==='/__outage/routing'){
   if(req.method!=='POST'||req.headers.get('X-Outage-Control')!==controlKey)return new Response('',{status:404});
   const primary=env.DB.withSession('first-primary');const a=await primary.prepare('SELECT 1 AS routing_probe').all(),bookmark=primary.getBookmark();
   const b=bookmark?await env.DB.withSession(bookmark).prepare('SELECT 1 AS routing_probe').all():null;
   // This unconstrained diagnostic reads only a literal, never customer data.
   const c=await env.DB.withSession('first-unconstrained').prepare('SELECT 1 AS routing_probe').all();
   const meta=r=>r?{primary:r.meta?.served_by_primary,region:r.meta?.served_by_region,duration_ms:r.meta?.duration}:null;
   return Response.json({bookmark_present:!!bookmark,primary:meta(a),anchored:meta(b),unconstrained_literal:meta(c)});
  }
  if(url.pathname==='/__outage/step'){
   if(req.method!=='POST'||req.headers.get('X-Outage-Control')!==controlKey)return new Response('',{status:404});
   const mode=url.searchParams.get('mode');if(!['timeout','503'].includes(mode))return new Response('',{status:400});
   let calls=0;const at=epoch+(mode==='503'?360000:0),start=Date.now();
   const result=await runCvieStep(env,async()=>{
    calls++;
    if(mode==='timeout'){await new Promise(resolve=>setTimeout(resolve,20000));throw new DOMException('Fictional NVD timeout','TimeoutError');}
    return new Response('Fictional NVD unavailable',{status:503,headers:{'Retry-After':'300'}});
   },at);
   return Response.json({calls,result,elapsed_ms:Date.now()-start});
  }
  // Real authenticated reads; no mutations, email, AI or real provider dispatch.
  if(req.method!=='GET'||!reads.has(url.pathname))return Response.json({error:'Read-only rehearsal'},{status:405});
  return worker.fetch(req,env,ctx);
 }};
}
