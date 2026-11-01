// Read-only production-D1 contract check with synthetic product identities.
// No customer records or sessions are loaded and no database writes are allowed.
import {writeFile} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {cvieRoute} from '../account-backend/src/cvie.js';
import {combinedCounts,combinedPage,excludedProductCves,sourceHealth} from '../account-backend/src/cvie-records.js';
import {productFamilies,productLabels} from '../account-backend/src/cvie-evidence.js';
import {coveragePlan,rawProductLabels,coverageMetadata,catalogueNames} from '../account-backend/src/product-coverage.js';
import {isHyperV} from '../account-backend/src/hyperv.js';
import {knownIdentity} from '../account-backend/src/product-identity.js';
const userId='cvie-d1-readonly-nonexistent-account';
const products=[
 {name:'Apache Tomcat',vendor:'apache',cpe:'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*'},
 {name:'PHP',vendor:'php',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*'},
 {name:'.NET Core',vendor:'microsoft',cpe:'cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*'},
 {name:'HyperV',vendor:'microsoft',cpe:'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*'},
 ...catalogueNames.map(name=>({name,vendor:'',cpe:name==='HyperV'?'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*':knownIdentity(name)?.cpe||''})),
].map((p,i)=>({...p,id:'cvie-d1-readonly-probe-'+i,user_id:userId,last_success_at:Date.now(),
 status:p.cpe?'ready':'needs_identity',candidates_json:'[]',cursor_json:JSON.stringify(coverageMetadata(coveragePlan(p))),
 recent_count:0,history_count:0,recent_complete_at:Date.now(),history_complete_at:Date.now(),error:''}));
const families=products.flatMap(p=>productFamilies(p).map(key=>({product_id:p.id,key,labels:productLabels(p),raw_labels:coveragePlan(p).families.flatMap(cpe=>rawProductLabels({...p,cpe})),scope:isHyperV(p)?'windows_hyperv':''})));
const database='46710e51-7ca4-4571-b89c-921b9969de0b';
let queries=0,rowsRead=0,rowsWritten=0;
const DB={prepare(sql){
 if(!/^\s*(SELECT|WITH|PRAGMA table_info)/i.test(sql))throw Error('Diagnostic permits read-only statements only');
 let params=[];
 const statement={bind(...values){params=values;return statement;},async all(){
  queries++;
  const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},body:JSON.stringify({sql,params})});
  const data=await response.json();
  if(!response.ok||!data.success||!data.result?.[0]?.success){
   const message=JSON.stringify(data.errors||data.result?.[0]?.error||{http:response.status});
   throw Error(message.slice(0,1500));
  }
  rowsRead+=data.result[0].meta?.rows_read||0;rowsWritten+=data.result[0].meta?.rows_written||0;
  return {results:data.result[0].results};
 },async first(){return (await statement.all()).results[0]||null;}};return statement;
}};
const env={DB,CVIE_SHARED_SCANS_ENABLED:process.env.CVIE_SHARED_SCANS_ENABLED||'false'},now=Date.now(),recent=new Date(now-92*864e5).toISOString(),history=new Date(now-366*864e5).toISOString();
const ctx={products,families:JSON.stringify(families),sources:{}};
const report={checked_at:new Date(now).toISOString(),read_only:true,synthetic_products:true,checks:[]};
async function check(stage,fn){
 const before={queries,rowsRead,rowsWritten};let error;
 try{await fn();}catch(caught){error=caught.message;}
 report.checks.push({stage,ok:!error,...(error?{error}:{}),statements:queries-before.queries,rows_read:rowsRead-before.rowsRead,rows_written:rowsWritten-before.rowsWritten});
}
await check('source schema',async()=>{const rows=(await DB.prepare('PRAGMA table_info(cvie_sources)').all()).results;report.source_columns=rows.map(r=>r.name);});
await check('saved scan JSON integrity',async()=>{report.invalid_scan_json=await DB.prepare('SELECT COUNT(*) AS invalid FROM cvie_products WHERE NOT json_valid(cursor_json)').first();});
await check('source status',()=>sourceHealth(env));
await check('combined counts',async()=>{const counts=await combinedCounts(env,userId,recent,history,now,ctx);assert.ok(counts.some(c=>c.recent_count>0),'Expected verified public evidence for the synthetic product catalogue');});
await check('advisory page',async()=>{const page=await combinedPage(env,userId,recent,'','',now,ctx);assert.ok(page.advisories.length,'Expected public advisories for the synthetic product catalogue');});
await check('withdrawal exclusions',()=>excludedProductCves(env,userId,ctx));
await check('digest page',()=>combinedPage(env,userId,recent,'','',now,{...ctx,digest:true}));
// Use the actual status handler, substituting only the owned-product SELECT.
// All evidence queries still execute on real D1; writes remain prohibited.
const statusEnv={...env,DB:{prepare(sql){
 if(/^\s*SELECT p\.\*/.test(sql)&&sql.includes('WHERE p.user_id=?')){
  const statement={bind(...params){assert.ok(params.includes(userId));return statement;},async all(){return {results:products};}};return statement;
 }
 return DB.prepare(sql);
}}};
await check('status handler and all three engine cards',async()=>{
 const response=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie'),statusEnv,{id:userId});
 assert.equal(response.status,200);const state=await response.json();
 assert.equal(state.products.length,products.length);
 assert.deepEqual(state.evidence.sources.map(s=>s.id).sort(),['cisa_kev','cve_program','nvd']);
 assert.ok(state.products.every(p=>p.progress&&p.status));
});
await check('lightweight progress handler and account-scoped products',async()=>{
 const response=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/progress'),statusEnv,{id:userId});
 assert.equal(response.status,200);const state=await response.json();
 assert.equal(state.products.length,products.length);assert.ok(state.products.every(p=>p.progress&&!('recent_count' in p)));
 assert.deepEqual(state.evidence.sources.map(s=>s.id).sort(),['cisa_kev','cve_program','nvd']);
});
await check('progress SELECT on real D1 for a nonexistent synthetic account',async()=>{
 const response=await cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/progress'),env,{id:userId});
 assert.equal(response.status,200);assert.deepEqual((await response.json()).products,[]);
});
report.ok=report.checks.every(c=>c.ok);report.queries=queries;
await writeFile(new URL('../data/cvie-d1-check.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report));
if(!report.ok)process.exitCode=1;
