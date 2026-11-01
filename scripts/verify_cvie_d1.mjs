// Read-only production-D1 contract check with synthetic product identities.
// No customer records or sessions are loaded and no database writes are allowed.
import {writeFile} from 'node:fs/promises';
import {combinedCounts,combinedPage,excludedProductCves,sourceHealth} from '../account-backend/src/cvie-records.js';
import {productFamilies,productLabels} from '../account-backend/src/cvie-evidence.js';
import {coveragePlan,rawProductLabels} from '../account-backend/src/product-coverage.js';
import {isHyperV} from '../account-backend/src/hyperv.js';
const products=[
 {name:'Apache Tomcat',vendor:'apache',cpe:'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*'},
 {name:'PHP',vendor:'php',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*'},
 {name:'.NET Core',vendor:'microsoft',cpe:'cpe:2.3:a:microsoft:.net:*:*:*:*:*:*:*:*'},
 {name:'HyperV',vendor:'microsoft',cpe:'cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*'},
].map((p,i)=>({...p,id:'cvie-d1-readonly-probe-'+i,last_success_at:Date.now()}));
const families=products.flatMap(p=>productFamilies(p).map(key=>({product_id:p.id,key,labels:productLabels(p),raw_labels:coveragePlan(p).families.flatMap(cpe=>rawProductLabels({...p,cpe})),scope:isHyperV(p)?'windows_hyperv':''})));
const database='46710e51-7ca4-4571-b89c-921b9969de0b';
let queries=0;
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
  return {results:data.result[0].results};
 },async first(){return (await statement.all()).results[0]||null;}};return statement;
}};
const env={DB},now=Date.now(),recent=new Date(now-92*864e5).toISOString(),history=new Date(now-366*864e5).toISOString();
const ctx={products,families:JSON.stringify(families),sources:{}};
const report={checked_at:new Date(now).toISOString(),read_only:true,synthetic_products:true,checks:[]};
async function check(stage,fn){try{await fn();report.checks.push({stage,ok:true});}catch(error){report.checks.push({stage,ok:false,error:error.message});}}
await check('source schema',async()=>{const rows=(await DB.prepare('PRAGMA table_info(cvie_sources)').all()).results;report.source_columns=rows.map(r=>r.name);});
await check('saved scan JSON integrity',async()=>{report.invalid_scan_json=await DB.prepare('SELECT COUNT(*) AS invalid FROM cvie_products WHERE NOT json_valid(cursor_json)').first();});
await check('source status',()=>sourceHealth(env));
await check('combined counts',()=>combinedCounts(env,'cvie-d1-readonly-nonexistent-account',recent,history,now,ctx));
await check('advisory page',()=>combinedPage(env,'cvie-d1-readonly-nonexistent-account',recent,'','',now,ctx));
await check('withdrawal exclusions',()=>excludedProductCves(env,'cvie-d1-readonly-nonexistent-account',ctx));
await check('digest page',()=>combinedPage(env,'cvie-d1-readonly-nonexistent-account',recent,'','',now,{...ctx,digest:true}));
report.ok=report.checks.every(c=>c.ok);report.queries=queries;
await writeFile(new URL('../data/cvie-d1-check.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report));
if(!report.ok)process.exitCode=1;
