// One-time/resumable deployment bootstrap. Reads legacy private scan caches only
// to re-normalize their public NVD evidence. Logs aggregate outcomes, never rows,
// aliases, account identifiers, SQL parameters or credentials.
import {reconcileSharedScopes,seedSharedHistory} from '../account-backend/src/shared-scopes.js';
import {normalizeNvd} from '../account-backend/src/cvie.js';
const database='46710e51-7ca4-4571-b89c-921b9969de0b';
let stage='initialization';
async function query(body){
 const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${process.env.CLOUDFLARE_ACCOUNT_ID}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},body:JSON.stringify(body)});
 const result=await response.json();
 if(!response.ok||!result.success||!result.result?.every(r=>r.success))throw Error('Production D1 operation failed');
 return result.result;
}
const DB={prepare(sql){let params=[];const statement={sql,get params(){return params;},bind(...values){params=values;return statement;},async all(){return (await query({sql,params}))[0];},async first(){return (await statement.all()).results[0]||null;},async run(){return (await query({sql,params}))[0];}};return statement;},
 async batch(statements){
  // The public REST API accepts one SQL string. Reuse one JSON parameter in
  // every statement so values stay bound, including quotes and private labels.
  const sql=statements.map((s,i)=>{let n=0;const bound=s.sql.replace(/'(?:''|[^'])*'|"(?:""|[^"])*"|--[^\n]*|\/\*[\s\S]*?\*\/|\?/g,token=>token==='?'?`json_extract(?1,'$[${i}][${n++}]')`:token);if(n!==s.params.length)throw Error('Unsupported batch parameters');return bound;}).join(';\n');
  return query({sql,params:[JSON.stringify(statements.map(s=>s.params))]});
 }};
const env={DB,CVIE_SHARED_SCANS_ENABLED:'true'};
try{
 stage='verify transactional D1 REST batch transport';
 const transport=await DB.batch([DB.prepare('SELECT ? AS value').bind(1),DB.prepare('SELECT ? AS value').bind(2)]);
 if(transport.length!==2||transport[0].results[0]?.value!==1||transport[1].results[0]?.value!==2)throw Error('Unexpected D1 batch response');
 if(process.argv.includes('--preflight')){
  console.log(JSON.stringify({ok:true,read_only:true,batch_transport_verified:true}));
 }else{
 let linked=0,seeded=0;
 stage='link verified product identities';
 for(let i=0;i<200;i++){const result=await reconcileSharedScopes(env,null,Date.now(),500);linked+=result.linked;if(!result.linked)break;if(i===199)throw Error('Bootstrap batch limit reached');}
 stage='sanitize and import existing public source history';
 for(let i=0;i<2000;i++){
  const scope=await DB.prepare("SELECT * FROM cvie_shared_scopes WHERE seed_state='pending' AND lease_until<? ORDER BY id LIMIT 1").bind(Date.now()).first();
  if(!scope)break;
  const result=await seedSharedHistory(env,scope,normalizeNvd);seeded+=result.seeded||0;
  if(i===1999)throw Error('Seed batch limit reached');
 }
 stage='verify shared cache bootstrap completion';
 const pending=await DB.prepare("SELECT COUNT(*) AS n FROM cvie_shared_scopes WHERE seed_state='pending'").first();
 if(pending.n)throw Error('A history migration is still leased or pending; rerun this resumable step');
 const totals=await DB.prepare('SELECT (SELECT COUNT(*) FROM cvie_shared_scopes) AS scopes,(SELECT COUNT(*) FROM cvie_shared_advisories) AS public_advisories,(SELECT COUNT(*) FROM cvie_product_scopes WHERE scope_id IS NOT NULL) AS private_links').first();
 console.log(JSON.stringify({ok:true,linked_this_run:linked,public_records_imported:seeded,...totals,legacy_private_history_preserved:true}));
 }
}catch{
 console.error('Shared CVIE bootstrap failed during '+stage+'. Legacy history remains preserved; deployment must not proceed until the resumable bootstrap passes.');process.exitCode=1;
}

