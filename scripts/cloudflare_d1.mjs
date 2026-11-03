import fs from 'node:fs';import assert from 'node:assert/strict';import {restBatch} from './cvie_rest_batch.mjs';
export const productionDatabase=()=>fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8').match(/database_id\s*=\s*"([a-f0-9-]+)"/)[1];
export function d1Client({database=productionDatabase(),readOnly=true,fetcher=fetch,env=process.env}={}){
 const account=env.CLOUDFLARE_ACCOUNT_ID,token=env.CLOUDFLARE_API_TOKEN;
 assert.ok(account&&token,'Use configured Cloudflare environment credentials');assert.match(database,/^[a-f0-9-]{36}$/);assert.match(account,/^[a-f0-9]{32}$/i);
 let queries=0;const base=`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}`;
 async function query(sql,params=[]){
  if(readOnly)assert.ok(/^SELECT\b/i.test(sql)&&!sql.includes(';'),'Read-only client accepts one SELECT only');
  queries++;const r=await fetcher(base+'/query',{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params}),signal:AbortSignal.timeout(60000)});let data;try{data=await r.json();}catch{throw Error('D1 returned an invalid response');}
  assert.ok(r.ok&&data.success&&Array.isArray(data.result)&&data.result.every(x=>x.success),'D1 operation failed; review aggregate workflow evidence (credentials and row data omitted)');
  if(readOnly)for(const result of data.result)assert.equal(result.meta?.rows_written||0,0,'Read-only audit unexpectedly wrote data');return data.result;
 }
 function prepare(sql){const make=params=>({sql,params,bind:(...args)=>make(args),all:async()=>{const r=(await query(sql,params))[0];return {results:r.results,meta:r.meta};},first:async()=>((await query(sql,params))[0].results||[])[0]||null,run:async()=>{const r=(await query(sql,params))[0];return {meta:r.meta};}});return make([]);}
 return {prepare,query,get queries(){return queries;},batch:async statements=>{assert.ok(!readOnly);return query(restBatch(statements).sql);},async metadata(){const r=await fetcher(base,{headers:{Authorization:'Bearer '+token},signal:AbortSignal.timeout(15000)});const data=await r.json();assert.ok(r.ok&&data.success,'Database identity verification failed');return data.result;}};
}
