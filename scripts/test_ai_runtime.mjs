// Real Cloudflare Worker + D1, synthetic users and an isolated provider fixture.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {fixture} from '../account-backend/tests/helpers/ai-db.mjs';
import {ALLOWANCE,RESERVATION,period} from '../account-backend/src/ai-pricing.js';
const require=createRequire(path.resolve(process.argv[2],'node_modules/wrangler/package.json'));
const {Miniflare,convertV4MiniflareOptions}=require('miniflare'),{build}=require('esbuild');
const root=fileURLToPath(new URL('..',import.meta.url)),f=fixture();
const script=`import {assist} from './account-backend/src/ai-allowance.js';
Date.now=()=>Date.parse('2026-11-11T18:00:00Z');
export default {async fetch(req,env){try{return Response.json(await assist(env,{id:'owner'},'north',await req.json()));}catch(e){return Response.json({error:e.message},{status:500});}}};`;
const bundled=await build({stdin:{contents:script,resolveDir:root},bundle:true,format:'esm',write:false});
const provider=`let calls=0;export default {async fetch(req){if(new URL(req.url).hostname==='counts.test')return Response.json({calls});calls++;
 if(req.url.includes('login.microsoftonline.com'))return Response.json({access_token:'fictional',token_type:'Bearer',expires_in:3600});
 return Response.json({model:'gpt-5.4-mini-2026-03-17',usage:{prompt_tokens:88,completion_tokens:172,total_tokens:260},choices:[{message:{content:'Fictional answer'},finish_reason:'stop'}]});}};`;
const bindings={...f.env};delete bindings.DB;
const mf=new Miniflare(convertV4MiniflareOptions({workers:[{name:'allowance',modules:true,script:bundled.outputFiles[0].text,compatibilityDate:'2026-10-28',d1Databases:{DB:'fictional-ai'},outboundService:'provider',bindings},
 {name:'provider',modules:true,script:provider,compatibilityDate:'2026-10-28'}]}));
try{
 const db=await mf.getD1Database('DB');
 // Preserve whole CREATE TRIGGER bodies when splitting this reviewed test schema.
 const sql=(f.setup+f.schema).replace(/--[^\n]*/g,'');
 const statements=[];let remaining=sql.trim();
 while(remaining){const match=remaining.match(remaining.startsWith('CREATE TRIGGER')?/^[\s\S]*?\bEND;/:/^[^;]+;/);assert.ok(match,'Incomplete fixture SQL');statements.push(match[0]);remaining=remaining.slice(match[0].length).trim();}
 // Separate setup from trigger definitions; SQL parser must see CREATE at start.
 for(const statement of statements)await db.prepare(statement).run();
 await db.prepare("INSERT INTO ai_organizations VALUES('north',1)").run();
 await db.prepare('INSERT INTO ai_months(org,month,spent) VALUES(?,?,?)').bind('north',period(Date.parse('2026-11-11T18:00:00Z')),ALLOWANCE-RESERVATION).run();
 const call=key=>mf.dispatchFetch('https://fixture.test/',{method:'POST',body:JSON.stringify({customer:'customer-a',request_key:key,question:'Fictional test'})}).then(r=>r.json());
 const results=await Promise.all(Array.from({length:20},(_,i)=>call('fictional-concurrent-'+i)));
 assert.equal(results.filter(r=>r.state==='settled').length,1,JSON.stringify(results));
 assert.equal(results.filter(r=>r.state==='blocked').length,19);
 const service=await mf.getWorker('provider');assert.equal((await (await service.fetch('https://counts.test/')).json()).calls,2);
 const repeat=await call('fictional-concurrent-0');assert.equal(repeat.replayed,true);
 const balance=await db.prepare('SELECT spent,reserved FROM ai_months').first();assert.ok(balance.spent+balance.reserved<=ALLOWANCE);
 console.log('PASS: 20 concurrent native Worker/D1 requests; one Azure inference, 19 hard stops, duplicate suppressed.');
}finally{await mf.dispose();f.store.close();}
