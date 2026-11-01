// Production release guard: metadata reads only, no user rows or secret values.
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
const account=process.env.CLOUDFLARE_ACCOUNT_ID,headers={Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'};
async function api(path,body){const r=await fetch('https://api.cloudflare.com/client/v4/accounts/'+account+path,{method:body?'POST':'GET',headers,...(body?{body:JSON.stringify(body)}:{})});const data=await r.json();if(!r.ok||!data.success)throw Error('Read-only Cloudflare release metadata check failed');return data.result;}
const settings=await api('/workers/scripts/cveharbor-accounts/settings'),bindings=settings.bindings||[];
const flags=Object.fromEntries(['PRODUCT_MONITOR_CHECKS_ENABLED','PRODUCT_MONITOR_DELIVERY_ENABLED','PRODUCT_MONITOR_TEST_ENABLED'].map(name=>[name,bindings.find(b=>b.name===name&&b.type==='plain_text')?.text||'false']));
assert.ok(Object.values(flags).every(v=>v!=='true'),'Monitoring activation requires separate approval');
const tables=await api('/d1/database/46710e51-7ca4-4571-b89c-921b9969de0b/query',{sql:"SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'lifecycle_monitor_%' OR name='lifecycle_watch_settings') ORDER BY name"});
const schedules=await api('/workers/scripts/cveharbor-accounts/schedules');
const report={flags,tables:tables[0].results.map(r=>r.name),secret_names:bindings.filter(b=>b.type==='secret_text').map(b=>b.name).sort(),sender:bindings.find(b=>b.name==='EMAIL_FROM'&&b.type==='plain_text')?.text||'',crons:(schedules.schedules||[]).map(s=>s.cron).sort()};
await fs.mkdir('work',{recursive:true});
if(process.argv.includes('--after')){
 assert.deepEqual(report,JSON.parse(await fs.readFile('work/monitoring-release-before.json','utf8')),'Deployment changed schema, activation flags, sender, secret bindings or schedule');
 const response=await fetch('https://api.cveharbor.com/v1/monitoring/status');assert.equal(response.status,401,'Private monitoring state must require authentication');
 console.log('PASS: monitoring code deployed; schema, secrets, sender, flags and Cron schedules unchanged; private route requires authentication');
}else{await fs.writeFile('work/monitoring-release-before.json',JSON.stringify(report));console.log('PASS: monitoring activation flags are off; pre-deployment schema/configuration metadata recorded without customer reads');}
