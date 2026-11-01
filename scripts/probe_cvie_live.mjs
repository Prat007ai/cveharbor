// Actual CVIE + real NVD, using a disposable local SQLite database. No deployment.
import fs from 'node:fs';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,monthsAgo} from '../account-backend/src/cvie.js';
const env={DB:new DB(),NVD_API_KEY:process.env.NVD_API_KEY};
const report={checked_at:new Date().toISOString(),provider:'NVD',engine:'CVIE',operation:'isolated database backfill; no production writes',ok:false};
try{
 await subscribeProducts(env,'a',[{name:'Apache Tomcat'}]);
 for(let page=0;page<30;page++){
  const result=await runCvieStep(env);
  if(result.retrying)throw Error('Live source could not complete; automatic retry is scheduled');
  if(result.complete){report.ok=true;report.pages_checked=page+1;break;}
  await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1100:6700));
 }
 const product=await env.DB.prepare('SELECT * FROM cvie_products').first();
 report.status=product.status;report.cpe=product.cpe;
 report.advisories=(await env.DB.prepare('SELECT record_json FROM cvie_advisories ORDER BY published DESC').all()).results.map(row=>JSON.parse(row.record_json));
 report.history_count=report.advisories.length;
 report.recent_count=report.advisories.filter(a=>Date.parse(a.published)>=monthsAgo(Date.now(),3)).length;
 if(product.error)report.error=product.error;
}catch(e){report.error=e.message;}
fs.writeFileSync('data/cvie-provider-check.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({...report,advisories:undefined}));
