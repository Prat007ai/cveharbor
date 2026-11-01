// Public NVD requests against a disposable database; never writes production.
import fs from 'node:fs';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import {subscribeProducts,runCvieStep,monthsAgo} from '../account-backend/src/cvie.js';
const env={DB:new DB(),NVD_API_KEY:process.env.NVD_API_KEY};
const report={checked_at:new Date().toISOString(),ok:false,scope:'NVD recent-history integration for four real product families; disposable account/database',products:[]};
try{
 await subscribeProducts(env,'a',[{name:'Apache Tomcat',vendor:'Apache'},{name:'PHP',vendor:'PHP'},{name:'WordPress',vendor:'WordPress'},{name:'Windows Server 2022',vendor:'Microsoft'}]);
 for(let request=0;request<60;request++){
  const result=await runCvieStep(env);if(result.retrying)throw Error('A real product history check requires a provider retry');
  const pending=await env.DB.prepare('SELECT COUNT(*) AS total FROM cvie_products WHERE recent_complete_at IS NULL').first();
  if(!pending.total){report.ok=true;report.requests=request+1;break;}
  await new Promise(resolve=>setTimeout(resolve,env.NVD_API_KEY?1100:6700));
 }
 const products=(await env.DB.prepare('SELECT id,name,cpe,status,recent_complete_at FROM cvie_products ORDER BY name').all()).results;
 for(const p of products){const records=(await env.DB.prepare('SELECT cve_id FROM cvie_advisories WHERE product_id=? AND published>=? ORDER BY cve_id').bind(p.id,new Date(monthsAgo(Date.now(),3)).toISOString()).all()).results;
  report.products.push({name:p.name,cpe:p.cpe,status:p.status,recent_complete_at:p.recent_complete_at,matched_advisories:records.length,sample_ids:records.slice(0,3).map(r=>r.cve_id)});
 }
 if(!report.ok)throw Error('The bounded live-product check did not complete all recent windows');
}catch(error){report.ok=false;report.error=error.message;}
fs.writeFileSync('data/cvie-product-check.json',JSON.stringify(report,null,2)+'\n');console.log(JSON.stringify(report));
