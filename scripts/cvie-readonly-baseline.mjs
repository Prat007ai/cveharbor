import {assertReadOnlySql} from './cvie_readonly_sql.mjs';
// Fixed read-only production diagnostics. No customer identifiers/content, provider
// requests, migrations, scan triggers or load tests. Credentials never enter output.
import fs from 'node:fs';
import {combinedPage} from '../account-backend/src/cvie-records.js';
import {productFamilies,productLabels} from '../account-backend/src/cvie-evidence.js';
import {rawProductLabels} from '../account-backend/src/product-coverage.js';
const token=process.env.CLOUDFLARE_API_TOKEN,account=process.env.CLOUDFLARE_ACCOUNT_ID;
if(!token||!account)throw Error('Read-only diagnostics require existing Cloudflare credentials');
const config=fs.readFileSync(new URL('../account-backend/wrangler.toml',import.meta.url),'utf8');
const database=/database_id\s*=\s*"([a-f0-9-]+)"/.exec(config)?.[1];if(!database)throw Error('Existing database binding not found');
const metrics=[];
const DB={prepare(sql){
 assertReadOnlySql(sql);
 const make=params=>({bind:(...args)=>make(args),async all(){
  const response=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/d1/database/${database}/query`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({sql,params}),signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw Error('Read-only D1 query failed with HTTP '+response.status);
  const result=await response.json(),r=result.result?.[0];if(!result.success||!r?.success)throw Error('Read-only D1 query failed');
  if(r.meta?.rows_written!==0)throw Error('Unexpected write metadata in read-only diagnostic');
  metrics.push({rows_read:r.meta.rows_read,rows_written:r.meta.rows_written,duration_ms:r.meta.duration});return r;
 },async first(){return (await this.all()).results?.[0]||null;}});return make([]);
}};
const report={checked_at:new Date().toISOString(),environment:'production read-only aggregate diagnostics',read_only:true,customer_content:false};
report.sources=(await DB.prepare('SELECT id,status,last_attempt_at,last_success_at,publisher_at,checkpoint,coverage_start_at,next_attempt_at,lease_until,record_retry_at,CASE WHEN error<>\'\' THEN 1 ELSE 0 END AS has_error FROM cvie_sources ORDER BY id').all()).results;
report.queue=(await DB.prepare("SELECT priority,CASE WHEN attempts=0 THEN 'not_attempted' ELSE 'retrying' END AS processing_status,COUNT(*) AS records,MIN(NULLIF(revision,'')) AS oldest_publisher_revision,MAX(attempts) AS maximum_attempts FROM cvie_disclosure_queue GROUP BY priority,processing_status ORDER BY priority,processing_status").all()).results;
report.queue_age_note='Existing schema has no enqueue timestamps. Publisher revision age is not queue age; processing throughput requires multiple observations or new operation telemetry.';
report.scan_states=(await DB.prepare('SELECT status,COUNT(*) AS scopes,MIN(last_success_at) AS oldest_success,MAX(last_success_at) AS latest_success FROM cvie_shared_scopes GROUP BY status').all()).results;
report.records=await DB.prepare("SELECT (SELECT COUNT(*) FROM cvie_kev) AS kev,(SELECT COUNT(*) FROM cvie_disclosures) AS disclosures,(SELECT COUNT(*) FROM cvie_disclosures WHERE state='REJECTED') AS rejected,(SELECT COUNT(*) FROM cvie_disclosure_queue) AS queued,(SELECT COUNT(*) FROM cvie_shared_advisories) AS shared_nvd").first();
const now=Date.now(),product={id:'cvie-readonly-synthetic-product',user_id:'cvie-readonly-nonexistent-account',name:'PHP',vendor:'php',cpe:'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*',cursor_json:'{}',candidates_json:'[]'};
const ctx={products:[product],scope:'all',families:JSON.stringify(productFamilies(product).map(key=>({product_id:product.id,key,labels:productLabels(product),raw_labels:rawProductLabels(product),scope:''}))),sources:Object.fromEntries(report.sources.map(s=>[s.id,s]))};
const before=metrics.length,start=performance.now();
const page=await combinedPage({DB,CVIE_SHARED_SCANS_ENABLED:'true'},product.user_id,new Date(now-92*864e5).toISOString(),'',product.id,now,ctx);
report.existing_public_php_lookup={result_count:page.advisories.length,has_more:Boolean(page.next),statements:metrics.length-before,rows_read:metrics.slice(before).reduce((n,m)=>n+m.rows_read,0),rows_written:0,elapsed_ms:performance.now()-start,synthetic_identity:true};
report.query_metrics=metrics;
fs.mkdirSync('artifacts',{recursive:true});fs.writeFileSync('artifacts/cvie-readonly-baseline.json',JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify(report,null,2));
