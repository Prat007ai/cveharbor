// Local-only schema ablation: never opens a remote Cloudflare account.
import fs from 'node:fs';import path from 'node:path';import {spawnSync} from 'node:child_process';
const {Miniflare}=await import(process.env.CVIE_MINIFLARE_MODULE||'miniflare');
const root=path.resolve('.'),baseline='a2e4597',mf=new Miniflare({modules:true,script:'export default {fetch(){return new Response("local only")}}',d1Databases:['LEGACY','REVIEWED','OPTIMIZED','FLAGS_OFF']});
const get=(name,revision)=>{if(!revision)return fs.readFileSync(root+'/account-backend/migrations/'+name,'utf8');const r=spawnSync('git',['show',revision+':account-backend/migrations/'+name],{encoding:'utf8'});if(r.status)throw Error('Missing baseline migration');return r.stdout;};
function split(sql){const r=spawnSync('python',['-c',`import sqlite3,json,sys
out=[]; buf=''
for ch in sys.stdin.read():
 buf+=ch
 if ch==';' and sqlite3.complete_statement(buf):out.append(buf);buf=''
print(json.dumps(out))`],{input:sql,encoding:'utf8'});return JSON.parse(r.stdout);}
const result={environment:'local Miniflare D1 schema experiment; not remote billing',baseline,rows_per_density:10000,variants:{}};
try{for(const name of ['LEGACY','REVIEWED','OPTIMIZED','FLAGS_OFF']){
 const db=await mf.getD1Database(name);await db.exec('CREATE TABLE users(id TEXT PRIMARY KEY);');
 for(const file of ['0019_cvie.sql','0020_cvie_evidence.sql','0022_cvie_shared_scans.sql',...(name==='LEGACY'?[]:['0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql'])])for(const sql of split(get(file,name==='REVIEWED'?baseline:null)))await db.prepare(sql).run();
 const cpe='cpe:2.3:a:php:php:*:*:*:*:*:*:*:*';await db.prepare('INSERT INTO cvie_shared_scopes(id,signature,name,vendor,cpe) VALUES(?,?,?,?,?)').bind('fixture',JSON.stringify(['fixture',[cpe],[],null]),'PHP','php',cpe).run();
 const cases=[];
 for(const [run,percent] of [0,10,100].entries()){
  const base=100000+run*10000,mapped=percent*100;
  const operations=[['disclosures',db.prepare(`WITH RECURSIVE n(x) AS(SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10000)
   INSERT INTO cvie_disclosures SELECT 'CVE-2026-'||CAST(?+x AS INTEGER),'PUBLISHED','2026-11-02T12:00:00Z','2026-11-02T12:00:00Z',json_object('id','CVE-2026-'||CAST(?+x AS INTEGER)),0 FROM n`).bind(base,base)],
   ['affected_relationships',db.prepare(`INSERT INTO cvie_disclosure_products SELECT cve_id,CASE WHEN cve_id<=? THEN ? ELSE 'name:unrelated:unrelated' END,'affected',?
    FROM cvie_disclosures WHERE cve_id>? AND cve_id<=?`).bind('CVE-2026-'+(base+mapped),'cpe:'+cpe,JSON.stringify([{vendor:'php',product:'php',versions:[{version:'1',lessThan:'9',status:'affected'}]}]),'CVE-2026-'+base,'CVE-2026-'+(base+10000))],
   ['nvd',db.prepare("INSERT INTO cvie_shared_advisories SELECT 'fixture',cve_id,published,record_json,'fixture' FROM cvie_disclosures WHERE cve_id>? AND cve_id<=?").bind('CVE-2026-'+base,'CVE-2026-'+(base+mapped))]];
  const out=await db.batch(operations.map(x=>x[1]));cases.push({mapped_percent:percent,operations:out.map((r,i)=>({operation:operations[i][0],rows_read:r.meta.rows_read,rows_written:r.meta.rows_written})),rows_read:out.reduce((n,r)=>n+r.meta.rows_read,0),rows_written:out.reduce((n,r)=>n+r.meta.rows_written,0)});
 }
 const counts=await db.prepare('SELECT (SELECT COUNT(*) FROM cvie_disclosures) disclosures,(SELECT COUNT(*) FROM cvie_disclosure_products) relationships').first();
 if(counts.disclosures!==30000||counts.relationships!==30000)throw Error('Incomplete synthetic fixture '+JSON.stringify(counts)+' missing '+JSON.stringify((await db.prepare('SELECT cve_id FROM cvie_disclosures WHERE NOT EXISTS(SELECT 1 FROM cvie_disclosure_products p WHERE p.cve_id=cvie_disclosures.cve_id) LIMIT 5').all()).results));
 result.variants[name]={record_counts:counts,feature_flags:name==='FLAGS_OFF'?'registry=false; fast_evidence=false (SQL triggers have no environment flags)':'schema experiment',cases};
 if(name!=='LEGACY')result.variants[name].rejection_plan=(await db.prepare("EXPLAIN QUERY PLAN SELECT cve_id FROM cvie_disclosures WHERE state='REJECTED'").all()).results;
}
fs.writeFileSync(process.argv[2]||'/tmp/cvie-ingestion-cost.json',JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(result,null,2));
}finally{await mf.dispose();}
