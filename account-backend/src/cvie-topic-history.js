import {catalogueNames} from './product-coverage.js';
import {cnaApplicability} from './cvie-evidence.js';
import {hyperVStatement} from './hyperv.js';

// These rules classify public, source-named affected products for browsing.
// Version, tenant or asset applicability is never inferred from a topic.
const microsoft=/\bmicrosoft\b/i;
const rules=[
 ['Windows Server OS',/\bwindows server\b/i,microsoft],['Windows 11 OS',/\bwindows 11\b/i,microsoft],
 ['Windows',/\bwindows\b/i,microsoft],['Azure',/\bazure\b/i,microsoft],
 ['Microsoft 365',/\b(microsoft 365|office 365|exchange online|sharepoint online|microsoft teams)\b/i,microsoft],
 ['Exchange SE',/\bexchange server\b/i,microsoft],['SharePoint / SharePoint Server',/\bsharepoint\b/i,microsoft],
 ['Microsoft Power Platform',/\b(power platform|power automate|power apps?|dataverse)\b/i,microsoft],
 ['Dynamics 365',/\bdynamics 365\b/i,microsoft],['Microsoft Fabric / Power BI',/\b(microsoft fabric|power bi)\b/i,microsoft],
 ['Azure AI / AI SDK',/\bazure (?:ai|openai|machine learning)\b/i,microsoft],
 ['.NET / ASP.NET',/(?:\.net\b|\baspnetcore\b|\bdotnet\b)/i,microsoft],
 ['.NET Core',/(?:\.net core\b|asp\.net core\b|\.net (?:[5-9]|1[0-9])(?:\.|\b))/i,microsoft],
 ['WordPress / Plugins',/\b(wordpress|woocommerce)\b/i],['PHP',/^(?:php|php fpm)(?:\b|$)/i],
 ['Python / PyPI',/\b(cpython|python|pypi)\b/i],['Angular',/^@?angular(?:\b|\/)/i],
 ['React / Next.js',/^(?:react(?: dom)?|next\.?js)(?:\b|$)/i],
 ['JavaScript / TypeScript',/\b(javascript|typescript)\b/i],['Node.js / npm',/\b(node\.?js|npm)\b/i],
 ['Drupal / CMS',/\b(drupal|umbraco|kentico)\b/i],['Linux',/\blinux kernel\b/i],
 ['Fortinet',/./,/\bfortinet\b/i],['Sophos Firewall',/\b(firewall|sfos|xg firewall)\b/i,/\bsophos\b/i],
 ['VMware',/./,/\bvmware\b/i],['Veeam Backup & Replication',/\bbackup (?:and|&) replication\b/i,/\bveeam\b/i],
 ['Docker / Kubernetes',/\b(docker|kubernetes|containerd)\b/i],['AWS',/./,/\b(amazon web services|aws)\b/i],
 ['SQL Server',/\b(sql server|azure sql)\b/i,microsoft],['MySQL / MariaDB',/\b(mysql|mariadb|percona)\b/i],
 ['NoSQL / MongoDB',/\bmongodb\b/i],['Progress Telerik',/\btelerik\b/i],['Sitefinity',/\bsitefinity\b/i],
 ['Kendo UI',/\bkendo ui\b/i],['jQuery / Bootstrap',/\b(jquery|bootstrap)\b/i],['iOS / Android',/\b(ios|ipados|android)\b/i]
];
function topicProducts(affected,record){
 const result=new Map();
 for(const item of affected){
  if(cnaApplicability([item])==='unaffected')continue;
  const name=String(item.product||'').trim(),vendor=String(item.vendor||'').trim();
  if(!name||/^(?:n\/a|unknown|unspecified)$/i.test(name))continue;
  const product=name.replace(/[_-]/g,' '),matches=rules.filter(([,p,v])=>p.test(product)&&(!v||v.test(vendor))).map(([label])=>label);
  if(microsoft.test(vendor)&&(/\bhyper v\b/i.test(product)||/\bwindows\b/i.test(product)&&hyperVStatement(record)))matches.push('HyperV');
  if(item.packageName&&item.collectionURL){
   try{
    const host=new URL(item.collectionURL).hostname.toLowerCase();
    const topic=({'npmjs.org':'Node.js / npm','registry.npmjs.org':'Node.js / npm','www.npmjs.com':'Node.js / npm','pypi.org':'Python / PyPI','plugins.trac.wordpress.org':'WordPress / Plugins','wordpress.org':'WordPress / Plugins'})[host];
    if(topic)matches.push(topic,'Application dependencies');
   }catch{/* Unrecognized directory retains only its explicit product matches. */}
  }
  for(const topic of matches){
   if(!result.has(topic))result.set(topic,new Set());
   result.get(topic).add([vendor,name].filter(Boolean).join(' · '));
  }
 }
 return [...result].map(([topic,products])=>({topic,products:[...products].sort()}));
}
export async function updateTopicHistory(env){
 const db=env.DB, state=await db.prepare('SELECT * FROM cvie_topic_backfill WHERE id=1').first();
 if(!state.complete){
  const {results}=await db.prepare('SELECT cve_id FROM cvie_disclosures WHERE cve_id>? ORDER BY cve_id LIMIT 40').bind(state.after_id).all();
  // A repeated/concurrent tick can replay discovery. Live updates retain their revision.
  await db.batch([
   db.prepare('INSERT OR IGNORE INTO cvie_topic_pending SELECT value,hex(randomblob(16)) FROM json_each(?)').bind(JSON.stringify(results.map(r=>r.cve_id))),
   db.prepare('UPDATE cvie_topic_backfill SET after_id=?,complete=? WHERE id=1 AND after_id=?').bind(results.at(-1)?.cve_id||state.after_id,Number(results.length<40),state.after_id)
  ]);
 }
 const {results:queue}=await db.prepare('SELECT * FROM cvie_topic_pending ORDER BY cve_id LIMIT 40').all();
 if(!queue.length)return;
 const ids=JSON.stringify(queue.map(r=>r.cve_id));
 const {results:rows}=await db.prepare("SELECT d.cve_id,d.state,d.record_json,d.published,p.affected_json FROM json_each(?) i JOIN cvie_disclosures d ON d.cve_id=i.value LEFT JOIN cvie_disclosure_products p ON p.cve_id=d.cve_id").bind(ids).all();
 const records=new Map();
 for(const r of rows){
  if(r.state!=='PUBLISHED')continue;
  if(!records.has(r.cve_id))records.set(r.cve_id,{record:JSON.parse(r.record_json),published:r.published,affected:[]});
  if(r.affected_json)records.get(r.cve_id).affected.push(...JSON.parse(r.affected_json));
 }
 const guard='EXISTS(SELECT 1 FROM cvie_topic_pending WHERE cve_id=? AND revision=?)';
 // Each CVE is atomically replaced. A newer source revision wins on the next tick.
 for(const {cve_id,revision} of queue){
  const r=records.get(cve_id),matches=r?topicProducts(r.affected,r.record):[];
  await db.batch([
   db.prepare('DELETE FROM cvie_topic_matches WHERE cve_id=? AND '+guard).bind(cve_id,cve_id,revision),
   db.prepare("INSERT INTO cvie_topic_matches SELECT ?,json_extract(value,'$.topic'),?,json_extract(value,'$.products') FROM json_each(?) WHERE "+guard).bind(cve_id,r?.published||'',JSON.stringify(matches),cve_id,revision),
   db.prepare('DELETE FROM cvie_topic_pending WHERE cve_id=? AND revision=?').bind(cve_id,revision)
  ]);
 }
}

export async function catalogueHistory(env,userId,params,now,monthsAgo){
 const db=env.DB;
 const saved=await db.prepare('SELECT preferences_json FROM user_technology_catalogue WHERE user_id=?').bind(userId).first();
 const defaults=saved?(JSON.parse(saved.preferences_json).defaults||[]):catalogueNames;
 const topics=[...new Set(defaults.filter(t=>catalogueNames.includes(t)))].sort();
 const period=params.get('months')||'3',token=params.get('after');
 let end=new Date(now).toISOString(),cursor=[end,'~'];
 if(token){
  try{const v=JSON.parse(atob(token));
   if(v.period!==period||v.topics!==JSON.stringify(topics)||!Array.isArray(v.cursor)||v.cursor.length!==2||typeof v.cursor[0]!=='string'||new Date(v.cursor[0]).toISOString()!==v.cursor[0]||!/^CVE-\d{4}-\d{4,}$/.test(v.cursor[1]))throw Error();
   if(typeof v.end!=='string'||new Date(v.end).toISOString()!==v.end||Date.parse(v.end)>now||now-Date.parse(v.end)>86400000||v.cursor[0]>v.end)throw Error();
   cursor=v.cursor;end=v.end;
  }catch{return {invalid:true};}
 }
 if(!topics.length)return {advisories:[],next:null,coverage:'no_topics_selected'};
 // Each indexed topic contributes at most 51 rows, even with a year of history.
 // Any globally top-51 disclosure must rank in the top 51 of a matching topic.
 const cutoff=new Date(monthsAgo(Date.parse(end),Number(period))).toISOString();
 const part=`SELECT * FROM (
  SELECT m.cve_id,m.published FROM cvie_topic_matches m
  JOIN cvie_disclosures d ON d.cve_id=m.cve_id AND d.state='PUBLISHED' AND d.published=m.published
  WHERE m.topic=? AND m.published>=(SELECT first_date FROM bounds) AND m.published<=(SELECT last_date FROM bounds)
  AND (m.published,m.cve_id)<((SELECT cursor_date FROM bounds),(SELECT cursor_id FROM bounds))
  AND NOT EXISTS(SELECT 1 FROM cvie_topic_pending q WHERE q.cve_id=m.cve_id)
  ORDER BY m.published DESC,m.cve_id DESC LIMIT 51)`;
 const sql=`WITH bounds(first_date,last_date,cursor_date,cursor_id) AS (VALUES(?,?,?,?))
  SELECT DISTINCT published,cve_id FROM (${topics.map(()=>part).join(' UNION ALL ')})
  ORDER BY published DESC,cve_id DESC LIMIT 51`;
 const {results:page}=await db.prepare(sql).bind(cutoff,end,...cursor,...topics).all();
 const keys=JSON.stringify(page.slice(0,50).map(r=>r.cve_id));
 const {results:details}=await db.prepare(`SELECT d.cve_id,d.record_json,m.topic,m.products_json,k.cve_id AS kev
  FROM json_each(?) ids JOIN cvie_disclosures d ON d.cve_id=ids.value
  JOIN cvie_topic_matches m ON m.cve_id=d.cve_id AND m.topic IN(SELECT value FROM json_each(?))
  LEFT JOIN cvie_kev k ON k.cve_id=d.cve_id
  WHERE d.state='PUBLISHED' AND NOT EXISTS(SELECT 1 FROM cvie_topic_pending q WHERE q.cve_id=d.cve_id)
  ORDER BY CAST(ids.key AS INTEGER),m.topic`).bind(keys,JSON.stringify(topics)).all();
 const records=new Map();
 for(const r of details){
  if(!records.has(r.cve_id))records.set(r.cve_id,{...JSON.parse(r.record_json),known_exploited:!!r.kev,topic_matches:[]});
  records.get(r.cve_id).topic_matches.push({topic:r.topic,source_products:JSON.parse(r.products_json)});
 }
 const coverage=await db.prepare("SELECT complete,EXISTS(SELECT 1 FROM cvie_topic_pending) AS pending,(SELECT coverage_start_at FROM cvie_sources WHERE id='cve_program') AS source_start FROM cvie_topic_backfill WHERE id=1").first();
 return {advisories:[...records.values()],next:page.length>50?btoa(JSON.stringify({period,end,topics:JSON.stringify(topics),cursor:[page[49].published,page[49].cve_id]})):null,coverage:coverage.complete&&!coverage.pending?'available_stored_disclosures':'indexing_stored_disclosures',source_start:coverage.source_start,from:cutoff,to:end};
}
