import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {updateTopicHistory,catalogueHistory} from '../src/cvie-topic-history.js';
import {monthsAgo,cvieRoute} from '../src/cvie.js';
const migration=readFileSync(new URL('../../deployment/proposals/cvie-topic-history/0033_cvie_topic_history.sql',import.meta.url),'utf8');
test('shared source history uses saved topics, stable pages and withdrawals across accounts',async()=>{
 const env={DB:new DB()},db=env.DB.sql,now=Date.now();
 try{
  const day=n=>new Date(now-n*86400000).toISOString();
  const upsert=db.prepare('INSERT INTO cvie_disclosures VALUES(?,?,?,?,?,?)');
  const affected=db.prepare('INSERT INTO cvie_disclosure_products VALUES(?,?,?,?)');
  const id=i=>'CVE-2026-'+(30000+i);
  for(let i=0;i<80;i++){
   const r={id:id(i),published:day(i===79?172:2),title:'Host security update',sources:[]};
   upsert.run(r.id,'PUBLISHED',r.published,r.published,JSON.stringify(r),now);
   const row={vendor:'Microsoft',product:'Windows Server 2022',defaultStatus:i===78?'unaffected':'affected'};
   affected.run(r.id,'host','affected',JSON.stringify([row]));
  }
  db.exec(migration);
  db.prepare('INSERT INTO user_technology_catalogue VALUES(?,?,?)').run('b',JSON.stringify({defaults:['MySQL / MariaDB']}),now);
  await updateTopicHistory(env);await updateTopicHistory(env);await updateTopicHistory(env);
  const page=(user,period,after='')=>catalogueHistory(env,user,new URLSearchParams({months:String(period),after}),now,monthsAgo);
  const a=await page('a',3);assert.equal(a.advisories.length,50);assert.ok(a.next);
  assert.deepEqual(a.advisories[0].topic_matches.map(x=>x.topic),['Windows','Windows Server OS']);
  const b=await page('a',3,a.next);assert.equal(b.advisories.length,28);
  assert.equal(new Set([...a.advisories,...b.advisories].map(r=>r.id)).size,78);
  assert.equal(b.next,null);assert.equal((await page('b',3)).advisories.length,0);
  assert.equal((await page('b',3,a.next)).invalid,true);assert.equal((await page('a',12,a.next)).invalid,true);
  const route=(account,flag,query='months=3')=>cvieRoute(new Request('https://api.cveharbor.com/v1/cvie/catalogue-history?'+query),{...env,CVIE_TOPIC_HISTORY_ENABLED:flag},{id:account},{});
  assert.equal((await (await route('a','false')).json()).enabled,false);
  const live=await (await route('a','true')).json();assert.equal(live.account_id,'a');assert.equal(live.advisories.length,50);
  assert.equal((await (await route('b','true')).json()).advisories.length,0);
  await assert.rejects(route('a','true','months=3&after=broken'),/invalid/);
  const year=await page('a',12);assert.equal((await page('a',12,year.next)).advisories.length,29);
  db.prepare("UPDATE cvie_disclosures SET state='REJECTED' WHERE cve_id=?").run(id(77));
  assert.ok(!(await page('a',3)).advisories.some(r=>r.id===id(77)));
  await updateTopicHistory(env);
  assert.equal(db.prepare('SELECT count(*) n FROM cvie_topic_matches WHERE cve_id=?').get(id(77)).n,0);
 }finally{db.close();}
});
