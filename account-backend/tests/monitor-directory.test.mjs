import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {common,lookupDirectory,cachedDirectory,directoryIdentity,directoryCycles,DIRECTORY_LIMIT} from '../src/monitor-directory.js';
import {handler as lifecycleHandler} from '../src/lifecycle.js';
import {monitoringHandler} from '../src/monitoring.js';
import {checkSubscribedSources,q} from '../src/monitor-engine.js';
const NOW=Date.parse('2026-11-02T01:00:00Z');
export function memoryCache(){const entries=new Map();return {entries,async match(key){return entries.get(key)?.clone()},async put(key,response){entries.set(key,response.clone())}};}
function env(){const db=new DB();db.sql.exec(fs.readFileSync(new URL('../lifecycle-schema.sql',import.meta.url),'utf8'));db.sql.exec(fs.readFileSync(new URL('../migrations/0023_lifecycle_monitoring.sql',import.meta.url),'utf8'));return {DB:db,DIRECTORY_CACHE:memoryCache()};}
const raw=[{cycle:'10',latest:'10.6.8',eol:'2026-12-09',support:false,releaseDate:'2022-12-14',latestReleaseDate:'2026-10-01'},{cycle:'11',latest:'11.2.1',eol:false}];
const api=(env,path='',method='GET',data={},id='a')=>monitoringHandler(new Request('https://api.cveharbor.com/v1/monitoring'+path,{method}),env,{id,email:id+'@example.test'},'/v1/monitoring'+path,data,NOW);
test('curated identities cover Microsoft and major frameworks with exact aliases, not fuzzy auto-selection',()=>{
 assert.ok(common.length>=80);assert.equal(new Set(common.map(p=>p.slug)).size,common.length);
 for(const name of ['.NET SDK','Entity Framework Core','Visual Studio Build Tools','FastAPI','Spring Boot','Ubuntu','Amazon Corretto','Flutter'])assert.ok(common.some(p=>p.name===name),name);
 assert.equal(directoryIdentity('Drupal CMS').slug,'drupal');assert.equal(directoryIdentity('Durpal CMS').slug,'durpal-cms');assert.equal(directoryIdentity('.NET Framework').slug,'dotnetfx');
});
test('one bounded public record is reused across customers and dates remain unknown when absent',async()=>{
 const e=env();let calls=0;const fetcher=async url=>{calls++;assert.equal(url,'https://endoflife.date/api/drupal.json');return Response.json(raw);};
 const result=await lookupDirectory(e,'Drupal CMS',NOW,fetcher);assert.equal(result.status,'found');assert.equal(result.cycles[1].eol_date,null);
 await lookupDirectory(e,'drupal',NOW+1,fetcher);assert.equal(calls,1);
 const list=await cachedDirectory(e);assert.deepEqual(list.map(p=>p.slug),['drupal']);
 const state=JSON.stringify(result);assert.doesNotMatch(state,/example.test|installed_version|user_id/);
 assert.ok(new TextEncoder().encode(state).length<24000);
 assert.equal(e.DB.sql.prepare('SELECT COUNT(*) AS n FROM lifecycle_monitor_products').get().n,0,'lookup payloads use no D1 product rows');
 assert.throws(()=>directoryCycles([{cycle:'x'},{cycle:'x'}]));
 assert.equal(directoryCycles(Array.from({length:50},(_,i)=>({cycle:String(i),eol:false}))).length,40);
 e.DB.sql.close();
});
test('failed or busy searches never grow the shared directory and never fetch customer URLs',async()=>{
 const e=env();let calls=0;const fetcher=async url=>{calls++;assert.ok(url.startsWith('https://endoflife.date/api/'));return new Response('',{status:404});};
 const miss=await lookupDirectory(e,'Durpal CMS',NOW,fetcher);assert.equal(miss.status,'unavailable');
 assert.equal((await lookupDirectory(e,'another product',NOW+1,fetcher)).status,'retry');assert.equal(calls,1);
 assert.equal((await cachedDirectory(e)).length,0);assert.equal(e.DB.sql.prepare('SELECT COUNT(*) AS n FROM lifecycle_monitor_products').get().n,0);
 const saved=await api(e,'/watches','POST',{product:'Private application',installed_version:'secret-build'});assert.equal(saved.status,201);
 const result=await (await api(e)).json();assert.equal(result.watches[0].product,'Private application');assert.equal(result.watches[0].source_id,null);
 assert.equal((await cachedDirectory(e)).length,0);e.DB.sql.close();
});
test('confirmed branches share public state while customer versions remain private, with no email consent changes',async()=>{
 const e=env();await lookupDirectory(e,'Drupal',NOW,()=>Response.json(raw));
 for(const id of ['a','b'])await api(e,'/watches','POST',{product:'Private '+id,slug:'drupal',cycle:'10',installed_version:id+'-private'},id);
 assert.equal(e.DB.sql.prepare("SELECT COUNT(*) AS n FROM lifecycle_monitor_products WHERE source_id='lifecycle:drupal'").get().n,1);
 const publicState=e.DB.sql.prepare('SELECT record_json FROM lifecycle_monitor_state').all().map(r=>r.record_json).join('');assert.doesNotMatch(publicState,/Private|a-private|b-private/);
 const a=await (await api(e)).json();assert.equal(a.watches.length,1);assert.equal(a.watches[0].verified.reliability,'community_lifecycle');assert.equal(a.watches[0].verified.milestones.eol,'2026-12-09');
 assert.equal(e.DB.sql.prepare('SELECT COUNT(*) AS n FROM lifecycle_preferences').get().n,0);
 assert.equal(e.DB.sql.prepare('SELECT COUNT(*) AS n FROM lifecycle_monitor_notifications').get().n,0);e.DB.sql.close();
});
test('a saved unresolved watch can be resolved only by its owner to a source-returned branch',async()=>{
 const e=env();const {ids}=await (await api(e,'/watches','POST',{product:'Drupal CMS',cycle:'10'})).json();
 await lookupDirectory(e,'Drupal',NOW,()=>Response.json(raw));
 await assert.rejects(()=>api(e,'/watches/'+ids[0]+'/identity','PUT',{slug:'drupal',cycle:'10'},'b'),/Watch not found/);
 await assert.rejects(()=>api(e,'/watches/'+ids[0]+'/identity','PUT',{slug:'drupal',cycle:'999'}),/returned by the source/);
 await api(e,'/watches/'+ids[0]+'/identity','PUT',{slug:'drupal',cycle:'10'});
 const row=await (await api(e)).json();assert.equal(row.watches[0].product,'Drupal');assert.equal(row.watches[0].source_id,'lifecycle:drupal');e.DB.sql.close();
});
test('subscribed lifecycle sources refresh once for shared branches without claiming security patches',async()=>{
 const e=env();await lookupDirectory(e,'Drupal',NOW,()=>Response.json(raw));await api(e,'/watches','POST',{product:'Drupal',slug:'drupal',cycle:'10',installed_version:'10.6.7'});
 let calls=0;await checkSubscribedSources(e,async url=>{calls++;assert.equal(url,'https://endoflife.date/api/drupal.json');return Response.json([{...raw[0],latest:'10.6.9'}]);},NOW+86400001);
 assert.equal(calls,1);const state=await (await api(e)).json();assert.equal(state.watches[0].verified.version,'10.6.9');assert.equal(state.watches[0].verified.security,false);e.DB.sql.close();
});
test('public cache uses at most 500 fixed payload slots plus one bounded index',async()=>{
 const e=env();for(let i=0;i<550;i++)await lookupDirectory(e,'Product '+i,NOW+4000*i,()=>Response.json(raw));
 assert.ok(e.DIRECTORY_CACHE.entries.size<=DIRECTORY_LIMIT+1);assert.ok((await cachedDirectory(e)).length<=DIRECTORY_LIMIT);
 assert.equal(e.DB.sql.prepare('SELECT COUNT(*) AS n FROM lifecycle_monitor_products').get().n,0);e.DB.sql.close();
});
test('production legacy schema saves unresolved products and resolves them without newer monitoring tables',async()=>{
 const db=new DB();db.sql.exec(fs.readFileSync(new URL('../lifecycle-schema.sql',import.meta.url),'utf8'));const e={DB:db,DIRECTORY_CACHE:memoryCache()};
 const legacy=(path='',method='GET',data={},id='a')=>lifecycleHandler(new Request('https://api.cveharbor.com/v1/lifecycle'+path,{method}),e,{id},'/v1/lifecycle'+path,data);
 const saved=await (await legacy('/watches','POST',{product:'Drupal CMS',cycle:'10',installed_version:'10.6.1'})).json();
 assert.equal((await (await legacy()).json()).watches[0].directory,null);
 await lookupDirectory(e,'Drupal',NOW,()=>Response.json(raw));
 await assert.rejects(()=>legacy('/watches/'+saved.id+'/identity','PUT',{slug:'drupal',cycle:'10'},'b'),/Watch not found/);
 await legacy('/watches/'+saved.id+'/identity','PUT',{slug:'drupal',cycle:'10'});
 const watches=(await (await legacy()).json()).watches;assert.equal(watches[0].installed_version,'10.6.1');assert.equal(watches[0].directory.eol_date,'2026-12-09');
 assert.equal((await (await legacy('','GET',{},'b')).json()).watches.length,0);db.sql.close();
});
