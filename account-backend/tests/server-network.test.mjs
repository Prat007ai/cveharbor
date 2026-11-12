import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import worker from '../src/index.js';
import {unifiedFixture} from './helpers/unified-db.mjs';
import {normalizeSnapshot} from '../src/server-network.js';
const snapshot=()=>({version:1,collected_at:'2026-01-01T00:00:00Z',adapters:[{id:'ethernet',name:'Production LAN',status:'Up',addresses:[{ip:'192.0.2.10',prefix:24,state:'Preferred'},{ip:'2001:db8::10',prefix:64,state:'Preferred'}]},{id:'backup',name:'Backup LAN',status:'Up',addresses:[{ip:'198.51.100.20',prefix:24,state:'Preferred'}]}],suggested:{adapter_id:'ethernet',ip:'192.0.2.10'}});
test('reject malformed, oversized, duplicate addresses and invalid suggested primary',()=>{
 for(const mutate of [s=>s.adapters[0].addresses[0].ip='999.1.1.1',s=>s.adapters[0].addresses[0].prefix=33,s=>s.adapters.push(s.adapters[0]),s=>s.suggested.ip='203.0.113.99',s=>s.adapters[0].addresses.push(s.adapters[0].addresses[0]),s=>s.collected_at='invalid']){const s=snapshot();mutate(s);assert.throws(()=>normalizeSnapshot(s));}
 assert.equal(normalizeSnapshot(snapshot()).adapters[0].addresses[1].family,'IPv6');
});
test('network imports, shared primary, scope and stale updates; AI stays unused',async t=>{
 const f=await unifiedFixture(),db=f.DB.sql;t.mock.method(globalThis,'fetch',f.fetcher);
 for(const path of ['../migrations/0029_finding_assignment_links.sql','../../deployment/proposals/customer-remediation/schema.sql','../migrations/0032_recovery_control.sql','../../deployment/proposals/organization-team-access/schema.sql','../../deployment/proposals/server-network/schema.sql'])db.exec(fs.readFileSync(new URL(path,import.meta.url),'utf8'));
 f.env.TEAM_ACCESS_ENABLED='true';
 async function call(user,path,method='GET',body,status=200){const r=await worker.fetch(f.request(path,method,body,user),f.env);const d=await r.json();assert.equal(r.status,status,JSON.stringify(d));return d;}
 const org=(await call('a','/team/organizations','POST',{name:'Fictional Northstar'},201)).id,base='/team/organizations/'+org;
 const customer=(await call('a',base+'/customers','POST',{name:'Fictional customer'},201)).id;
 const env=(await call('a',base+'/environments/'+customer,'POST',{name:'Test',kind:'QA'},201)).id;
 const other=(await call('a',base+'/environments/'+customer,'POST',{name:'Other',kind:'QA'},201)).id;
 for(const environment_id of [env,other])await call('a',base+'/assets/'+customer,'POST',{environment_id,name:'DEMO-WEB01',asset_type:'Server',technology:'.NET Runtime',version:'8.0.1'},201);
 const route=base+'/server-network/'+customer,payload={environment_id:env,name:'DEMO-WEB01',snapshot:snapshot()};
 let saved=await call('a',route,'POST',payload);assert.equal(saved.primary_ip,'');
 await call('a',base+'/members','POST',{email:'other@example.test',role:'Viewer',scope:'selected',customers:[customer]},201);
 const token=f.emails.at(-1).text_body.match(/#team-invite=([a-f0-9]{64})/)[1];await call('b','/team/accept','POST',{token,revision:1});
 assert.equal((await call('b',route)).networks.length,1);
 const choice={environment_id:env,name:'DEMO-WEB01',adapter_id:'backup',ip:'198.51.100.20',revision:saved.revision};
 await call('b',route,'PUT',choice,403);
 const member=(await call('a',base+'/members')).members.find(m=>m.email==='other@example.test');
 await call('a',base+'/members/'+member.id,'PUT',{role:'Editor',scope:'selected',customers:[customer],revision:member.revision});
 saved=await call('b',route,'PUT',choice);assert.equal(saved.primary_ip,choice.ip);
 await call('a',route,'PUT',choice,409);
 saved=await call('a',route,'POST',payload);assert.equal(saved.primary_ip,choice.ip,'reimport preserves customer choice');
 const changed=snapshot();changed.collected_at='2026-01-02T00:00:00Z';changed.adapters[1].addresses=[];
 saved=await call('a',route,'POST',{...payload,snapshot:changed});assert.equal(saved.primary_ip,choice.ip,'missing primary is retained visibly for review');
 await call('a',route,'PUT',{...choice,revision:saved.revision},400);
 await call('a',route,'POST',payload,409);
 await call('a',route,'POST',{...payload,environment_id:other});assert.equal((await call('b',route)).networks.length,2,'same name in different environment remains distinct');
 assert.equal((await call('b','/inventory/server-network')).networks.length,0,'organization data does not leak into personal storage');
 await call('b','/inventory/server-network','PUT',{...choice,revision:saved.revision},404);
 await call('a',base+'/members/'+member.id,'DELETE',{revision:member.revision+1});await call('b',route,'GET',undefined,404);
 db.prepare('UPDATE operations_control SET write_hold=1,database_frozen=1 WHERE id=1').run();
 assert.throws(()=>db.prepare('DELETE FROM inventory_server_network').run(),/recovery write hold/);
});
