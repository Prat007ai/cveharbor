import assert from 'node:assert/strict';
import {test} from 'node:test';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
import view from '../server-security.js';
const environments=[{id:'prod',customer_id:'c1',name:'Production'},{id:'qa',customer_id:'c1',name:'QA'},{id:'other',customer_id:'c2',name:'Production'}];
const customers=[{id:'c1',name:'Northstar'},{id:'c2',name:'Fictional Other'}];
const assets=[
 {id:'a',name:'WEB01',environment_id:'prod',asset_type:'Server',technology:'.NET Runtime',version:'8.0.1',notes:'Server role: Web; Fictional'},
 {id:'b',name:'web01',environment_id:'prod',asset_type:'Server',technology:'.NET Runtime',version:'8.0.2',notes:'Server role: Web; Fictional'},
 {id:'c',name:'WEB01',environment_id:'qa',asset_type:'Application'},
 {id:'d',name:'WEB01',environment_id:'other',asset_type:'Server'},
 {id:'e',name:'DB01',environment_id:'prod',asset_type:'Database'}];
test('customer/environment/host grouping preserves side-by-side versions and their findings',()=>{
 const groups=view.group({assets,environments,customers,issues:[{asset_id:'a',id:'CVE-2099-11111'},{asset_id:'b',id:'CVE-2099-11111'},{asset_id:'not-accessible',id:'CVE-2099-22222'}]});
 assert.equal(groups.length,4);const server=groups.find(g=>g.assets.length===2);
 assert.equal(server.role,'Web');assert.equal(server.roleConflict,false);assert.deepEqual(server.assets.map(a=>a.version),['8.0.1','8.0.2']);assert.equal(server.issues.length,2);
 assert.equal(groups.filter(g=>g.issues.length).length,1);assert.equal(view.role(assets[3]),'Not recorded');assert.equal(view.role(assets[4]),'Database');
});
test('roles are explicit, with inconsistent entries flagged and multi-role entries supported',()=>{
 assert.equal(view.role({name:'DC01',technology:'Active Directory',asset_type:'Server'}),'Not recorded');
 assert.equal(view.role({notes:'Publisher: Server role: Database;'}),'Not recorded');
 assert.equal(view.role({notes:'Server role: Web / Application;'}),'Web / Application');
 assert.equal(view.group({assets:[assets[0],{...assets[1],notes:'Server role: Database;'}],environments})[0].roleConflict,true);
});
test('host filters, role filters, safe rendering and bounded pagination',()=>{
 const dom=new JSDOM('<main></main>',{runScripts:'outside-only'}),w=dom.window;
 w.eval(fs.readFileSync('server-security.js','utf8'));const host=w.document.querySelector('main');
 const inventory=Array.from({length:26},(_,i)=>({...assets[0],id:'a'+i,name:'WEB'+i}));inventory[0].name='<img src=x onerror=alert(1)>';
 w.CVEHARBOR_SERVER_SECURITY.render(host,{assets:inventory,environments,customers});
 assert.equal(host.querySelectorAll('article').length,12);assert.equal(host.querySelectorAll('img').length,0);
 host.querySelector('.server-pages button:last-child').click();assert.equal(host.querySelectorAll('article').length,12);
 const search=host.querySelector('input');search.value='WEB25';search.dispatchEvent(new w.Event('input'));assert.equal(host.querySelectorAll('article').length,1);assert.match(host.textContent,/No matches in the loaded assessment/);
 search.value='missing';search.dispatchEvent(new w.Event('input'));assert.equal(host.querySelectorAll('article').length,0);
 dom.window.close();
});
