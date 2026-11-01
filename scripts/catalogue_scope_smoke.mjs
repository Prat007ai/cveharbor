// Real frontend + real account/CVIE routes on in-memory SQLite, no network.
import fs from 'node:fs';
import assert from 'node:assert/strict';
import {JSDOM} from 'jsdom';
import {DB} from '../account-backend/tests/helpers/d1.mjs';
import worker from '../account-backend/src/index.js';
import {catalogueRevision} from '../account-backend/src/catalogue-selection.js';
const env={DB:new DB(),CVIE_SHARED_SCANS_ENABLED:'true'},token='a'.repeat(64);
env.DB.sql.prepare('INSERT INTO sessions VALUES(?,?,?,?)').run('s','a',await catalogueRevision(token),Date.now()/1000+3600);
env.DB.sql.exec("INSERT INTO user_totp VALUES('a',1); INSERT INTO inventory_assets VALUES('a','WordPress'); INSERT INTO user_stack VALUES('a','Exchange SE'); UPDATE cvie_provider_budget SET next_request_at=9999999999999;");
const data=JSON.parse(fs.readFileSync('data/demo-advisories.json','utf8'));
let signedIn=true,failSave=false,holdSave=null,delaySave=false;
const pending=[],seen=[];
async function fetcher(url,options={}){
 const u=new URL(url);seen.push({path:u.pathname,scope:u.searchParams.get('scope'),method:options.method||'GET'});
 if(u.pathname==='/v1/me')return Response.json({authenticated:signedIn,email:signedIn?'a@example.test':undefined},{status:signedIn?200:401});
 if(!u.pathname.startsWith('/v1/cvie')&&u.pathname!=='/v1/technology-catalogue')return Response.json({});
 if(failSave&&options.method==='PUT')return Response.json({error:'Synthetic save failure'},{status:503});
 const execute=()=>worker.fetch(new Request(url,{...options,headers:{...options.headers,Origin:'https://cveharbor.com',...(signedIn?{Cookie:'cvh_session='+token}:{})}}),env,{waitUntil:p=>pending.push(p)});
 if(delaySave&&options.method==='PUT'){delaySave=false;return new Promise(resolve=>{holdSave=async()=>resolve(await execute())})}
 return execute();
}
async function until(fn){for(let i=0;i<120;i++){if(fn())return;await new Promise(r=>setTimeout(r,15))}throw Error('Frontend did not settle')}
async function page(){
 const dom=new JSDOM(fs.readFileSync('index.html','utf8'),{url:'https://cveharbor.com/vulnerabilities/',runScripts:'outside-only',pretendToBeVisual:true});
 const w=dom.window;w.fetch=fetcher;w.AbortSignal=globalThis.AbortSignal;w.CVEHARBOR_DATA=data;w.Element.prototype.scrollIntoView=function(){};
 for(const script of ['advisory-details.js','cvie.js','app.js'])w.eval(fs.readFileSync(script,'utf8'));
 await until(()=>w.document.querySelector('.cvie-scope-summary')&&!w.CVEHARBOR_CVIE.loading);return dom;
}
let dom=await page(),w=dom.window,d=w.document;
const selectedNames=()=>[...d.querySelectorAll('.technology-row .technology-name')].map(el=>el.textContent);
const setDefaults=names=>{d.getElementById('technologyManageButton').click();for(const input of d.querySelectorAll('#technologyDefaultChoices input')){input.checked=names.includes(input.parentElement.textContent);input.dispatchEvent(new w.Event('change'))}};
const save=async()=>{d.getElementById('technologySaveButton').click();await until(()=>!d.getElementById('technologySaveButton').disabled);await until(()=>!w.CVEHARBOR_CVIE.loading);await Promise.all(pending.splice(0))};
setDefaults(['Windows Server OS','.NET Core']);await save();
assert.equal(d.querySelectorAll('.technology-row').length,2);assert.equal(d.getElementById('technologyTotal').textContent,'2');
assert.deepEqual([...w.CVEHARBOR_CVIE.products].map(p=>p.name).sort(),['.NET Core','Windows Server OS']);
assert.doesNotMatch(d.getElementById('categoryGrid').textContent,/WordPress|Exchange|NGINX/);
assert.match(d.querySelector('.cvie-scan-details summary').textContent,/Catalogue product scan status \(2\)/);
// Failure retains saved display, while an in-flight draft cannot alter the saved request.
setDefaults(['PHP']);failSave=true;await save();assert.match(d.getElementById('technologyCustomizeStatus').textContent,/Unable to save/);assert.equal(d.querySelectorAll('.technology-row').length,2);failSave=false;
setDefaults(['.NET Core']);delaySave=true;d.getElementById('technologySaveButton').click();await until(()=>holdSave);assert.ok([...d.querySelectorAll('#technologyDefaultChoices input')].every(i=>i.disabled));await holdSave();await until(()=>!d.getElementById('technologySaveButton').disabled&&!w.CVEHARBOR_CVIE.loading);assert.equal(w.CVEHARBOR_CVIE.products.length,1);
// Reload and sign back in load the authoritative saved scope.
dom.window.close();dom=await page();w=dom.window;d=w.document;assert.equal(d.querySelectorAll('.technology-row').length,1);
signedIn=false;w.dispatchEvent(new w.CustomEvent('cveharbor:account-state',{detail:{authenticated:false}}));assert.equal(d.getElementById('technologyCustomizer').hidden,true);
signedIn=true;w.dispatchEvent(new w.CustomEvent('cveharbor:account-state',{detail:{authenticated:true,email:'a@example.test'}}));await until(()=>d.querySelectorAll('.technology-row').length===1&&!w.CVEHARBOR_CVIE.loading);
setDefaults(['.NET Core','WordPress / Plugins']);await save();assert.equal(d.querySelectorAll('.technology-row').length,2);
setDefaults([]);await save();assert.equal(d.querySelectorAll('.technology-row').length,0);assert.equal(w.CVEHARBOR_CVIE.products.length,0);assert.match(d.getElementById('technologyEmpty').textContent,/No technologies selected/);
assert.ok(seen.filter(x=>x.path.startsWith('/v1/cvie')).every(x=>x.scope==='catalogue'));
assert.equal(env.DB.sql.prepare('SELECT count(*) n FROM inventory_assets').get().n,1);assert.equal(env.DB.sql.prepare('SELECT count(*) n FROM user_stack').get().n,1);
dom.window.close();env.DB.sql.close();console.log('PASS catalogue UI + actual backend: exact selection, failure, pending saves, refresh, sessions, adding and empty scope');
