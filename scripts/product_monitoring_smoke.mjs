// Browser contract tests use synthetic data only; no vendor or email requests.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
const dom=new JSDOM(fs.readFileSync('index.html','utf8'),{url:'https://cveharbor.com/lifecycle/',runScripts:'outside-only'}),w=dom.window,d=w.document;
let owner='a',provisioned=true,operating=false,testAllowed=false,saves=0,prefs={email_enabled:0,lead_days:90,alert_types:['security'],delivery_mode:'daily'};
const rows={a:[],b:[]},history={a:[],b:[]};
w.confirm=()=>true;w.prompt=()=>null;
w.CVEHARBOR_LIFECYCLE={checked_at:new Date().toISOString(),available_products:['dotnet','wordpress'],cycles:[{slug:'dotnet',product:'.NET',cycle:'8.0',latest:'8.0.11',eol_date:'2027-11-01',url:'https://endoflife.date/dotnet'}],errors:[]};
w.CVEHARBOR_LIFECYCLE.cycles.push({slug:'sharepoint',product:'SharePoint Server',cycle:'subscription',eol_date:null},{slug:'sharepoint',product:'SharePoint Server',cycle:'2019',eol_date:'2026-07-14'});
w.fetch=async(url,options={})=>{
 const path=new URL(url).pathname,method=options.method||'GET',body=options.body?JSON.parse(options.body):{};
 if(path.endsWith('/status'))return Response.json(path.includes('/monitoring')?{ready:provisioned,scheduler:{enabled:operating,operating},recipient:owner+'@example.test',admin:false,test_allowed:testAllowed}:{ready:true});
 if(path.endsWith('/directory'))return Response.json({products:[]});
 if(path.endsWith('/directory/lookup'))return Response.json({status:'unavailable',message:'Source temporarily unavailable'});
 if(path.endsWith('/history'))return Response.json({history:history[owner]});
 if(path.endsWith('/preferences')&&method==='PUT'){prefs={...prefs,...body};saves++;return Response.json({saved:true});}
 if(path.endsWith('/watches')&&method==='POST'){rows[owner].push({...body,id:crypto.randomUUID(),monitoring_status:'enabled',monitoring_label:operating?'Monitoring Active':'Monitoring Not Yet Active',notice_days:[90]});saves++;return Response.json({saved:true});}
 if(path.match(/\/watches\/[\w-]+$/)&&method==='PUT'){const row=rows[owner].find(r=>path.endsWith(r.id));Object.assign(row,body,{monitoring_status:body.status||row.monitoring_status});return Response.json({saved:true});}
 if(path==='/v1/monitoring'||path==='/v1/lifecycle')return Response.json({watches:rows[owner],preferences:prefs,email_delivery_active:false,scheduler:{operating,enabled:operating},recipient:owner+'@example.test'});
 throw Error('Unexpected browser request: '+path);
};
const until=async fn=>{const end=Date.now()+3000;while(!fn()){if(Date.now()>end)throw Error('UI did not settle');await new Promise(r=>setTimeout(r,5));}};
const auth=(email,authenticated=true)=>w.dispatchEvent(new w.CustomEvent('cveharbor:account-state',{detail:{email,authenticated}}));
try{
 w.eval(fs.readFileSync('lifecycle-monitor.js','utf8'));w.eval(fs.readFileSync('product-monitoring.js','utf8'));
 const sharepoint=[...d.querySelectorAll('.lifecycle-source-row')].find(r=>r.textContent.includes('SharePoint'));assert.match(sharepoint.textContent,/Support date not published/);assert.doesNotMatch(sharepoint.textContent,/2026-07-14/,'unknown latest-cycle support never borrows an older cycle date');
 assert.match(d.getElementById('productMonitorActivation').textContent,/Not Yet Active/);assert.equal(d.getElementById('lifecycleWatchSave').disabled,true);
 auth('a@example.test');await until(()=>!d.getElementById('lifecycleWatchSave').disabled);
 d.getElementById('lifecycleProduct').value='dotnet';d.getElementById('lifecycleProduct').dispatchEvent(new w.Event('change'));d.getElementById('lifecycleCycle').value='8.0';d.getElementById('lifecycleInstalled').value='8.0.9';
 await until(()=>!d.getElementById('lifecycleLookupProduct').disabled);
 d.getElementById('lifecycleWatchForm').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await until(()=>saves===1&&d.getElementById('lifecycleWatches').textContent.includes('8.0.9'));
 assert.match(d.getElementById('lifecycleWatches').textContent,/Monitoring Not Yet Active/);
 await w.CVEHARBOR_LIFECYCLE_MONITOR.refresh();assert.match(d.getElementById('lifecycleWatches').textContent,/8.0.9/,'watch persists after reload');
 d.querySelector('[data-monitor-tab="settings"]').click();d.getElementById('lifecycleEmailOptin').checked=true;d.getElementById('lifecycleLead').value='14';
 d.getElementById('lifecyclePreferencesForm').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await until(()=>saves===2);assert.equal(prefs.lead_days,14);assert.deepEqual(prefs.alert_types,['security']);
 d.querySelector('[data-monitor-tab="history"]').click();await until(()=>d.getElementById('productMonitorHistory').textContent.includes('No notifications'));
 assert.equal(d.getElementById('productMonitorTest').disabled,true,'unapproved test configuration cannot send');
 owner='b';auth('b@example.test');await until(()=>d.getElementById('lifecycleWatchCount').textContent==='0 monitored');assert.doesNotMatch(d.getElementById('lifecycleWatches').textContent,/8.0.9/);
 auth('',false);assert.equal(d.getElementById('lifecycleWatchSave').disabled,true);assert.equal(d.getElementById('productMonitorHistory').textContent,'');
 provisioned=false;owner='a';auth('a@example.test');await until(()=>d.getElementById('lifecycleUserStatus').textContent.includes('loaded'));
 assert.match(d.getElementById('productMonitorActivation').textContent,/checks and email are not enabled/,'legacy saved preferences do not claim active monitoring');
 assert.ok(d.getElementById('lifecyclePublished').textContent.includes('.NET'),'reference directory remains available');
 assert.ok(fs.readFileSync('lifecycle-monitor.css','utf8').includes('body[data-page="lifecycle"]'),'styles are scoped to the lifecycle workspace');
 console.log('PASS product monitoring UI: watch persistence, account isolation, saved alert options, truthful activation, history, test gating and reference directory.');
}finally{dom.window.close();}
