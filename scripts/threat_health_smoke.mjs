import assert from 'node:assert/strict';
import fs from 'node:fs';
import {JSDOM} from 'jsdom';
const html=fs.readFileSync('index.html','utf8');
const timestamp='2026-10-31T12:00:00Z';
for(const failed of [false,true]){
 const dom=new JSDOM(html,{url:'https://cveharbor.com/threats/',runScripts:'outside-only'});
 const w=dom.window,timers=[];
 w.Date.now=()=>Date.parse(timestamp)+60000;
 w.setInterval=fn=>{timers.push(fn);return 1};
 w.CVEHARBOR_THREATS={checked_at:timestamp,last_changed_at:timestamp,added_count:0,removed_count:0,sources:{dshield_scanners:{ok:true,count:1,published_count:1,last_success:timestamp},feodo_c2:failed?{ok:false,retained_count:1,last_success:timestamp,error:'Upstream unavailable'}:{ok:true,count:1,published_count:1,last_success:timestamp}},indicators:[{ip:'8.8.8.8',source_id:'dshield_scanners',source:'DShield',activity:'Scanning'},{ip:'8.8.8.8',source_id:'feodo_c2',source:'Feodo',activity:'Botnet C2',stale:failed}]};
 w.eval(fs.readFileSync('threats.js','utf8'));
 const doc=w.document,status=doc.getElementById('threatStatus');
 assert.equal(status.dataset.health,failed?'degraded':'current');
 assert.match(status.textContent,/not a complete list/);
 assert.match(doc.getElementById('threatCount').textContent,/1 matching IPs · 2 of 2 source reports/);
 const select=doc.getElementById('threatSourceFilter');select.value='dshield_scanners';select.dispatchEvent(new w.Event('change'));
 assert.match(doc.getElementById('threatCount').textContent,/1 of 1 source reports/);
 w.Date.now=()=>Date.parse(timestamp)+4*60*60*1000;timers[0]();
 assert.equal(status.dataset.health,'stale');assert.match(status.textContent,/STALE SNAPSHOT/);
 dom.window.close();
}
console.log('PASS threat health: current, failed source, stale snapshot, unique counts and filter totals');
