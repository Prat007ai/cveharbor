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
 assert.match(doc.getElementById('threatCount').textContent,/1 matching IPs · 0 network ranges · 2 of 2 source reports/);
 const select=doc.getElementById('threatSourceFilter');select.value='dshield_scanners';select.dispatchEvent(new w.Event('change'));
 assert.match(doc.getElementById('threatCount').textContent,/1 of 1 source reports/);
 w.Date.now=()=>Date.parse(timestamp)+4*60*60*1000;timers[0]();
 assert.equal(status.dataset.health,'stale');assert.match(status.textContent,/STALE SNAPSHOT/);
 dom.window.close();
}
console.log('PASS threat health: current, failed source, stale snapshot, unique counts and filter totals');

// Synthetic fixtures exercise the four-source presentation, not live intelligence.
{
 const dom=new JSDOM(html,{url:'https://cveharbor.com/threats/',runScripts:'outside-only'});
 const w=dom.window;w.Date.now=()=>Date.parse(timestamp);w.setInterval=()=>1;
 const sources=Object.fromEntries(['dshield_scanners','feodo_c2','threatfox','spamhaus_drop'].map(id=>[id,{ok:true,last_success:timestamp}]));
 const indicators=Array.from({length:151},(_,i)=>({ip:`8.8.0.${i+1}`,source_id:'dshield_scanners',source:'DShield',activity:'Scanning'}));
 indicators.push({ip:'9.9.9.9',source_id:'threatfox',source:'ThreatFox',activity:'Malware-associated IP',observed_at:timestamp,last_seen:timestamp,evidence:[{ioc_id:'fixture-1',malware:'<img src=x onerror=alert(1)>',port:443,threat_type:'Botnet C2',source_confidence:90,first_seen:timestamp,last_seen:timestamp}]});
 indicators.push({ip:'8.8.0.0/24',network:'8.8.0.0/24',kind:'network',source_id:'spamhaus_drop',source:'Spamhaus DROP',activity:'Reported malicious network range',sbl_id:'fixture-SBL',geo:{country:'Test',latitude:1,longitude:1}});
 w.CVEHARBOR_THREATS={checked_at:timestamp,sources,indicators};w.eval(fs.readFileSync('threats.js','utf8'));
 const d=w.document,select=d.getElementById('threatSourceFilter');
 assert.equal(select.options.length,5);
 assert.match(d.getElementById('threatCount').textContent,/152 matching IPs · 1 network ranges · 150 of 153/);
 [...d.querySelectorAll('#threatRows button')].find(b=>b.textContent==='Show more reports').click();
 assert.equal(d.querySelectorAll('.threat-entry').length,153);
 select.value='spamhaus_drop';select.dispatchEvent(new w.Event('change'));
 assert.match(d.getElementById('threatCount').textContent,/0 matching IPs · 1 network ranges · 1 of 1/);
 d.querySelector('#threatRows button').click();assert.match(d.getElementById('threatDetailContent').textContent,/Network range \(CIDR\)/);
 assert.match(d.getElementById('threatDetailContent').textContent,/fixture-SBL/);
 select.value='threatfox';select.dispatchEvent(new w.Event('change'));d.querySelector('#threatRows button').click();
 assert.match(d.getElementById('threatDetailContent').textContent,/Port 443 · Provider confidence: 90/);
 assert.equal(d.querySelectorAll('#threatDetailContent img').length,0,'source fields remain text');
 w.eval(fs.readFileSync('geo-map.js','utf8'));
 assert.match(d.getElementById('geoMapSummary').textContent,/0 geolocated IPs/,'ranges never plotted as a host');
 dom.window.close();
}
console.log('PASS expanded feeds: pagination, source filters, CIDR totals, evidence, escaped text and map exclusions');
