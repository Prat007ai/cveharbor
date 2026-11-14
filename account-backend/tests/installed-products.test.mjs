import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {DB} from './helpers/d1.mjs';
import {knownIdentity,productCpe} from '../src/product-identity.js';
import {subscribeProducts,repairAccountCoverage,runCvieStep,inventoryProductProgress} from '../src/cvie.js';
import {bindProductIdentities} from '../src/cvie-onboarding.js';
import {assessedSnapshot} from '../src/agent-validation.js';
const family=(v,p)=>`cpe:2.3:a:${v}:${p}:*:*:*:*:*:*:*:*`;
function env(){const DBi=new DB();for(const n of ['0028_cvie_source_efficiency.sql','0029_cvie_identity_registry.sql'])DBi.sql.exec(fs.readFileSync(new URL('../migrations/'+n,import.meta.url),'utf8'));return {DB:DBi,CVIE_REGISTRY_ENABLED:'true',CVIE_SHARED_SCANS_ENABLED:'true'};}
test('Windows installer aliases resolve exact families without matching sibling products or arbitrary descriptions',()=>{
 for(const [name,v,p] of [['Google Chrome','google','chrome'],['Mozilla Firefox (x64 en-CA)','mozilla','firefox'],['FileZilla 3.71.1','filezilla-project','filezilla_client'],['FortiClient','fortinet','forticlient'],['ESET Endpoint Security','eset','endpoint_security'],['KeePass Password Safe 2.61.1','keepass','keepass'],['Microsoft Edge','microsoft','edge_chromium'],['Microsoft OneDrive','microsoft','onedrive'],['Notepad++ (64-bit x64)','notepad-plus-plus','notepad\\+\\+'],['AdGuard','adguard','adguard'],['Python 3.12.10 Core Interpreter (64-bit)','python','python']]){
  assert.equal(knownIdentity(name)?.cpe,family(v,p),name);assert.equal(productCpe(knownIdentity(name).cpe),family(v,p));assert.equal(knownIdentity(name,'Unrelated Vendor'),null);
 }
 for(const n of ['FileZilla Server','Google Chrome Helper','KeePassXC','Microsoft Edge WebView2 Runtime','Mozilla Maintenance Service','ESET Management Agent','Adobe Acrobat (64-bit)','Microsoft 365 Apps for enterprise - en-us','Photos','Copilot','Lenovo Vantage Service','Microsoft Windows Application Compatibility Fix Database'])assert.equal(knownIdentity(n),null,n);
 for(const c of ['cpe:2.3:a:notepad-plus-plus:notepad++:*:*:*:*:*:*:*:*','cpe:2.3:a:vendor:x\\:*:*:*:*:*:*:*:*:*',family('vendor','product?')])assert.equal(productCpe(c),null);
});
test('existing unresolved mappings repair once, preserving explicit identities and account isolation',async()=>{
 const e=env();try{
  await subscribeProducts(e,'a',[{name:'Google Chrome'},{name:'Microsoft Edge'}],'inventory');
  e.DB.sql.exec("UPDATE cvie_products SET cpe='',status='needs_identity',cursor_json='{}' WHERE name='Google Chrome'");
  e.DB.sql.prepare("UPDATE cvie_products SET cpe=?,status='ready' WHERE name='Microsoft Edge'").run(family('microsoft','edge'));
  assert.equal(await repairAccountCoverage(e,'a','inventory'),true);
  const rows=e.DB.sql.prepare('SELECT * FROM cvie_products ORDER BY name').all();
  assert.equal(rows[0].cpe,family('google','chrome'));assert.equal(rows[1].cpe,family('microsoft','edge'));
  assert.equal((await inventoryProductProgress(e,'b',['Google Chrome'])).products.length,0);
  assert.deepEqual((await inventoryProductProgress(e,'a',['Google Chrome'])).products.map(p=>p.name),['Google Chrome']);
  assert.equal(await repairAccountCoverage(e,'a','inventory'),false);
 }finally{e.DB.sql.close();}
});
test('unknown inventory gets one budgeted directory lookup; ambiguity is never guessed or restarted by binding',async()=>{
 const e=env();try{
  await subscribeProducts(e,'a',[{name:'Fictional Agent Tool'}],'inventory');
  let p=e.DB.sql.prepare('SELECT * FROM cvie_products').get();assert.equal(p.status,'queued');
  await runCvieStep(e,()=>Response.json({startIndex:0,totalResults:2,products:['one','two'].map(v=>({cpe:{cpeName:family(v,'fictional_agent_tool')}}))}),Date.now(),'a','inventory');
  p=e.DB.sql.prepare('SELECT * FROM cvie_products').get();assert.equal(p.status,'needs_identity');assert.equal(p.cpe,'');
  await bindProductIdentities(e,'a');assert.equal(e.DB.sql.prepare('SELECT status FROM cvie_products').get().status,'needs_identity');
 }finally{e.DB.sql.close();}
});
test('a provider outage keeps automatic discovery retryable and never produces a clean result',async()=>{
 const e=env();try{await subscribeProducts(e,'a',[{name:'Fictional Agent Tool'}],'inventory');
  await runCvieStep(e,()=>new Response('Unavailable',{status:503}),Date.now(),'a','inventory');
  const p=e.DB.sql.prepare('SELECT * FROM cvie_products').get();assert.equal(p.status,'retrying');assert.ok(p.next_attempt_at>Date.now());
  await bindProductIdentities(e,'a');assert.equal(e.DB.sql.prepare('SELECT status FROM cvie_products').get().status,'retrying');
 }finally{e.DB.sql.close();}
});
test('.NET compatibility suppression requires same-collection release evidence and preserves genuine side-by-side versions',()=>{
 const legacy={name:'.NET Framework',version:'4.0.0.0',details:'Framework registry version; verify patch applicability.'};
 const modern={name:'.NET Framework',version:'4.8.1',details:'Registry release: 534296; framework family, not Windows patch level.'};
 const old={...legacy,version:'3.5'},runtime={name:'.NET Runtime',version:'8.0.1',details:''};
 const raw={products:[legacy,modern,old,runtime]};assert.deepEqual(assessedSnapshot(raw).products,[modern,old,runtime]);assert.equal(raw.products.length,4);
 for(const p of [null,{...modern,details:''},{...modern,version:'4.7'},{...modern,name:'Third-party .NET Framework'}]){
  const products=[legacy,...(p?[p]:[])];assert.deepEqual(assessedSnapshot({products}).products,products);
 }
});
