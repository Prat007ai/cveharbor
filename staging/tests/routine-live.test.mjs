import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {verifyLiveApplication} from '../scripts/routine-live.mjs';
import {TARGET} from '../target.mjs';

test('health, exact assets and controls are distinct live outcomes without a user session',async t=>{
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'staging-assets-'));
 t.after(()=>fs.rmSync(dir,{recursive:true,force:true}));
 fs.mkdirSync(path.join(dir,'public'));
 for(const f of ['app.js','styles.css'])fs.writeFileSync(path.join(dir,'public',f),f);
 const controls=['technologySelectAll','technologyUnselectAll','technologySaveButton','technologyCustomizeStatus'].map(id=>'id="'+id+'"').join(' ');
 for(const broken of [null,'/v1/health','/styles.css','/vulnerabilities/']){
   const checked=[];
   const transport=async(url,opts)=>{
     assert.equal(new URL(url).origin,TARGET.origin);assert.equal(opts.redirect,'error');assert.ok(!opts.method||opts.method==='GET');
     const p=new URL(url).pathname;
     return new Response(p===broken?'{}':p==='/v1/health'?JSON.stringify({ready:true,accounts:'configured'}):p.endsWith('/')?controls:p.slice(1));
   };
   const result=verifyLiveApplication({},transport,x=>checked.push(x),dir);
   if(broken){await assert.rejects(result);assert.ok(!checked.includes('application_assets_verified'));}
   else {await result;assert.equal(checked.at(-1),'application_assets_verified');}
 }
});
