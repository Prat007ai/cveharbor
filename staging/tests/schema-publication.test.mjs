import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { root } from '../scripts/configure.mjs';

test('concurrent local plan builders never expose partial JSON or change approved SQL digests', async () => {
  const cwd=path.resolve(root,'..'),out=path.join(root,'.build/schema');
  const first=spawnSync('python',['staging/scripts/migration-plan.py'],{cwd,encoding:'utf8'});
  assert.equal(first.status,0,first.stderr);
  const digest=JSON.parse(fs.readFileSync(path.join(root,'bootstrap-approval.v1.json'))).execution_plan_sha256;
  const children=[];let active=2,observations=0;
  const builds=Array.from({length:2},()=>new Promise((resolve,reject)=>{
    const child=spawn('python',['staging/scripts/migration-plan.py'],{cwd,stdio:['ignore','pipe','pipe'],timeout:120000});children.push(child);
    let error='';child.stderr.on('data',b=>{error+=b;});child.stdout.resume();
    child.on('error',reject);child.on('close',code=>{active--;code===0?resolve():reject(Error(error||'Plan builder failed'));});
  }));
  // Observe each replacement during real concurrent builds, without modifying
  // the approved plan or relaxing parse/checksum assertions.
  const observe=(async()=>{
    while(active){
      for(const file of ['manifest.json','validated-plan.json','execution-plan.json']){
        const bytes=fs.readFileSync(path.join(out,file));JSON.parse(bytes);
        if(file==='execution-plan.json')assert.equal(createHash('sha256').update(bytes).digest('hex'),digest);
      }
      observations++;await new Promise(resolve=>setTimeout(resolve,50));
    }
  })();
  try{await Promise.all([...builds,observe]);assert.ok(observations>0);}
  finally{for(const child of children)if(child.exitCode===null)child.kill();}
});
