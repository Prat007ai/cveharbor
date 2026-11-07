import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {TARGET} from '../target.mjs';
import {output,hash} from './customer-candidate-artifact.mjs';

// No application session and no user-supplied URLs or commands. Never log response bodies.
export async function verifyLiveApplication(env,transport,step,dir=output){
  const headers={'CF-Access-Client-Id':env.CF_STAGING_ACCESS_CLIENT_ID,'CF-Access-Client-Secret':env.CF_STAGING_ACCESS_CLIENT_SECRET};
  const get=route=>transport(TARGET.origin+route,{headers,redirect:'error',signal:AbortSignal.timeout(20000)});
  step('live_health_check');
  const health=await get('/v1/health');
  assert.equal(health.status,200);
  const body=await health.json();
  assert.equal(body.accounts,'configured');assert.equal(body.ready,true);
  step('live_health_ok',{status:health.status});
  for(const filename of ['app.js','styles.css']){
    step(filename==='app.js'?'live_javascript':'live_styles');
    const r=await get('/'+filename);assert.equal(r.status,200);
    assert.equal(hash(Buffer.from(await r.arrayBuffer())),hash(fs.readFileSync(path.join(dir,'public',filename))));
  }
  step('live_catalogue_controls');
  const page=await get('/vulnerabilities/');assert.equal(page.status,200);
  const html=await page.text();
  for(const id of ['technologySelectAll','technologyUnselectAll','technologySaveButton','technologyCustomizeStatus'])
    assert.ok(html.includes('id="'+id+'"'));
  step('application_assets_verified');
}
