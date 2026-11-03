import test from 'node:test';import assert from 'node:assert/strict';
import {runCloud} from '../scripts/cloud.mjs';
test('legacy provisioning cannot create, delete or deploy resources',async()=>{
 for(const action of ['create-database','deploy','deploy-workers','deploy-frontend','delete'])await assert.rejects(runCloud(action,{},()=>assert.fail('No network permitted')),/retired/);
});
