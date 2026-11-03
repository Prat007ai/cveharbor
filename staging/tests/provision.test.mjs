import test from 'node:test';import assert from 'node:assert/strict';
import {authorize,provision} from '../scripts/provision.mjs';
test('old approval variables and marked commits cannot reactivate initial provisioning',async()=>{
 assert.throws(()=>authorize({CF_STAGING_PROVISION_ACTION:'deploy-workers'},{}),/retired/);
 await assert.rejects(provision({},{}),/retired/);
});
