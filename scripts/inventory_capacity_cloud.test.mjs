import test from 'node:test';
import assert from 'node:assert/strict';
import {validateCloudRun} from './inventory_capacity_cloud.mjs';
const valid={GITHUB_REPOSITORY:'Prat007ai/cveharbor',GITHUB_REF:'refs/heads/main',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',GITHUB_WORKFLOW_REF:'Prat007ai/cveharbor/.github/workflows/inventory-capacity-cloud.yml@refs/heads/main',GITHUB_RUN_ID:'12345678901',GITHUB_SHA:'a'.repeat(40),CAPACITY_REVIEWED_COMMIT:'a'.repeat(40),CLOUDFLARE_ACCOUNT_ID:'9706b4d98ad72884e67fd1eb875c8a61',CLOUDFLARE_API_TOKEN:'fictional-only'};
test('cloud rehearsal requires exact main, manual first attempt, reviewed commit, staging account and caller',()=>{
 assert.equal(validateCloudRun(valid),'cveharbor-capacity-12345678901');
 for(const [key,value] of [['GITHUB_REPOSITORY','other/repo'],['GITHUB_REF','refs/heads/feature'],['GITHUB_EVENT_NAME','push'],['GITHUB_RUN_ATTEMPT','2'],['GITHUB_WORKFLOW_REF','Prat007ai/cveharbor/.github/workflows/other.yml@refs/heads/main'],['GITHUB_RUN_ID','../../escape'],['CAPACITY_REVIEWED_COMMIT','b'.repeat(40)],['CLOUDFLARE_ACCOUNT_ID','aa99b9b15e0492302e4f6484b8d27bc2'],['CLOUDFLARE_API_TOKEN','']])assert.throws(()=>validateCloudRun({...valid,[key]:value}));
});
