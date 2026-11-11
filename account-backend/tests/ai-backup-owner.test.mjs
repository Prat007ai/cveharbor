import test from 'node:test';
import assert from 'node:assert/strict';
import {owner,adminRoute} from '../src/ai-admin.js';
import {fixture,user} from './helpers/ai-db.mjs';

test('both release-controlled owners can administer; organization owners and delegates cannot',async()=>{
 const f=fixture();f.env.CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL='other@example.test';
 const post=new Request('https://api.example.test/v1/ai/admin/organizations',{method:'POST'});
 for(const id of ['admin','other']){
  assert.equal(owner(f.env,user(id)),true);
  await adminRoute(post,f.env,user(id),'/organizations',{org:'north',enabled:false});
 }
 f.store.exec("INSERT INTO ai_admins(user_id,granted_by) VALUES('staff','admin')");
 for(const id of ['owner','staff'])await assert.rejects(adminRoute(post,f.env,user(id),'/organizations',{org:'north',enabled:false}),/administrator access/);
 assert.equal(f.store.prepare("SELECT count(*) n FROM ai_audit WHERE action='pause organization AI'").get().n,2);
 for(const email of ['admin@example.test','other@example.test'])await assert.rejects(adminRoute(post,f.env,user('other'),'/access',{action:'revoke',email}),/platform owner cannot be changed/);
 f.store.close();
});
test('missing, malformed and near-match backup identities never grant ownership',()=>{
 const f=fixture();
 for(const binding of [undefined,'',true,['other@example.test'],'other@example.test.evil']){
  f.env.CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL=binding;
  assert.equal(owner(f.env,user('other')),false);
 }
 f.env.CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL='OTHER@example.test';
 assert.equal(owner(f.env,user('other')),true);
 assert.equal(owner(f.env,{email:''}),false);
 f.store.close();
});
