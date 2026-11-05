import test from 'node:test';
import assert from 'node:assert/strict';
import application from '../../account-backend/src/index.js';
import {newSecret,encryptSecret,totp} from '../../account-backend/src/totp.js';
import {adminRoute} from '../admin.mjs';
import {createFrontend} from '../frontend.mjs';
import {FullDB} from './helpers/full-db.mjs';
import {TARGET} from '../target.mjs';
const email='reviewer@example.invalid',other='other@example.invalid',key='synthetic-key-with-at-least-thirty-two-characters';
const hash=async text=>Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))).toString('hex');
const reset=(data={confirm:'invalidate-pending-mfa'},headers={})=>new Request(TARGET.origin+'/__staging/mfa/pending/reset',{method:'POST',headers:{Origin:TARGET.origin,'Content-Type':'application/json','X-CVEHarbor-Staging-Admin':email,...headers},body:JSON.stringify(data)});
async function setup(enabled=0){
 const DB=new FullDB(),now=Math.floor(Date.now()/1000),secret=newSecret();
 for(const [id,address] of [['self',email],['other',other]]){
  DB.sql.prepare('INSERT INTO users(id,email) VALUES(?,?)').run(id,address);
  DB.sql.prepare('INSERT INTO user_totp(user_id,encrypted_secret,enabled,created_at) VALUES(?,?,?,?)').run(id,await encryptSecret({TOTP_ENCRYPTION_KEY:key},secret,id),id==='self'?enabled:0,now);
  DB.sql.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run(id+'session',id,id+'sessionhash',now+600,now);
  DB.sql.prepare('INSERT INTO totp_login_challenges(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run(id+'challenge',id,await hash(id==='self'?'a'.repeat(64):'b'.repeat(64)),now+300,now);
  DB.sql.prepare('INSERT INTO login_challenges(id,email,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run(id+'email',address,id+'emailhash',now+600,now);
  DB.sql.prepare('INSERT INTO totp_recovery_codes(user_id,code_hash) VALUES(?,?)').run(id,id+'recoveryhash');
 }
 return {DB,secret,env:{DB,STAGING_MODE:'true',STAGING_ADMIN_EMAILS:email}};
}
const snapshot=DB=>JSON.stringify(['user_totp','sessions','totp_login_challenges','login_challenges','totp_recovery_codes'].map(t=>DB.sql.prepare('SELECT * FROM '+t).all()));
test('self-only pending reset invalidates old proofs, requires fresh email proof and preserves other users',async()=>{
 const {DB,secret,env}=await setup();
 try{
  const response=await adminRoute(reset(),env,null,null),result=await response.json();
  assert.equal(response.status,200);assert.deepEqual(result,{pending_enrollment_invalidated:true,sign_in_required:true});
  assert.doesNotMatch(JSON.stringify(result),new RegExp(secret));assert.equal(response.headers.get('Cache-Control'),'private, no-store');
  assert.equal(DB.sql.prepare("SELECT * FROM user_totp WHERE user_id='self'").get(),undefined);
  assert.equal(DB.sql.prepare("SELECT COUNT(*) n FROM totp_login_challenges WHERE user_id='self'").get().n,0);
  assert.equal(DB.sql.prepare("SELECT COUNT(*) n FROM sessions WHERE user_id='self'").get().n,0);
  assert.ok(DB.sql.prepare("SELECT used_at FROM login_challenges WHERE email=?").get(email).used_at);
  assert.equal(DB.sql.prepare("SELECT COUNT(*) n FROM user_totp WHERE user_id='other'").get().n,1);
  assert.equal(DB.sql.prepare("SELECT COUNT(*) n FROM sessions WHERE user_id='other'").get().n,1);
  assert.equal(DB.sql.prepare('SELECT COUNT(*) n FROM totp_recovery_codes').get().n,2);
  const authEnv={DB,TOTP_ENCRYPTION_KEY:key,RECOVERY_CONTROL_REQUIRED:'false'};
  const call=(path,data)=>application.fetch(new Request('https://api.cveharbor.com/v1'+path,{method:'POST',headers:{Origin:'https://cveharbor.com','Content-Type':'application/json'},body:JSON.stringify(data)}),authEnv,{});
  // A previously disclosed secret plus its old challenge can no longer enroll.
  assert.equal((await call('/auth/totp/enroll',{mfa_challenge:'a'.repeat(64),code:await totp(secret)})).status,401);
  const salt='c'.repeat(64),now=Math.floor(Date.now()/1000);
  DB.sql.prepare('INSERT INTO login_challenges(id,email,token_hash,expires_at,created_at) VALUES(?,?,?,?,?)').run('fresh-email',email,await hash(salt+':123456'),now+600,now);
  const fresh=await (await call('/auth/verify',{challenge_id:'fresh-email',salt,code:'123456'})).json();
  assert.equal(fresh.mfa_enrollment_required,true);assert.notEqual(fresh.secret,secret);
  assert.equal((await call('/auth/totp/enroll',{mfa_challenge:'a'.repeat(64),code:await totp(secret)})).status,401);
  // Recovery/session protections still come only from verified MFA enrollment.
  const enrolled=await call('/auth/totp/enroll',{mfa_challenge:fresh.mfa_challenge,code:await totp(fresh.secret)});
  assert.equal(enrolled.status,200);const done=await enrolled.json();assert.equal(done.authenticated,true);assert.equal(done.recovery_codes.length,8);
  assert.equal((await call('/auth/totp/enroll',{mfa_challenge:fresh.mfa_challenge,code:await totp(fresh.secret)})).status,401);
  assert.equal((await adminRoute(reset(),env,null,null)).status,409);
 }finally{DB.close();}
});
test('active factors, missing confirmation, other-account targeting and cross-origin requests cannot reset',async()=>{
 for(const enabled of [0,1]){
  const {DB,env}=await setup(enabled);try{
   const before=snapshot(DB);
   for(const req of [reset({}),reset({confirm:'invalidate-pending-mfa',email:other}),reset(undefined,{Origin:'https://evil.invalid'}),reset(undefined,{'X-CVEHarbor-Staging-Admin':other}),reset(undefined,{'Content-Type':'text/plain'})])assert.ok((await adminRoute(req,env,null,null)).status>=400);
   if(enabled)assert.equal((await adminRoute(reset(),env,null,null)).status,409);
   assert.equal(snapshot(DB),before);
  }finally{DB.close();}
 }
});
test('batch rollback and concurrent completion leave the factor and proofs intact',async()=>{
 for(const mode of ['rollback','completed']){
  const {DB,env}=await setup();try{
   const original=DB.batch.bind(DB),before=snapshot(DB);
   DB.batch=async statements=>{if(mode==='completed')DB.sql.exec("UPDATE user_totp SET enabled=1 WHERE user_id='self'");return original(mode==='rollback'?[...statements,DB.prepare('SELECT missing_column')]:statements);};
   const result=await adminRoute(reset(),env,null,null);assert.equal(result.status,mode==='rollback'?503:409);
   if(mode==='rollback')assert.equal(snapshot(DB),before);
   else{assert.equal(DB.sql.prepare("SELECT enabled FROM user_totp WHERE user_id='self'").get().enabled,1);assert.equal(DB.sql.prepare("SELECT COUNT(*) n FROM sessions WHERE user_id='self'").get().n,1);assert.equal(DB.sql.prepare("SELECT COUNT(*) n FROM totp_login_challenges WHERE user_id='self'").get().n,1);}
  }finally{DB.close();}
 }
});
test('frontend blocks spoofed administrator headers and allows only verified allowlisted human identity',async()=>{
 const {DB,env}=await setup();try{
  let calls=0;const binding={STAGING_ADMIN_EMAILS:email,STAGING_API:{fetch:async req=>{calls++;return adminRoute(req,env,null,null);}}};
  assert.equal((await createFrontend(async()=>true).fetch(reset(),binding)).status,403);assert.equal(calls,0);
  const verified=async(_token,_issuer,_aud,_reject,identity)=>{identity({email});return true;};
  assert.equal((await createFrontend(verified).fetch(reset(),binding)).status,200);assert.equal(calls,1);
 }finally{DB.close();}
});
