(()=>{'use strict';
const $=id=>document.getElementById(id);
const API='https://api.cveharbor.com/v1';
const status=text=>$('accountSecurityStatus').textContent=text;
async function request(path,method='GET',payload){
 const r=await fetch(API+path,{method,credentials:'include',cache:'no-store',headers:{'Content-Type':'application/json'},body:payload===undefined?undefined:JSON.stringify(payload)});
 const data=await r.json().catch(()=>({}));
 if(!r.ok)throw Error(data.error||'Account service unavailable');
 return data;
}
function renderCodes(codes){
 const list=$('accountSecurityRecoveryList');list.replaceChildren();
 for(const code of codes){
  if(!/^[a-f0-9]{16}$/.test(code))throw Error('Invalid code format returned');
  const li=document.createElement('li'),value=document.createElement('code'),copy=document.createElement('button');
  value.textContent=code;copy.type='button';copy.className='account-recovery-copy';copy.textContent='Copy code';
  copy.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(code);copy.textContent='Copied'}catch{status('Select and copy only the code text.')}});
  li.append(value,copy);list.append(li);
 }
}
$('accountSecurityRecoveryStart').addEventListener('click',()=>{$('accountSecurityRecoveryForm').hidden=false;$('accountSecurityRecoveryCode').focus()});
$('accountSecurityRecoveryForm').addEventListener('submit',async event=>{
 event.preventDefault();const btn=event.currentTarget.querySelector('[type=submit]');btn.disabled=true;
 try{
  const response=await request('/auth/totp/recovery/rotate','POST',{code:$('accountSecurityRecoveryCode').value.trim()});
  renderCodes(response.recovery_codes);
  $('accountSecurityRecoveryForm').hidden=true;$('accountSecurityRecoveryCode').value='';
  $('accountSecurityRecoveryResult').hidden=false;status('New recovery codes generated. All previous codes are invalid.');
 }catch(e){status(e.message)}finally{btn.disabled=false}
});
$('accountSecurityRecoveryDone').addEventListener('click',()=>{$('accountSecurityRecoveryList').replaceChildren();$('accountSecurityRecoveryResult').hidden=true;status('Recovery codes hidden. Keep your saved copy secure.')});
$('accountSecuritySignOut').addEventListener('click',async()=>{
 try{await request('/auth/logout','POST');location.replace('/workspace/')}catch(e){status(e.message)}
});
(async()=>{
 try{
  const me=await request('/me');
  if(!me.authenticated)throw Error('Sign in required');
  $('accountSecurityEmail').textContent=me.email||'';
  $('accountSecurityDashboard').hidden=false;
  try{
   const mfa=await request('/auth/totp/status');
   if(!mfa.enabled){status('Authenticator status needs verification. Your session remains signed in.');return}
   $('accountSecurityMfaStatus').textContent='Enabled';
   $('accountSecurityMfaBadge').textContent='Enabled';
   status('');
  }catch(error){
   $('accountSecurityMfaStatus').textContent='Temporarily unavailable';
   $('accountSecurityMfaBadge').textContent='Check status';
   status('Your account is signed in, but authenticator settings could not be refreshed. Try reloading this page.');
  }
 }catch(error){
  if(/Sign in required|Unauthorized|MFA not enabled/.test(error.message)){location.replace('/workspace/');return}
  status('Could not verify your session. Please retry this page. Your account settings were not changed.');
 }
})();
})();