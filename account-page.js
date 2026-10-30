(() => {
'use strict';
const root=document.getElementById('accountPageRequest');if(!root)return;
const $=id=>document.getElementById(id);
const API='https://api.cveharbor.com/v1';
let challenge='',salt='',mfaChallenge='';
const message=text=>{$('accountPageMessage').textContent=text;};
function renderQr(id,uri){
 const target=$(id);target.replaceChildren();
 if(!uri||!uri.startsWith('otpauth://totp/'))return;
 if(typeof QRCode!=='function'){message('QR code unavailable. Use the setup key below.');return;}
 new QRCode(target,{text:uri,width:196,height:196,colorDark:'#071624',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.M});
}
async function request(path,method='GET',payload){
 const response=await fetch(API+path,{method,credentials:'include',
  headers:{'Content-Type':'application/json'},
  body:payload===undefined?undefined:JSON.stringify(payload)});
 const result=await response.json().catch(()=>({}));
 if(!response.ok)throw Error(result.error||'Account service unavailable');
 return result;
}
function signedIn(email){
 $('accountPageSignedOut').hidden=true;
 $('accountPageSignedIn').hidden=false;
 $('accountPageIdentity').textContent='Signed in as '+email;
 $('accountPageHeading').innerHTML='Welcome to your <span>CVEHarbor workspace</span>';
 message('Your account is connected.');
 loadTotpStatus();
}
function signedOut(){
 mfaChallenge='';$('accountPageRequiredEnroll').hidden=true;$('accountPageTotpVerify').hidden=true;$('accountPageTotpCode').value='';
 $('accountPageSignedOut').hidden=false;
 $('accountPageSignedIn').hidden=true;
 $('accountPageHeading').innerHTML='Access your private <span>CVEHarbor workspace</span>';
}
const mode=new URLSearchParams(location.search).get('mode');
if(mode==='register')$('accountFormTitle').textContent='Create your free CVEHarbor account';
else if(mode==='login')$('accountFormTitle').textContent='Log in to CVEHarbor';
root.addEventListener('submit',async event=>{
 event.preventDefault();const button=$('accountPageSend');button.disabled=true;
 try{
  const data=await request('/auth/request','POST',{email:$('accountPageEmail').value.trim()});
  challenge=data.challenge_id;salt=data.salt;
  $('accountPageVerify').hidden=false;root.hidden=true;
  message('Check your email for the six digit code. It expires after ten minutes.');
  $('accountPageCode').focus();
 }catch(error){message(error.message)}
 finally{button.disabled=false}
});
$('accountPageVerify').addEventListener('submit',async event=>{
 event.preventDefault();const button=$('accountPageConfirm');button.disabled=true;
 try{
  const data=await request('/auth/verify','POST',{challenge_id:challenge,salt,code:$('accountPageCode').value});
  if(data.mfa_enrollment_required){
   mfaChallenge=data.mfa_challenge;
   $('accountPageSignedOut').hidden=true;
   $('accountPageRequiredSecret').textContent=data.secret;
   renderQr('accountPageRequiredQr',data.otpauth_url);
   $('accountPageRequiredEnroll').hidden=false;
   message('Authenticator setup is required before accessing your workspace.');
   return;
  }
  if(data.mfa_required){mfaChallenge=data.mfa_challenge;$('accountPageSignedOut').hidden=true;$('accountPageTotpVerify').hidden=false;message('Enter your authenticator code or a saved recovery code.');$('accountPageTotpCode').focus();return;}
  if(!data.authenticated)throw Error('Could not confirm your account.');
  signedIn(data.email||$('accountPageEmail').value.trim());
 }catch(error){message(error.message)}
 finally{button.disabled=false}
});
$('accountPageBack').addEventListener('click',()=>{
 challenge='';salt='';$('accountPageVerify').hidden=true;root.hidden=false;
 $('accountPageCode').value='';message('Enter an email address to request a new code.');
});
$('accountPageLogout').addEventListener('click',async()=>{
 try{
  await request('/auth/logout','POST');signedOut();
  $('accountPageVerify').hidden=true;root.hidden=false;
  message('Signed out successfully.');
 }catch(error){message(error.message)}
});

$('accountPageRequiredEnrollForm').addEventListener('submit',async event=>{
 event.preventDefault();const button=event.currentTarget.querySelector('button[type=submit]');button.disabled=true;
 try{
  const result=await request('/auth/totp/enroll','POST',{mfa_challenge:mfaChallenge,code:$('accountPageRequiredCode').value.trim()});
  if(!result.authenticated)throw Error('Could not enable authenticator.');
  mfaChallenge='';
  $('accountPageRequiredEnrollForm').hidden=true;
  $('accountPageRequiredSecret').textContent='';
  $('accountPageRequiredRecoveryCodes').textContent=result.recovery_codes.join('\n');
  $('accountPageRequiredRecovery').hidden=false;
  message('Authenticator enabled. Save your recovery codes before continuing.');
  window.cveharborEnrolledEmail=result.email;
 }catch(error){message(error.message)}finally{button.disabled=false}
});
$('accountPageRequiredContinue').addEventListener('click',()=>{
 $('accountPageRequiredRecoveryCodes').textContent='';
 $('accountPageRequiredEnroll').hidden=true;
 signedIn(window.cveharborEnrolledEmail||$('accountPageEmail').value.trim());
});
async function loadTotpStatus(){
 try{
  const status=await request('/auth/totp/status');
  $('accountPageTotpStatus').textContent=!status.available?'Authenticator enrollment is not configured yet.':status.enabled?'Authenticator app enabled. Your account requires an authenticator at the next login.':'Protect this account with an authenticator app.';
  $('accountPageTotpSetup').hidden=!status.available||status.enabled;
 }catch(e){$('accountPageTotpStatus').textContent='MFA settings unavailable.'}
}
$('accountPageTotpVerify').addEventListener('submit',async event=>{
 event.preventDefault();const button=event.currentTarget.querySelector('button[type=submit]');button.disabled=true;
 try{const result=await request('/auth/totp/verify','POST',{mfa_challenge:mfaChallenge,code:$('accountPageTotpCode').value.trim()});
  if(!result.authenticated)throw Error('Authenticator verification failed.');
  $('accountPageTotpVerify').hidden=true;mfaChallenge='';signedIn(result.email||$('accountPageEmail').value.trim());
 }catch(e){message(e.message)}finally{button.disabled=false}
});
$('accountPageTotpBack').addEventListener('click',()=>{signedOut();$('accountPageVerify').hidden=true;root.hidden=false;message('Request another email verification code.');});
$('accountPageTotpSetup').addEventListener('click',async()=>{
 try{const result=await request('/auth/totp/setup','POST');$('accountPageTotpSecret').textContent=result.secret;
  renderQr('accountPageTotpQr',result.otpauth_url);
  $('accountPageTotpEnroll').hidden=false;$('accountPageTotpSetup').hidden=true;message('Add the key to your authenticator app, then verify the code.');
 }catch(e){message(e.message)}
});
$('accountPageTotpEnrollForm').addEventListener('submit',async event=>{
 event.preventDefault();const button=event.currentTarget.querySelector('button[type=submit]');button.disabled=true;
 try{const result=await request('/auth/totp/enable','POST',{code:$('accountPageTotpEnrollCode').value.trim()});
  $('accountPageTotpEnroll').hidden=true;$('accountPageTotpSecret').textContent='';
  $('accountPageTotpRecoveryCodes').textContent=result.recovery_codes.join('\n');
  $('accountPageTotpRecovery').hidden=false;
  $('accountPageTotpStatus').textContent='Authenticator app enabled.';
  message('MFA is enabled. Save your recovery codes securely.');
 }catch(e){message(e.message)}finally{button.disabled=false}
});
$('accountPageTotpRecoveryDone').addEventListener('click',()=>{$('accountPageTotpRecoveryCodes').textContent='';$('accountPageTotpRecovery').hidden=true;message('Recovery codes hidden. Sign in will now require your authenticator.');});
request('/me').then(data=>{
 if(data.authenticated)signedIn(data.email||'');
 else signedOut();
}).catch(error=>{
 signedOut();
 if(!/Sign in required/.test(error.message))message('Account service unavailable. You can still browse the public website.');
});
})();