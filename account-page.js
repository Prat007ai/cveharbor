(() => {
'use strict';
const root=document.getElementById('accountPageRequest');if(!root)return;
const $=id=>document.getElementById(id);
const API='https://api.cveharbor.com/v1';
let challenge='',salt='';
const message=text=>{$('accountPageMessage').textContent=text;};
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
 $('accountPageHeading').textContent='Welcome to CVEHarbor';
 message('Your account is connected.');
}
function signedOut(){
 $('accountPageSignedOut').hidden=false;
 $('accountPageSignedIn').hidden=true;
 $('accountPageHeading').textContent='Log in or create an account';
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
request('/me').then(data=>{
 if(data.authenticated)signedIn(data.email||'');
 else signedOut();
}).catch(error=>{
 signedOut();
 if(!/Sign in required/.test(error.message))message('Account service unavailable. You can still browse the public website.');
});
})();