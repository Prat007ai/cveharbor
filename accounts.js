(() => {
'use strict';
const $=id=>document.getElementById(id), API='https://api.cveharbor.com/v1';
if(!$('accountWorkspace'))return;
let authenticated=false,email='';
const note=(msg)=>{$('accountMessage').textContent=msg};
const service=(msg)=>{const node=$('accountServiceStatus');if(node)node.textContent=msg};
async function call(path,method='GET',payload){
 const res=await fetch(API+path,{method,credentials:'include',headers:{'Content-Type':'application/json'},body:payload===undefined?undefined:JSON.stringify(payload)});
 let body={};try{body=await res.json()}catch(_){}
 if(!res.ok){const error=Error(body.error||'Account API not available');error.status=res.status;throw error}
 return body;
}
function state(isAuth,address=''){
 authenticated=isAuth;email=address;
 $('accountSignedOut').hidden=isAuth;$('accountSignedIn').hidden=!isAuth;
 $('accountIdentity').textContent=isAuth?'Signed in: '+address:'';
}
async function loadPrefs(){
 const data=await call('/alerts'),prefs=data.preferences||{};
 $('alertEnabled').checked=!!data.consented&&(prefs.enabled===1||prefs.enabled===true);
 $('alertSeverity').value=prefs.severity==='high'?'high':'critical';
 $('alertFrequency').value=prefs.frequency==='hourly'?'hourly':'daily';
 const node=$('alertDeliveryStatus');
 if(node){
  node.textContent=data.migration_required?'Alert database upgrade is pending. Email delivery is not enabled.':
   !data.consented?'Email reports are not subscribed. Check the box and save to explicitly subscribe.':
   data.delivery_active?'Email reports are enabled. You will receive matching advisories when they are available.':
   'Your subscription is saved. Scheduled email delivery is awaiting activation.';
 }
}
async function check(){
 try{
  const data=await call('/me');
  state(!!data.authenticated,data.email||'');
  service('Account service available');
  if(data.authenticated){
   note('Your account is connected. You can sync your local data when ready.');
   try{await loadPrefs()}catch(_){note('Signed in, but saved alert preferences could not be loaded.')}
  }else note('Sign in to synchronize data.');
 }catch(error){
  state(false);
  if(error.status===401){service('Account service available');note('Sign in to synchronize data.')}
  else{service('Account service unavailable');note('Account service currently unavailable. Existing local tracking continues to work.')}
 }
}
$('accountRequest').addEventListener('submit',async ev=>{
 ev.preventDefault();const button=$('accountSendCode');button.disabled=true;
 try{
  const data=await call('/auth/request','POST',{email:$('accountEmail').value.trim()});
  $('accountChallenge').value=data.challenge_id;$('accountSalt').value=data.salt;
  $('accountVerify').hidden=false;note('A one-time sign in code has been emailed. It expires after 10 minutes.');
 }catch(e){note(e.message)}
 finally{button.disabled=false}
});
$('accountVerify').addEventListener('submit',async ev=>{
 ev.preventDefault();const button=$('accountVerifyButton');button.disabled=true;
 try{
  const result=await call('/auth/verify','POST',{challenge_id:$('accountChallenge').value,salt:$('accountSalt').value,code:$('accountCode').value});
  if(result.authenticated){state(true,result.email);service('Account service available');note('Signed in. Your existing local selections are not overwritten until you choose a sync action.');try{await loadPrefs()}catch(_){note('Signed in, but saved alert preferences could not be loaded.')}}
 }catch(e){note(e.message)}finally{button.disabled=false}
});
$('accountLogout').addEventListener('click',async()=>{try{await call('/auth/logout','POST');state(false);note('Signed out. Locally saved data remains on this browser.')}catch(e){note(e.message)}});
$('accountUpload').addEventListener('click',async()=>{
 if(!authenticated)return;
 try{
  const selected=JSON.parse(localStorage.getItem('cveharbor.stack.v1')||'[]');
  const remediation=JSON.parse(localStorage.getItem('cveharbor.remediation.v1')||'[]');
  if(!Array.isArray(selected)||!Array.isArray(remediation))throw Error('Invalid locally saved data');
  if(!confirm('Upload '+selected.length+' saved technologies and '+remediation.length+' remediation records from THIS browser? This replaces the records currently saved in your CVEHarbor account.'))return;
  if(selected.length===0&&remediation.length===0&&!confirm('This browser has no saved records. Uploading will CLEAR any cloud technology selections and remediation records. Are you sure?'))return;
  await call('/stack','PUT',{stack:selected.slice(0,100).map(technology=>({technology,product_version:''}))});
  await call('/remediations','PUT',{remediations:remediation.slice(0,250)});
  note('Local technology selections and remediation records uploaded to your account.');
 }catch(e){note('Upload not completed: '+e.message)}
});
$('accountDownload').addEventListener('click',async()=>{
 if(!authenticated)return;
 if(!confirm('Replace this browser’s technology selections and remediation records with your saved account data? Export local records first if needed.'))return;
 try{
  const [stack,remediation]=await Promise.all([call('/stack'),call('/remediations')]);
  localStorage.setItem('cveharbor.stack.v1',JSON.stringify(stack.stack.map(x=>x.technology)));
  localStorage.setItem('cveharbor.remediation.v1',JSON.stringify(remediation.remediations));
  note('Account data downloaded. Refresh this page to display the updated records.');
 }catch(e){note('Download failed: '+e.message)}
});
$('accountAlerts').addEventListener('submit',async ev=>{
 ev.preventDefault();if(!authenticated)return;
 try{
  const data=await call('/alerts','PUT',{enabled:$('alertEnabled').checked,severity:$('alertSeverity').value,frequency:$('alertFrequency').value});
  note(data.message||'Preferences saved.');
  await loadPrefs();
 }catch(e){note(e.message)}
});
$('accountSendTest').addEventListener('click',async()=>{
 if(!authenticated)return;
 const button=$('accountSendTest');button.disabled=true;
 note('Preparing a sample email using your saved cloud technology stack...');
 try{
  const data=await call('/alerts/test','POST');
  note(data.message||'Sample email accepted by SMTP2GO.');
 }catch(error){note('Sample email not sent: '+error.message)}
 finally{button.disabled=false}
});
$('accountDelete').addEventListener('click',async()=>{
 if(!authenticated||!confirm('Permanently delete your CVEHarbor account, saved stack, remediation records and alert preferences? This cannot be undone.'))return;
 try{await call('/account','DELETE');state(false);note('Your account was deleted. Browser-local data is unchanged.')}catch(e){note(e.message)}
});
check();
})();