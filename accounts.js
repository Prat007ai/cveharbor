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
 if(!isAuth){
  if(stackTimer)clearTimeout(stackTimer);
  stackTimer=null;savedCloudStack=null;linkedWatchlist=false;
 }
 showWatchlistStatus();
 window.dispatchEvent(new CustomEvent('cveharbor:account-state',{detail:{authenticated:isAuth,email:address}}));
}

let savedCloudStack=null,linkedWatchlist=false,stackSaving=null,stackTimer=null;
const selectedHere=()=>window.CVEHARBOR_WATCHLIST?.getSelected?.()||[];
const sameList=(a,b)=>Array.isArray(a)&&Array.isArray(b)&&
  a.length===b.length&&[...a].sort().every((item,i)=>item===[...b].sort()[i]);
function showWatchlistStatus(){
 const headline=$('stackSyncHeadline'),message=$('stackSyncStatus');
 const save=$('accountSaveStack'),load=$('accountLoadStack');
 if(!headline||!message||!save||!load)return;
 const current=selectedHere();
 save.disabled=!authenticated||!Array.isArray(savedCloudStack);
 load.hidden=!authenticated||!Array.isArray(savedCloudStack)||sameList(current,savedCloudStack);
 if(!authenticated){
  headline.textContent='Selected in this browser';
  message.textContent=current.length+' selected technologies. Sign in on the right to save them for your email reports.';
  return;
 }
 if(!Array.isArray(savedCloudStack)){
  headline.textContent='Checking account watchlist';
  message.textContent='Checking the technologies saved for your email reports.';
  return;
 }
 const same=sameList(current,savedCloudStack);
 if(linkedWatchlist){
  headline.textContent=same&&(!stackSaving&&!stackTimer)?'Email watchlist is up to date':'Saving watchlist changes';
  message.textContent=same&&!stackSaving&&!stackTimer?
    savedCloudStack.length+' technologies saved to your account for personalized email reports. Future checkbox changes sync automatically.':
    'Your technology changes are being saved. Email reports will use the updated selections after synchronization.';
  save.textContent='Save selections now';
 }else{
  headline.textContent='Connect your browser selections';
  message.textContent=current.length+' selected in this browser, '+savedCloudStack.length+
    ' saved in your email watchlist. Choose which list to use before enabling automatic synchronization.';
  save.textContent='Use these selections for email reports';
 }
}
async function readCloudStack(){
 const result=await call('/stack');
 savedCloudStack=(result.stack||[]).map(row=>row.technology).filter(x=>typeof x==='string');
 linkedWatchlist=sameList(selectedHere(),savedCloudStack);
 showWatchlistStatus();
}
function planStackSave(){
 if(stackTimer)clearTimeout(stackTimer);
 if(!authenticated||!linkedWatchlist)return;
 if(sameList(selectedHere(),savedCloudStack)){showWatchlistStatus();return;}
 stackTimer=setTimeout(()=>{
  stackTimer=null;
  saveCloudStack().catch(error=>note('Automatic watchlist sync failed. Save the selections again: '+error.message));
 },450);
 showWatchlistStatus();
}
async function saveCloudStack(){
 if(!authenticated)throw Error('Please sign in first');
 if(stackSaving){
  await stackSaving;
  if(sameList(selectedHere(),savedCloudStack))return;
 }
 if(!sameList(selectedHere(),savedCloudStack)){
  const list=selectedHere();
  stackSaving=call('/stack','PUT',{stack:list.map(technology=>({technology,product_version:''}))});
  showWatchlistStatus();
  try{
   await stackSaving;
   savedCloudStack=list;
   linkedWatchlist=true;
  }catch(error){
   linkedWatchlist=false;
   throw error;
  }finally{
   stackSaving=null;
   showWatchlistStatus();
  }
 }
 if(linkedWatchlist&&!sameList(selectedHere(),savedCloudStack))planStackSave();
}
async function flushWatchlist(){
 if(stackTimer){clearTimeout(stackTimer);stackTimer=null;}
 if(!linkedWatchlist||!Array.isArray(savedCloudStack)){
  throw Error('Save your selected technologies for email reports first.');
 }
 for(let i=0;i<5&&(!sameList(selectedHere(),savedCloudStack)||stackSaving);i++)await saveCloudStack();
 if(!sameList(selectedHere(),savedCloudStack))throw Error('Your watchlist has unsaved changes. Try again.');
 showWatchlistStatus();
}
window.addEventListener('cveharbor:stack-changed',()=>{
 if(authenticated&&linkedWatchlist)planStackSave();
 else showWatchlistStatus();
});
$('accountSaveStack').addEventListener('click',async()=>{
 if(!authenticated||!Array.isArray(savedCloudStack))return;
 const local=selectedHere();
 if(!linkedWatchlist&&!sameList(local,savedCloudStack)&&savedCloudStack.length &&
    !window.confirm('Replace '+savedCloudStack.length+' saved email watchlist technologies with '+local.length+' selections from this browser?'))return;
 const button=$('accountSaveStack');button.disabled=true;
 try{await saveCloudStack();linkedWatchlist=true;showWatchlistStatus();note('These technologies are now saved for your email reports. Changes you make here will sync automatically.')}
 catch(e){note('Could not save your email watchlist: '+e.message)}
 finally{showWatchlistStatus()}
});
$('accountLoadStack').addEventListener('click',async()=>{
 if(!authenticated)return;
 const button=$('accountLoadStack');button.disabled=true;
 try{
  const result=await call('/stack');
  const incoming=(result.stack||[]).map(x=>x.technology);
  if(selectedHere().length&&!sameList(selectedHere(),incoming)&&
     !window.confirm('Replace this browser\'s technology selections with '+incoming.length+' technologies saved to your account?'))return;
  window.CVEHARBOR_WATCHLIST?.loadFromCloud?.(incoming);
  savedCloudStack=incoming;
  linkedWatchlist=true;
  note('Saved cloud watchlist loaded. Your email report technology selections match this browser.');
 }catch(e){note('Unable to load your account watchlist: '+e.message)}
 finally{showWatchlistStatus()}
});
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
   try{await readCloudStack()}catch(_){note('Signed in, but the email watchlist could not be loaded. Refresh to retry.')}
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
  if(result.authenticated){state(true,result.email);service('Account service available');note('Signed in. Your existing local selections are not overwritten until you choose a sync action.');try{await loadPrefs()}catch(_){note('Signed in, but saved alert preferences could not be loaded.')}try{await readCloudStack()}catch(_){note('Signed in, but the watchlist could not be loaded. Refresh to retry.')}}
 }catch(e){note(e.message)}finally{button.disabled=false}
});
$('accountLogout').addEventListener('click',async()=>{try{await call('/auth/logout','POST');state(false);note('Signed out. Locally saved data remains on this browser.')}catch(e){note(e.message)}});
$('accountUpload').addEventListener('click',async()=>{
 if(!authenticated)return;
 try{
  const selected=JSON.parse(localStorage.getItem('cveharbor.stack.v1')||'[]');
  if(!Array.isArray(selected))throw Error('Invalid locally saved watchlist');
  if(!confirm('Replace the '+(savedCloudStack?.length||0)+' technologies saved in your email watchlist with '+selected.length+' selections from this browser? Remediation records are managed separately in the Cloudflare tracker.'))return;
  if(selected.length===0&&!confirm('This browser has no selected technologies. Uploading will clear the cloud watchlist. Are you sure?'))return;
  await call('/stack','PUT',{stack:selected.slice(0,100).map(technology=>({technology,product_version:''}))});
  savedCloudStack=selected.slice(0,100);linkedWatchlist=true;showWatchlistStatus();
  note('Browser technology selections uploaded to your email watchlist. Use the Remediation Tracker to import older browser records.');
 }catch(e){note('Upload not completed: '+e.message)}
});
$('accountDownload').addEventListener('click',async()=>{
 if(!authenticated)return;
 if(!confirm('Replace this browser’s technology selections with your email watchlist saved in the cloud? Remediation records will remain in Cloudflare D1.'))return;
 try{
  const stack=await call('/stack');
  const technologies=stack.stack.map(x=>x.technology);
  localStorage.setItem('cveharbor.stack.v1',JSON.stringify(technologies));
  window.CVEHARBOR_WATCHLIST?.loadFromCloud?.(technologies);
  savedCloudStack=technologies;linkedWatchlist=true;showWatchlistStatus();
  note('Saved cloud watchlist loaded. Remediation records are available in the authenticated Cloudflare D1 tracker.');
 }catch(e){note('Download failed: '+e.message)}
});
$('accountAlerts').addEventListener('submit',async ev=>{
 ev.preventDefault();if(!authenticated)return;
 try{
  if($('alertEnabled').checked){
   if(!selectedHere().length)throw Error('Choose at least one technology before subscribing.');
   await flushWatchlist();
  }
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
  if(!selectedHere().length)throw Error('Choose a technology and save it to your email watchlist before testing.');
  await flushWatchlist();
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