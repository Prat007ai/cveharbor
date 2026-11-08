(() => {
'use strict';
// Only coalesce in-flight GETs in this document. A later visit rechecks the server.
const pending = new Map();
async function read(path) {
 const delays = [350, 900, 1800];
 for (let attempt = 0; ; attempt++) {
  let response;
  try {
   response = await fetch('https://api.cveharbor.com/v1' + path, {
    credentials: 'include', cache: 'no-store', headers: {Accept: 'application/json'},
    signal: globalThis.AbortSignal?.timeout?.(6000)
   });
  } catch (error) {
   if (attempt === delays.length) throw error;
  }
  if (response?.ok) return response.json();
  if (response && (![500, 502, 503, 504].includes(response.status) || attempt === delays.length)) {
   const error = new Error('Account service returned ' + response.status);
   error.status = response.status;
   throw error;
  }
  await new Promise(resolve => setTimeout(resolve, delays[attempt]));
 }
}
window.CVEHarborAccountRead = path => {
 if (!pending.has(path)) pending.set(path, read(path).finally(() => pending.delete(path)));
 return pending.get(path);
};
function mountHeader(){
const target=document.getElementById('headerAccountActions');if(!target)return;
const guestLinks=[...target.childNodes];
let generation=0;
function showAccount(data){
 if(data?.authenticated===false){target.replaceChildren(...guestLinks);return}
 const workspace=document.createElement('a');
 if(data?.authenticated!==true){
  workspace.href='/account/';workspace.className='header-account-primary';workspace.textContent='Account';
  target.replaceChildren(workspace);return;
 }
 workspace.href='/workspace/';workspace.className='header-account-primary';workspace.textContent='My Workspace';
 const name=document.createElement('span');name.className='header-account-user';
 name.textContent=data.email||'Signed in';name.title=name.textContent;
 target.replaceChildren(name,workspace);
}
async function check(){
 const current=++generation;
 showAccount(null);
 try{
  const data=await window.CVEHarborAccountRead('/me');
  if(current===generation)showAccount(data);
 }catch(error){if(current===generation&&error.status===401)showAccount({authenticated:false})}
}
function confirmed(event){generation++;showAccount(event.detail)}
window.addEventListener('cveharbor:account-state',confirmed);
window.addEventListener('cveharbor:catalogue-session',confirmed);
window.addEventListener('pageshow',event=>{if(event.persisted)void check()});
void check();
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',mountHeader,{once:true});
else mountHeader();
})();
