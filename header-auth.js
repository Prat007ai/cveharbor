(() => {
'use strict';
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
  const response=await fetch('https://api.cveharbor.com/v1/me',{credentials:'include',cache:'no-store',headers:{Accept:'application/json'}});
  const data=response.status===401?{authenticated:false}:response.ok?await response.json():null;
  if(current===generation)showAccount(data);
 }catch{/* The neutral Account link remains available while the service is unreachable. */}
}
function confirmed(event){generation++;showAccount(event.detail)}
window.addEventListener('cveharbor:account-state',confirmed);
window.addEventListener('cveharbor:catalogue-session',confirmed);
window.addEventListener('pageshow',event=>{if(event.persisted)void check()});
void check();
})();
