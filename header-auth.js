(() => {
'use strict';
const target=document.getElementById('headerAccountActions');if(!target)return;
fetch('https://api.cveharbor.com/v1/me',{credentials:'include',headers:{Accept:'application/json'}})
.then(async response=>response.ok?response.json():null)
.then(data=>{
 if(!data?.authenticated)return;
 target.replaceChildren();
 const workspace=document.createElement('a');
 workspace.href='/workspace/';workspace.className='header-account-primary';workspace.textContent='My Workspace';
 const name=document.createElement('span');name.className='header-account-user';
 name.textContent=data.email||'Signed in';name.title=name.textContent;
 target.append(name,workspace);
}).catch(()=>{});
})();