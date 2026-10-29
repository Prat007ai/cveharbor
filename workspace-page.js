(() => {'use strict';
const $=id=>document.getElementById(id);
fetch('https://api.cveharbor.com/v1/me',{credentials:'include',headers:{Accept:'application/json'}})
.then(async response=>response.ok?response.json():null)
.then(data=>{
 const yes=!!data?.authenticated;
 $('workspaceAccess').hidden=!yes;$('workspaceSignIn').hidden=yes;
 $('workspaceSession').textContent=yes?'Signed in as '+data.email:'Please sign in to open your personal workspace.';
}).catch(()=>{
 $('workspaceSignIn').hidden=false;
 $('workspaceSession').textContent='The account service is unavailable. You can still browse public vulnerability information.';
});
})();