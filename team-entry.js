import {api,resetTeamSession,display,panel,element,button,link,notice,switchAccount} from './team-ui.js';
import {organizationDashboard,reviewInvite,workspacePicker} from './team-workspace.js';

const root=document.querySelector('#teamAccess');
const account=!!document.querySelector('#accountSecurityDashboard');
const invite=/^#team-invite=([a-f0-9]{64})$/.exec(location.hash);
if(invite){
  sessionStorage.setItem('teamInvitation',invite[1]);
  history.replaceState(null,'',location.pathname+location.search);
}
const org=new URLSearchParams(location.search).get('team');
let generation=0;
function showAccountTeam(show){
  document.body.classList.toggle('team-admin-open',show);
  root.hidden=!show;
  document.querySelector('#teamTab')?.setAttribute('aria-pressed',String(show));
  document.querySelector('#personalTab')?.setAttribute('aria-pressed',String(!show));
}
async function start(){
  const request=++generation,token=!account&&sessionStorage.getItem('teamInvitation');
  if(!account&&(token||org))document.body.classList.add('team-requested');
  try{
    const me=await window.CVEHarborAccountRead('/me');
    if(request!==generation||!me.authenticated)return;
    if(account){
      const data=await api('organizations');
      if(request!==generation)return;
      if((!data.organizations.length&&data.can_create)||data.organizations.some(o=>o.role==='Owner')){
        const personal=document.querySelector('#personalTab'),team=document.querySelector('#teamTab');
        personal.onclick=()=>showAccountTeam(false);
        team.onclick=async()=>{
          showAccountTeam(true);panel.replaceChildren();notice('Loading team settings…');
          try{const {teamSettings}=await import('./team-admin.js');const state=await api('organizations');if(request!==generation)return;await teamSettings(state.organizations,state.can_create);notice('');}catch(error){notice(error.message);}
        };
        personal.parentElement.hidden=false;
      }
    }else if(token||org){
      document.body.classList.add('team-workspace-open');
      if(token)await reviewInvite(token);else await organizationDashboard(org);
    }else{
      const data=await api('organizations');
      if(request===generation)workspacePicker(data.organizations);
    }
  }catch(error){
    if(request!==generation)return;
    if(!account&&(token||org)){
      if(error.status===401){
        document.body.classList.remove('team-workspace-open');
        display(element('h2',token?'Accept your workspace invitation':'Sign in to your organization'),element('p','Continue below with your invited email and authenticator.'));
      }else{
        display(element('h2','Workspace access unavailable'),element('p',error.message),
          button('Try again',start),button('Use another account',switchAccount),button('Return to my workspace',()=>{sessionStorage.removeItem('teamInvitation');location.replace('/workspace/');}),link('Account & Security','/account/'));
      }
    }
  }
}
window.addEventListener('cveharbor-auth-change',e=>{
  if(e.detail?.authenticated)void start();
  else {generation++;resetTeamSession();panel.replaceChildren();notice('');root.hidden=true;if(account){showAccountTeam(false);document.querySelector('#teamTabs').hidden=true;}document.body.classList.remove('team-workspace-open');if(!account&&sessionStorage.getItem('teamInvitation'))display(element('p','Sign in with the invited email to review your workspace invitation.'));}
});
void start();
