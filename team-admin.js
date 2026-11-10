import {api,orgPath,workspaceLink,display,element,field,button,select,link,table,notice} from './team-ui.js';
import {harborLight} from './team-invitation-art.js';

function banner(title){
  const header=element('div','','team-banner');
  header.style.backgroundImage='linear-gradient(90deg,#0b2639 10%,transparent 92%),url(data:image/png;base64,'+harborLight+')';
  header.append(element('h2',title));return header;
}
export async function teamSettings(organizations,canCreate){
  const nodes=[element('h2','Organization workspaces')];
  for(const org of organizations){
    const row=element('div','','team-actions');
    row.append(element('strong',org.name),element('span',org.role),link('Open workspace',workspaceLink(org.id)));
    if(org.role==='Owner')row.append(button('Manage team',()=>members(org)));
    nodes.push(row);
  }
  if(canCreate){
    const name=element('input');name.maxLength=100;name.required=true;
    const inventory=select([['separate','Start with a new organization inventory'],['existing','Share my existing customer inventory']],'separate');
    const description=element('p','A new inventory belongs to the organization. Owners can transfer responsibility to another active team member.');
    inventory.onchange=()=>description.textContent=inventory.value==='existing'?'This shares your current and future customers. Your original account retains Owner access because it owns these records.':'A new inventory belongs to the organization. Owners can transfer responsibility to another active team member.';
    nodes.push(field('Organization name',name),field('Customer inventory',inventory),description,button('Create organization',async()=>{
        const value=name.value.trim();if(!value)throw Error('Enter an organization name.');
        const org=await api('organizations','POST',{name:value,include_existing:inventory.value==='existing'});
        await members({...org,name:value,role:'Owner'});
      },true));
  }
  display(...nodes);
}
async function members(org){
  const base=orgPath(org.id)+'/members';
  const {members:list,customers}=await api(base);
  const labels=new Map(customers.map(c=>[c.id,c.name]));
  const rows=list.map(m=>{
    const actions=element('div','','team-actions');
    actions.append(button('Edit',()=>edit(org,customers,m)));
    if(m.status!=='Active')actions.append(button('Reissue',async()=>{await api(base+'/'+m.id,'POST',{revision:m.revision});await members(org);notice('New invitation sent.');}));
    if(!m.founder)actions.append(button('Remove',async()=>{
      if(!window.confirm('Remove '+m.email+' from '+org.name+'?'))return;
      await api(base+'/'+m.id,'DELETE',{revision:m.revision});await members(org);
    }));
    const date=m.signed_at?new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'long'}).format(m.signed_at*1000):m.active?'No recorded sign-in':'Available after acceptance';
    return [m.email,m.role,m.scope==='all'?'All current and future customers':m.customers.map(id=>labels.get(id)||'Removed customer').join(', '),m.status,date,actions];
  });
  display(banner(org.name),element('h3','Team members'),element('p','Active members have accepted their invitation. Last sign-in shows their most recent successful CVEHarbor sign-in.'),button('Invite member',()=>edit(org,customers),true),button('Refresh members',()=>members(org)),
    table(['Member','Role','Customer access','Status','Last sign-in','Actions'],rows),link('Open workspace',workspaceLink(org.id)));
}
function edit(org,customers,member){
  const base=orgPath(org.id)+'/members';
  const email=element('input');email.type='email';email.required=true;email.maxLength=254;email.value=member?.email||'';email.disabled=!!member;
  const role=select(['Viewer','Editor','Owner'].map(s=>[s,s]),member?.role||'Viewer');
  const scope=select([['selected','Selected customers'],['all','All current and future customers']],member?.scope||'selected');
  role.disabled=!!member?.founder;
  const choices=element('fieldset','','team-choices');choices.append(element('legend','Assigned customers'));
  const checks=customers.map(customer=>{
    const label=element('label'),check=element('input');check.type='checkbox';check.value=customer.id;
    check.checked=member?.customers.includes(customer.id)||false;
    label.append(check,document.createTextNode(customer.name));choices.append(label);return check;
  });
  const help=element('p');
  let memberScope=member?.role==='Owner'?'selected':scope.value;
  function update(){
    const owner=role.value==='Owner';
    if(!scope.disabled)memberScope=scope.value;
    scope.value=owner?'all':memberScope;
    scope.disabled=owner;
    choices.hidden=scope.value==='all';
    help.textContent=member?.founder?'The founding account owns the existing records and retains Owner access.':
      {Owner:'Manage all customers, invitations and membership.',Editor:'View and update records for assigned customers.',Viewer:'Read records for assigned customers.'}[role.value];
  }
  role.onchange=update;scope.onchange=update;update();
  const path=member?base+'/'+member.id:base;
  const save=button(member?'Save changes':'Preview invitation email',async()=>{
    if(!email.reportValidity())return;
    const selected=scope.value==='all'?[]:checks.filter(c=>c.checked).map(c=>c.value);
    if(scope.value==='selected'&&!selected.length)throw Error('Select at least one customer.');
    const payload={email:email.value.trim(),role:role.value,scope:scope.value,customers:selected};
    if(member){
      try{await api(path,'PUT',{...payload,revision:member.revision});}
      catch(error){if(error.status===409)await members(org);throw error;}
      await members(org);notice('Access updated.');return;
    }
    const send=button('Send invitation',async()=>{
      try{await api(path,'POST',payload);}catch(error){await members(org);throw error;}
      await members(org);notice('Invitation sent.');
    },true);
    const message=await api(orgPath(org.id)+'/preview','POST',payload);
    const preview=element('iframe','','team-email-preview');
    preview.title='Invitation email for '+payload.email;
    preview.setAttribute('sandbox','');
    preview.srcdoc='<meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:"><body style="margin:0">'+message.html.replace('cid:harbor-light.png','data:image/png;base64,'+harborLight);
    display(element('h2','Invitation email preview'),element('p',message.subject),preview,button('Edit invitation',form),send);
  },true);
  function form(){display(banner(member?'Edit member access':'Invite a team member'),element('p',org.name),field('Email address',email),field('Organization role',role),help,field('Customer access',scope),choices,button('Back to members',()=>members(org)),save);}
  form();
}
