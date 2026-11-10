import {api,orgPath,workspaceLink,display,element,field,button,select,table,link,notice,actions,accountIdentity,switchAccount} from './team-ui.js';

const countLabel=(count,singular,plural=singular+'s')=>count+' '+(count===1?singular:plural);

function harborIcon(path){
  const ns='http://www.w3.org/2000/svg';
  const svg=document.createElementNS(ns,'svg'),line=document.createElementNS(ns,'path');
  svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('class','harbor-icon');
  svg.setAttribute('aria-hidden','true');line.setAttribute('d',path);svg.append(line);
  return svg;
}

export async function reviewInvite(token){
  const info=await api('invitation','POST',{token});
  const card=element('article','','harbor-invitation'),content=element('div','','harbor-invitation-content');
  const account=element('div','','harbor-access-row');
  const identity=element('div','','harbor-stack');
  identity.append(element('span','Signed in as','harbor-label'),accountIdentity(info.email));
  const change=button('Use another account',switchAccount);
  change.classList.add('harbor-text-button');
  account.append(identity,change);
  const role=element('div','','harbor-access-row'),roleText=element('div','','harbor-stack');
  const descriptions={Owner:'Manage members and all workspace records.',Editor:'View and edit assigned customer records.',Viewer:'View assigned customer records.'};
  roleText.append(element('strong','Your role'),element('span',descriptions[info.role],'harbor-label'));
  role.append(roleText,element('span',info.role,'harbor-chip'));
  const customers=element('div','','harbor-access-row'),grants=element('div','','harbor-grants');
  for(const name of info.scope==='all'?['All current and future customers']:info.customers)grants.append(element('span',name,'harbor-chip'));
  customers.append(element('strong','Customer access'),grants);
  const eyebrow=element('p','Workspace invitation','harbor-eyebrow');
  eyebrow.prepend(harborIcon('M3 5h18v14H3z M3 6l9 7 9-7'));
  content.append(eyebrow,element('h2','Join '+info.organization+'?'),account,role,customers,
    actions(button('Join workspace',async()=>{
      const result=await api('accept','POST',{token,revision:info.revision});
      sessionStorage.removeItem('teamInvitation');location.replace(workspaceLink(result.org));
    },true),button('Decide later',()=>{sessionStorage.removeItem('teamInvitation');location.replace('/workspace/');})));
  card.append(content);display(card);
}
export async function organizationDashboard(id,preferredCustomer=''){
  const base=orgPath(id),info=await api(base+'/customers');
  const title=element('h1',info.name),summary=element('div','','harbor-grants');
  summary.append(element('span',info.role,'harbor-chip'),element('span',countLabel(info.customers.length,'assigned customer'),'harbor-label'));
  const chooser=select([['','Choose a customer'],...info.customers.map(c=>[c.id,c.name])],'');
  const detail=element('section','','harbor-customer');
  let serial=0;
  let sources;
  async function potentialFindings(container,data){
    try{
      sources??=Promise.all([import('/data.js'),import('/catalog.js'),import('/inventory-matching.js')]);
      await sources;
      if(!container.isConnected)return;
      if(!Array.isArray(window.CVEHARBOR_DATA?.advisories))throw Error();
      const records=[...window.CVEHARBOR_DATA.advisories,...(window.CVEHARBOR_CATALOG?.advisories||[])];
      const result=window.CVEHARBOR_INVENTORY_MATCH.evaluate(data.assets,records,100);
      const names=new Map(data.assets.map(a=>[a.id,a.name]));
      container.replaceChildren(element('h3','Potential findings'),element('p',countLabel(result.total,'advisory match','advisory matches')+' · Verify applicability against installed versions.'),
        ...(result.items.length?[table(['Asset','CVE','Severity','Evidence'],result.items.map(f=>[names.get(f.asset_id),f.id,f.severity,f.evidence]))]:[]));
      if(result.limited)container.append(element('p','Showing the first 100 matches.'));
    }catch{sources=null;container.textContent='Advisory matching is temporarily unavailable.';}
  }
  function textInput(value='',max=120){
    const input=element('input');input.value=value;input.maxLength=max;return input;
  }
  function editAsset(customer,data,a){
    const name=textInput(a?.name),technology=textInput(a?.technology),version=textInput(a?.version,80);
    const type=select(['Software','Server','WEB','Application','Database','Cloud Service','Network Device','Other'].map(s=>[s,s]),a?.asset_type||'Software');
    const notes=element('textarea');notes.value=a?.notes||'';notes.maxLength=500;
    const env=select(data.environments.map(e=>[e.id,e.name]),data.environments[0]?.id||'');
    detail.replaceChildren(element('h2',a?'Edit asset':'Add asset'),...(a?[]:[field('Environment',env)]),field('Asset name',name),field('Asset type',type),field('Technology',technology),field('Version',version),field('Notes',notes),
      button('Cancel',load),button('Save asset',async()=>{
        const payload={name:name.value,asset_type:type.value,technology:technology.value,version:version.value,notes:notes.value};
        if(a)await api(base+'/asset/'+customer,'PUT',{...payload,asset_id:a.id,expected:a});
        else await api(base+'/assets/'+customer,'POST',{...payload,environment_id:env.value});
        await load();
      },true));
  }
  async function load(){
    const request=++serial,customer=chooser.value;
    detail.replaceChildren();notice('');
    if(!customer)return;
    try{
      const data=await api(base+'/customers/'+encodeURIComponent(customer));
      if(request!==serial||!detail.isConnected)return;
      renderCustomer(data,customer);
    }catch(error){if(request===serial)notice(error.message);}
  }
  function renderCustomer(data,customer){
    const canEdit=data.customer.role!=='Viewer';
    const assetRows=data.assets.map(a=>{
      const cells=[a.name,a.environment,a.technology,a.version,a.notes];
      if(canEdit)cells.push(button('Edit asset',()=>editAsset(customer,data,a)));
      return cells;
    });
    const records=data.remediations.map(r=>{
      const cells=[r.id.split('~')[0],r.status,r.owner,r.due,r.notes];
      if(canEdit)cells.push(button('Edit remediation',()=>{
        const status=select(['Open','Investigating','Remediated','Accepted Risk','Not Applicable'].map(s=>[s,s]),r.status);
        const owner=element('input');owner.value=r.owner;owner.maxLength=100;
        const notes=element('textarea');notes.value=r.notes;notes.maxLength=1200;
        const due=element('input');due.type='date';due.value=r.due;
        const reason=element('textarea');reason.maxLength=1000;
        detail.replaceChildren(element('h2','Edit '+r.id.split('~')[0]),field('Status',status),field('Assigned owner',owner),field('Due date',due),field('Remediation notes',notes),field('Reason for status change',reason),
          button('Cancel',load),button('Save changes',async()=>{
            await api(base+'/remediation/'+encodeURIComponent(customer),'PUT',{id:r.id,expected_updated:r.updated_at,status:status.value,owner:owner.value,notes:notes.value,due:due.value,status_change_reason:reason.value});
            await load();
          },true));
      }));
      return cells;
    });
    function group(heading,headers,rows,controls){
      const card=element('section','','harbor-records'),bar=element('div','','harbor-toolbar');
      bar.append(element('h3',heading));
      if(controls&&controls.childElementCount)bar.append(controls);
      card.append(bar,rows.length?table(headers,rows):element('p','No records for this customer.'));return card;
    }
    const tools=element('div','','team-actions');
    if(canEdit){
      tools.append(button('Add environment',()=>{
        const name=textInput('',100),kind=select(['Production','Staging','Development','QA','UAT','Other'].map(s=>[s,s]),'Production');
        detail.replaceChildren(element('h2','Add environment'),field('Name',name),field('Type',kind),button('Cancel',load),
          button('Save environment',async()=>{await api(base+'/environments/'+customer,'POST',{name:name.value,kind:kind.value});await load();},true));
      }));
      if(data.environments.length)tools.prepend(button('Add asset',()=>editAsset(customer,data),true));
      tools.append(button('Track a CVE',()=>{
        const cve=textInput('',28),owner=textInput('',100),notes=element('textarea');notes.maxLength=1200;
        detail.replaceChildren(element('h2','Track a CVE for '+data.customer.name),field('CVE ID',cve),field('Assigned owner',owner),field('Notes',notes),button('Cancel',load),
          button('Create remediation',async()=>{await api(base+'/remediation/'+customer,'POST',{cve_id:cve.value,owner:owner.value,notes:notes.value});await load();},true));
      }));
    }
    const metrics=element('dl','','harbor-metrics');
    const measures=[
      [data.environments.length,'environment','M2 10l10-7 10 7 M4 9v12h16V9 M8 21v-8h8v8'],
      [data.assets.length,'asset','M12 3l10 5-10 5L2 8z M2 12l10 5 10-5 M2 16l10 5 10-5'],
      [data.findings.length,'reviewed finding','M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z M8 12l3 3 5-6']
    ];
    for(const [count,label,path] of measures){
      const metric=element('div');
      const value=element('dd');value.append(harborIcon(path),String(count));
      metric.append(element('dt',count===1?label:label+'s'),value);metrics.append(metric);
    }
    const potential=element('section','Checking advisories for these assets…','harbor-records');
    detail.replaceChildren(element('h2',data.customer.name),metrics,
      group('Environments',['Environment','Environment type'],data.environments.map(e=>[e.name,e.kind])),
      group('Assets',['Asset','Environment','Technology','Version','Notes',...(canEdit?['Actions']:[])],assetRows,tools),
      potential,group('Reviewed findings',['Asset','CVE','Status','Notes'],data.findings.map(f=>[f.asset,f.cve_id,f.status,f.notes])),
      group('Remediation tracker',['CVE','Status','Assigned owner','Due','Notes',...(canEdit?['Actions']:[])],records),
      group('Recent team activity',['Team member','Change','Time'],data.activity.map(entry=>[entry.email,entry.action,new Date(entry.at*1000).toLocaleString()])),
      button('Print customer report',async()=>{
        const refreshed=await api(base+'/customers/'+encodeURIComponent(customer));
        if(chooser.value!==customer||!detail.isConnected)return;
        await renderCustomer(refreshed,customer);
        if(chooser.value===customer&&detail.isConnected)window.print();
      }));
    return potentialFindings(potential,data);
  }
  chooser.onchange=load;
  const actions=element('div','','team-actions');
  actions.append(button('Refresh',async()=>{
    const preferred=chooser.value;
    display(element('p','Checking workspace access...'),link('My personal workspace','/workspace/'));
    try{await organizationDashboard(id,preferred);}catch(error){display(element('p',error.message),link('My personal workspace','/workspace/'));}
  }));
  if(info.scope==='all'&&info.role!=='Viewer')actions.append(button('Add customer',()=>{
    ++serial;const name=textInput();
    detail.replaceChildren(element('h2','Add customer'),field('Customer name',name),button('Cancel',load),
      button('Create customer',async()=>{await api(base+'/customers','POST',{name:name.value});await organizationDashboard(id);},true));
  }));
  const header=element('div','','harbor-workspace-header'),orgInfo=element('div','','harbor-stack');
  orgInfo.append(title,summary);
  header.append(orgInfo,field('Customer',chooser),actions);
  display(header,detail,link('My personal workspace','/workspace/'));
  const selected=info.customers.find(c=>c.id===preferredCustomer)||(info.customers.length===1?info.customers[0]:null);
  if(selected){chooser.value=selected.id;await load();}
}
export function workspacePicker(organizations){
  if(!organizations.length)return;
  display(element('h2','Organization workspaces'),...organizations.map(org=>link(org.name+' · '+org.role,workspaceLink(org.id))));
}
