// Organization dashboard uses only the existing permission-scoped team endpoints.
import {api,orgPath,element,table,link,select,field} from './team-ui.js';
const params=new URLSearchParams(location.search),org=params.get('org');
if(org){
 const status=document.getElementById('customerDashStatus');
 const host=element('section','','data-panel ops-panel organization-security');status.after(host);
 const base=orgPath(org);let generation=0;
 const agentHost=element('div');host.after(agentHost);
 import('./agent-ui.js').then(({mountAgents})=>mountAgents(agentHost,{setup:false,scope:()=>({org,customer:params.get('customer')||'',environment:params.get('environment')||''}),onChange:()=>void render()})).catch(()=>{agentHost.textContent='Agent connection controls could not load. Refresh to retry.';});
 async function render(){
  const ticket=++generation;host.replaceChildren();status.textContent='Checking organization access and assessing inventory…';
  try{
   const info=await api(base+'/customers');if(ticket!==generation)return;
   const customer=params.get('customer')||info.customers[0]?.id;
   if(!customer||!info.customers.some(c=>c.id===customer))throw Error('This customer is not available to your account.');
   const data=await api(base+'/customers/'+encodeURIComponent(customer));if(ticket!==generation)return;
   if(data.assets.some(a=>!a.environment_id))throw Error('Inventory assessment requires the updated backend environment identifiers.');
   const chooser=select(info.customers.map(c=>[c.id,c.name]),customer),env=select([['','All environments'],...data.environments.map(e=>[e.id,e.name])],params.get('environment')||'');
   if(params.get('environment')&&!data.environments.some(e=>e.id===params.get('environment')))throw Error('This environment is not available for the selected customer.');
   const controls=element('div','','inventory-actions'),results=element('section');
   const refresh=element('button','Refresh assessment','ops-download');refresh.type='button';refresh.onclick=render;
   controls.append(field('Customer',chooser),field('Environment',env),refresh,link('Open organization workspace','/workspace/?team='+encodeURIComponent(org)));
   chooser.onchange=()=>{params.set('customer',chooser.value);params.delete('environment');void render();};
   env.onchange=()=>{params.set('environment',env.value);draw();};
   const records=[...new Map([...(window.CVEHARBOR_DATA?.advisories||[]),...(window.CVEHARBOR_CATALOG?.advisories||[])].map(r=>[r.id,r])).values()];
   const byCve=new Map(records.map(r=>[r.id,r]));
   const findingLink=f=>window.CVEHARBOR_FINDING_AI?.detailButton({finding:f,advisory:byCve.get(f.id)||f,customer,org})||link(f.id,'/vulnerabilities/?cve='+encodeURIComponent(f.id));
   function draw(){
    const assets=data.assets.filter(a=>!env.value||a.environment_id===env.value);
    results.replaceChildren(window.CVEHARBOR_ASSESSMENT.summary(assets,records));
    const result=window.CVEHARBOR_INVENTORY_MATCH.evaluate(assets,records,5000),byId=new Map(assets.map(a=>[a.id,a]));
    if(window.CVEHARBOR_FINDING_AI)results.prepend(window.CVEHARBOR_FINDING_AI.priorities({findings:result.items,onOpen:findingLink}));
    const servers=element('section');servers.setAttribute('aria-label','Security by server');results.append(servers);
    window.CVEHARBOR_SERVER_SECURITY.render(servers,{assets,issues:result.items,limited:result.limited,environments:data.environments.map(e=>({...e,customer_id:customer})),customers:[{id:customer,name:data.customer.name}]},{findingLink,loadNetworks:()=>api(base+'/server-network/'+encodeURIComponent(customer)),savePrimary:data.customer.role==='Viewer'?null:payload=>api(base+'/server-network/'+encodeURIComponent(customer),'PUT',payload)});
    const findingRows=result.items.slice(0,250).map(f=>{const a=byId.get(f.asset_id);let reference='Source unavailable';try{if(new URL(f.source_url).protocol==='https:')reference=link('Advisory',f.source_url);}catch{}const state=window.CVEHARBOR_INVENTORY_MATCH.applicability(f);return [a.name,window.CVEHARBOR_SERVER_SECURITY.role(a),a.technology,a.version||'Unknown',findingLink(f),f.severity,state.label,state.reason+' '+f.evidence,reference];});
    if(result.total>250)results.append(element('p','Showing the first 250 findings. Select an environment to narrow the review.'));
    results.append(element('h2','Vulnerability findings'),findingRows.length?table(['Hostname / asset','Server role','Product','Installed version','CVE','Severity','Assessment','Evidence','Source'],findingRows):element('p','No matching findings in the available index. Coverage remains unverified.'));
    results.append(element('h2','Installed products'),table(['Hostname / asset','Server role','Environment','Product','Version'],assets.map(a=>[a.name,window.CVEHARBOR_SERVER_SECURITY.role(a),a.environment,a.technology,a.version||'Unknown'])));
    status.textContent=info.name+' · '+data.customer.name+' · '+data.customer.role+' · Assessment complete against the available index.';
   }
   host.append(controls,results);draw();
  }catch(e){if(ticket===generation){host.replaceChildren();status.textContent=e.message+' No assessment completed.';}}
 }
 await render();
 window.addEventListener('focus',()=>void render());
}
