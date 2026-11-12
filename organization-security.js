// Organization dashboard uses only the existing permission-scoped team endpoints.
import {api,orgPath,element,table,link,select,field} from './team-ui.js';
const params=new URLSearchParams(location.search),org=params.get('org');
if(org){
 const status=document.getElementById('customerDashStatus');
 const host=element('section','','data-panel ops-panel organization-security');status.after(host);
 const base=orgPath(org);let generation=0;
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
   function draw(){
    const assets=data.assets.filter(a=>!env.value||a.environment_id===env.value);
    const records=[...(window.CVEHARBOR_DATA?.advisories||[]),...(window.CVEHARBOR_CATALOG?.advisories||[])];
    results.replaceChildren(window.CVEHARBOR_ASSESSMENT.summary(assets,records));
    if(!records.length)return;
    const result=window.CVEHARBOR_INVENTORY_MATCH.evaluate(assets,records,5000),byId=new Map(assets.map(a=>[a.id,a]));
    const findingRows=result.items.map(f=>{const a=byId.get(f.asset_id);let reference='Source unavailable';try{if(new URL(f.source_url).protocol==='https:')reference=link('Advisory',f.source_url);}catch{}return [a.name,a.technology,a.version||'Unknown',f.id,f.severity,f.level==='version_review'?'Affected-version candidate':'Needs verification',f.evidence,reference];});
    results.append(element('h2','Vulnerability findings'),findingRows.length?table(['Asset','Product','Installed version','CVE','Severity','Assessment','Evidence','Source'],findingRows):element('p','No matching findings in the available index. Coverage remains unverified.'));
    results.append(element('h2','Installed products'),table(['Asset','Environment','Product','Version'],assets.map(a=>[a.name,a.environment,a.technology,a.version||'Unknown'])));
    status.textContent=info.name+' · '+data.customer.name+' · '+data.customer.role+' · Assessment complete against the available index.';
   }
   host.append(controls,results);draw();
  }catch(e){if(ticket===generation){host.replaceChildren();status.textContent=e.message+' No assessment completed.';}}
 }
 await render();
 window.addEventListener('focus',()=>void render());
}
