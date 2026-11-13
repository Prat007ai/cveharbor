(()=>{
'use strict';
const workspace=document.getElementById('workspaceAccess');if(!workspace)return;
const el=(tag,value='',className='')=>{const n=document.createElement(tag);n.textContent=value;n.className=className;return n;};
const root=el('section','','finding-ai'),title=el('h2','✦ CVEHarbor AI'),button=el('button','Review customer priorities','finding-ai-generate'),results=el('div'),status=el('p');
button.type='button';status.setAttribute('role','status');root.append(title,el('p','Review your customer’s potential vulnerabilities, then open a finding for an evidence-based fix guide. AI guidance uses the selected workspace’s allowance.'),button,status,results);workspace.prepend(root);
let generation=0,inventoryRequest=null;
window.addEventListener('cveharbor-auth-change',()=>{generation++;inventoryRequest?.abort();results.replaceChildren();status.textContent='';button.disabled=false;});
button.addEventListener('click',async()=>{
 const epoch=++generation;button.disabled=true;status.textContent='Loading your customer inventory…';results.replaceChildren();
 try{
  const {readInventory}=window.CVEHARBOR_INVENTORY_CLIENT||await import('/inventory-client.js');
  const data=await readInventory('inventory',{resourceList:['customers','environments']});if(epoch!==generation)return;
  if(!Array.isArray(data.customers))throw Error('Inventory is unavailable. Open My Environments to check your access.');
  await Promise.all([import('/data.js'),import('/catalog.js'),import('/inventory-matching.js').then(()=>import('/inventory-assessment.js'))]);if(epoch!==generation)return;
  const records=[...new Map([...(window.CVEHARBOR_DATA?.advisories||[]),...(window.CVEHARBOR_CATALOG?.advisories||[])].map(r=>[r.id,r])).values()],byCve=new Map(records.map(r=>[r.id,r]));
  const chooser=el('select'),label=el('label','Customer '),list=el('div');chooser.append(new Option('Choose a customer',''),...data.customers.map(c=>new Option(c.name,c.id)));label.append(chooser);results.append(label,list);
  let selection=0;
  chooser.addEventListener('change',async()=>{
   const current=++selection;inventoryRequest?.abort();inventoryRequest=new AbortController();
   list.replaceChildren();if(!chooser.value)return;
   const customer=chooser.value;
   list.append(el('p','Checking saved inventory… You can choose another customer while this finishes.'));
   try{
   // Load only the selected customer's software; keep the chooser independent of large inventories.
   const scoped=data.assets?data:await readInventory('inventory',{customer,resourceList:['environments','assets'],signal:inventoryRequest.signal});
   if(epoch!==generation||current!==selection)return;
   const envs=new Set(scoped.environments.filter(e=>e.customer_id===customer).map(e=>e.id)),assets=scoped.assets.filter(a=>envs.has(a.environment_id));
   const findings=await window.CVEHARBOR_INVENTORY_MATCH.evaluateAsync(assets,records,250,{cancelled:()=>epoch!==generation||current!==selection});
   if(epoch!==generation||current!==selection)return;
   list.replaceChildren();
   list.append(el('p',assets.length+' saved software entries · '+findings.total+' potential matches in the available index.'));
   const states=window.CVEHARBOR_INVENTORY_MATCH.summarize(findings.items);list.append(el('p',states.affected_version+' affected version detected · '+states.needs_verification+' need verification'+(findings.limited?' (available results only)':'')+'.','applicability-summary'));
   list.append(window.CVEHARBOR_FINDING_AI.priorities({findings:findings.items,onOpen:f=>window.CVEHARBOR_FINDING_AI.detailButton({finding:f,advisory:byCve.get(f.id)||f,customer})}));
   const link=el('a','View all findings and inventory coverage');link.href='/customer-dashboard/?customer='+encodeURIComponent(customer);list.append(link);
   }catch(error){if(error.name!=='AbortError'&&epoch===generation&&current===selection)list.replaceChildren(el('p','Priority review could not finish. Open the Customer Security Dashboard to review current findings.'));}
  });
  status.textContent=data.customers.length?'Select one customer to review their priorities. No AI request has been sent.':'Add a customer and assets in My Environments to start.';
 }catch(error){if(epoch===generation)status.textContent=error.message;}finally{if(epoch===generation)button.disabled=false;}
});
})();
