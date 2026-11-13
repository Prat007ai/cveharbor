(()=>{
'use strict';
const workspace=document.getElementById('workspaceAccess');if(!workspace)return;
const el=(tag,value='',className='')=>{const n=document.createElement(tag);n.textContent=value;n.className=className;return n;};
const root=el('section','','finding-ai'),title=el('h2','✦ CVEHarbor AI'),button=el('button','Review customer priorities','finding-ai-generate'),results=el('div'),status=el('p');
button.type='button';status.setAttribute('role','status');root.append(title,el('p','Review your customer’s potential vulnerabilities, then open a finding for an evidence-based fix guide. AI guidance uses the selected workspace’s allowance.'),button,status,results);workspace.prepend(root);
let generation=0;
window.addEventListener('cveharbor-auth-change',()=>{generation++;results.replaceChildren();status.textContent='';button.disabled=false;});
button.addEventListener('click',async()=>{
 const epoch=++generation;button.disabled=true;status.textContent='Loading your customer inventory…';results.replaceChildren();
 try{
  const response=await fetch('https://api.cveharbor.com/v1/inventory',{credentials:'include',cache:'no-store'});if(!response.ok)throw Error('Sign in again to review your inventory.');
  const data=await response.json();if(epoch!==generation)return;
  if(!Array.isArray(data.customers))throw Error('Inventory is unavailable. Open My Environments to check your access.');
  await Promise.all([import('/data.js'),import('/catalog.js'),import('/inventory-matching.js').then(()=>import('/inventory-assessment.js'))]);if(epoch!==generation)return;
  const records=[...new Map([...(window.CVEHARBOR_DATA?.advisories||[]),...(window.CVEHARBOR_CATALOG?.advisories||[])].map(r=>[r.id,r])).values()],byCve=new Map(records.map(r=>[r.id,r]));
  const chooser=el('select'),label=el('label','Customer '),list=el('div');chooser.append(new Option('Choose a customer',''),...data.customers.map(c=>new Option(c.name,c.id)));label.append(chooser);results.append(label,list);
  chooser.addEventListener('change',()=>{
   list.replaceChildren();if(!chooser.value)return;
   const customer=chooser.value,envs=new Set(data.environments.filter(e=>e.customer_id===customer).map(e=>e.id)),assets=data.assets.filter(a=>envs.has(a.environment_id));
   const findings=window.CVEHARBOR_INVENTORY_MATCH.evaluate(assets,records,250);
   list.append(el('p',assets.length+' saved software entries · '+findings.total+' potential matches in the available index.'));
   const states=window.CVEHARBOR_INVENTORY_MATCH.summarize(findings.items);list.append(el('p',states.affected_version+' affected version detected · '+states.needs_verification+' need verification'+(findings.limited?' (available results only)':'')+'.','applicability-summary'));
   list.append(window.CVEHARBOR_FINDING_AI.priorities({findings:findings.items,onOpen:f=>window.CVEHARBOR_FINDING_AI.detailButton({finding:f,advisory:byCve.get(f.id)||f,customer})}));
   const link=el('a','View all findings and inventory coverage');link.href='/customer-dashboard/?customer='+encodeURIComponent(customer);list.append(link);
  });
  status.textContent=data.customers.length?'Select one customer to review their priorities. No AI request has been sent.':'Add a customer and assets in My Environments to start.';
 }catch(error){if(epoch===generation)status.textContent=error.message;}finally{if(epoch===generation)button.disabled=false;}
});
})();
