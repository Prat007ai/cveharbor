(()=>{'use strict';
const $=id=>document.getElementById(id),make=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
let inventory={customers:[],environments:[],assets:[]},active=false,changed=()=>{},api=null,generation=0;
const select=(id,label)=>{const wrap=make('label',label),input=make('select');input.id=id;wrap.append(input);return {wrap,input};};
function options(input,first,rows){input.replaceChildren();for(const [value,label] of [first,...rows]){const o=make('option',label);o.value=value;input.append(o);}}
function dependent(){
 const customer=$('remediationCustomer').value,old=$('remediationEnvironment').value;
 options($('remediationEnvironment'),['','No specific environment'],inventory.environments.filter(e=>e.customer_id===customer).map(e=>[e.id,e.name]));
 if([...$('remediationEnvironment').options].some(o=>o.value===old))$('remediationEnvironment').value=old;
 assets();
 $('remediationAssociateLabel').hidden=!$('remediationCustomer').dataset.existing||!customer||customer==='unassigned';
}
function assets(){options($('remediationAsset'),['','No specific asset'],inventory.assets.filter(a=>a.environment_id===$('remediationEnvironment').value).map(a=>[a.id,a.name+' · '+a.technology+' '+(a.version||'')]));}
function defaults(){if(!active)return;const filter=$('remediationCustomerFilter').value;$('remediationCustomer').value=filter==='all'?'':filter;delete $('remediationCustomer').dataset.existing;$('remediationAssociate').checked=false;dependent();}
function clear(){generation++;active=false;inventory={customers:[],environments:[],assets:[]};$('remediationCustomerPanel')?.remove();$('remediationCustomerFields')?.remove();document.querySelector('[data-customer-column]')?.remove();}
async function load(features,request,onChange){
 clear();if(!features.shared_records_available)return;
 const token=generation,data=await request('/inventory');if(token!==generation)return;inventory=data;api=request;changed=onChange;active=true;
 const panel=make('section');panel.id='remediationCustomerPanel';panel.className='rt-panel rt-customer-filter';
 const filter=select('remediationCustomerFilter','Customer');options(filter.input,['all','All Records'],[...data.customers.map(c=>[c.id,c.name]),['unassigned','Unassigned Records']]);panel.append(filter.wrap);
 $('remediationTracker').prepend(panel);
 const fields=make('div');fields.id='remediationCustomerFields';fields.className='ops-span rt-customer-fields';
 const customer=select('remediationCustomer','Customer *');options(customer.input,['','Choose a customer or Unassigned'],[...data.customers.map(c=>[c.id,c.name]),['unassigned','Unassigned Records']]);customer.input.required=true;
 const environment=select('remediationEnvironment','Environment (optional)'),asset=select('remediationAsset','Asset (optional)');
 const confirmation=make('label','I confirm this existing unassigned record belongs to the selected customer.');confirmation.id='remediationAssociateLabel';const check=make('input');check.type='checkbox';check.id='remediationAssociate';confirmation.prepend(check);confirmation.hidden=true;
 fields.append(customer.wrap,environment.wrap,asset.wrap,confirmation);if(!features.customer_records_available)fields.append(make('small','Customer-only records require the separately reviewed migration. Existing asset-linked work remains available.'));
 $('remediationForm').prepend(fields);customer.input.addEventListener('change',dependent);environment.input.addEventListener('change',assets);
 asset.input.addEventListener('change',()=>{if(asset.input.value)$('remediationReasonLabel').hidden=false;});
 const requested=new URLSearchParams(location.search).get('customer_id');
 if(requested&&[...filter.input.options].some(o=>o.value===requested))filter.input.value=requested;
 else if(requested)throw Error('Selected customer is not available in this account.');
 filter.input.addEventListener('change',()=>{const url=new URL(location.href);url.searchParams.set('customer_id',filter.input.value);history.replaceState(null,'',url);defaults();changed();});
 defaults();
}
function beginEdit(task){if(!active)return;defaults();$('remediationCustomer').value='unassigned';$('remediationCustomer').dataset.existing=task.id;dependent();}
function payload(item,editing){
 const customer=$('remediationCustomer').value;if(!customer)throw Error('Choose a customer or deliberately select Unassigned Records.');
 if(editing&&customer!=='unassigned'&&!$('remediationAssociate').checked)throw Error('Confirm the existing record association.');
 return {...item,cve_id:item.id,customer_id:customer,environment_id:$('remediationEnvironment').value||null,asset_id:$('remediationAsset').value||null,...(editing?{existing_id:editing.id,confirm_association:$('remediationAssociate').checked}:{})};
}
function decorate(row,task){const cell=make('td'),label=make('span','Customer');label.className='rt-cell-label';label.setAttribute('aria-hidden','true');cell.append(label,document.createTextNode(task.scope?.customer_name||'Unassigned Records'));if(task.scope?.environment_name)cell.append(make('small',task.scope.environment_name));if(task.scope?.asset_name)cell.append(make('small',task.scope.asset_name));row.insertBefore(cell,row.children[3]);}
function recordFor(tasks,cve){const c=$('remediationCustomer').value,e=$('remediationEnvironment').value,a=$('remediationAsset').value;const found=tasks.filter(t=>t.cve_id===cve||t.id===cve).filter(t=>c==='unassigned'?!t.scope:t.scope?.customer_id===c&&(t.scope.environment_id||'')===e&&(t.scope.asset_id||'')===a);return found.length===1?found[0]:null;}
window.CVEHARBOR_CUSTOMER_REMEDIATION={load,clear,defaults,beginEdit,decorate,recordFor,get active(){return active;},query:()=>active?'?customer_id='+encodeURIComponent($('remediationCustomerFilter').value):'',save:(item,editing)=>api('/customer-remediations','POST',payload(item,editing))};
})();
