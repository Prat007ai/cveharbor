(() => {
'use strict';
const $=id=>document.getElementById(id);
if(!$('inventoryWorkspace'))return;
const api='https://api.cveharbor.com/v1/inventory';
let signedIn=false,ready=false,data={customers:[],environments:[],assets:[]};
const make=(tag,className='',value='')=>{
 const el=document.createElement(tag);if(className)el.className=className;el.textContent=String(value);return el;
};
const status=message=>{$('inventoryMessage').textContent=message;};
async function call(path='',method='GET',body){
 const res=await fetch(api+path,{method,credentials:'include',
 headers:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});
 const result=await res.json().catch(()=>({}));
 if(!res.ok)throw Error(result.error||'Inventory service unavailable');
 return result;
}
function option(select,value,label){
 const o=make('option','',label);o.value=value;select.append(o);
}
function selects(){
 const customers=$('inventoryCustomerSelect'),envs=$('inventoryEnvironmentSelect');
 const previousCustomer=customers.value,previousEnv=envs.value;
 customers.replaceChildren();envs.replaceChildren();
 option(customers,'','Choose customer');option(envs,'','Choose environment');
 for(const customer of data.customers)option(customers,customer.id,customer.name);
 for(const environment of data.environments){
  const owner=data.customers.find(x=>x.id===environment.customer_id);
  option(envs,environment.id,(owner?.name||'Customer')+' / '+environment.name);
 }
 if(data.customers.some(x=>x.id===previousCustomer))customers.value=previousCustomer;
 if(data.environments.some(x=>x.id===previousEnv))envs.value=previousEnv;
}
function render(){
 selects();
 $('inventoryCustomerCount').textContent=data.customers.length;
 $('inventoryEnvironmentCount').textContent=data.environments.length;
 $('inventoryAssetCount').textContent=data.assets.length;
 const root=$('inventoryRecords');root.replaceChildren();
 for(const customer of data.customers){
  const card=make('article','inventory-customer');
  const header=make('div','ops-result-top');header.append(make('h4','',customer.name));
  const deleteCustomer=make('button','ops-remove','Remove customer');deleteCustomer.type='button';
  deleteCustomer.addEventListener('click',()=>remove('customers',customer.id,customer.name));
  header.append(deleteCustomer);card.append(header);
  const envs=data.environments.filter(x=>x.customer_id===customer.id);
  if(!envs.length)card.append(make('p','ops-note','No environments added yet.'));
  for(const env of envs){
   const group=make('section','inventory-environment');
   const h=make('div','ops-result-top');h.append(make('strong','',env.name+' · '+env.kind));
   const del=make('button','ops-remove','Remove environment');del.type='button';
   del.addEventListener('click',()=>remove('environments',env.id,env.name));h.append(del);group.append(h);
   const assets=data.assets.filter(x=>x.environment_id===env.id);
   if(!assets.length)group.append(make('p','ops-note','No servers, applications or software versions recorded.'));
   for(const asset of assets){
    const row=make('div','inventory-asset ops-result-top');
    const info=make('div','');
    info.append(make('strong','',asset.name+' · '+asset.technology),
      make('p','ops-note',asset.asset_type+' · Version: '+(asset.version||'Not recorded')+
        (asset.notes?' · '+asset.notes:'')));
    const actions=make('div','inventory-actions');
    const edit=make('button','ops-remove','Edit');edit.type='button';
    edit.addEventListener('click',()=>{
      $('inventoryEnvironmentSelect').value=asset.environment_id;
      $('inventoryAssetName').value=asset.name;
      $('inventoryType').value=asset.asset_type;
      $('inventoryTechnology').value=asset.technology;
      $('inventoryVersion').value=asset.version;
      $('inventoryNotes').value=asset.notes;
      $('inventoryAssetEditId').value=asset.id;
      $('inventoryAssetSave').textContent='Update asset';
      $('inventoryAssetName').focus();
    });
    const removeAsset=make('button','ops-remove','Remove');removeAsset.type='button';
    removeAsset.addEventListener('click',()=>remove('assets',asset.id,asset.name));
    actions.append(edit,removeAsset);row.append(info,actions);group.append(row);
   }
   card.append(group);
  }
  root.append(card);
 }
 if(!data.customers.length)root.append(make('p','ops-note','Start by adding a customer, then create an environment and register its installed technologies.'));
}
async function load(){
 data=await call();render();
}
async function remove(type,id,name){
 if(!window.confirm('Remove '+name+' and any records it contains?'))return;
 try{await call('/'+type+'/'+id,'DELETE');await load();status(name+' removed from your private inventory.')}
 catch(e){status(e.message)}
}
async function onAccount(event){
 signedIn=!!event.detail?.authenticated;
 document.querySelectorAll('#inventoryWorkspace form input,#inventoryWorkspace form select,#inventoryWorkspace form textarea,#inventoryWorkspace form button')
  .forEach(el=>{el.disabled=!signedIn});
 if(!signedIn){ready=false;data={customers:[],environments:[],assets:[]};render();status('Sign in above to view your private customer inventory.');return;}
 try{
  const flags=await call('/status');ready=!!flags.ready;
  if(!ready){status('Cloudflare D1 inventory migration is required before customer records can be saved.');return;}
  await load();status('Inventory loaded from your private Cloudflare D1 account.');
 }catch(e){status('Unable to load inventory: '+e.message)}
}
window.addEventListener('cveharbor:account-state',event=>{void onAccount(event)});
async function save(form,endpoint,payload){
 if(!signedIn||!ready){status('Sign in and complete the database migration first.');return;}
 const button=form.querySelector('button[type=submit]');button.disabled=true;
 try{await call(endpoint,'POST',payload);form.reset();await load();status('Saved to your account inventory.')}
 catch(e){status('Could not save: '+e.message)}
 finally{button.disabled=false}
}
$('inventoryCustomerForm').addEventListener('submit',event=>{
 event.preventDefault();
 void save(event.currentTarget,'/customers',{name:$('inventoryCustomerName').value.trim()});
});
$('inventoryEnvironmentForm').addEventListener('submit',event=>{
 event.preventDefault();
 void save(event.currentTarget,'/environments',{customer_id:$('inventoryCustomerSelect').value,
 name:$('inventoryEnvironmentName').value.trim(),kind:$('inventoryKind').value});
});
$('inventoryAssetForm').addEventListener('submit',async event=>{
 event.preventDefault();
 if(!signedIn||!ready){status('Sign in and complete database migration first.');return;}
 const form=event.currentTarget,editId=$('inventoryAssetEditId').value;
 const payload={environment_id:$('inventoryEnvironmentSelect').value,
 name:$('inventoryAssetName').value.trim(),asset_type:$('inventoryType').value,
 technology:$('inventoryTechnology').value.trim(),version:$('inventoryVersion').value.trim(),
 notes:$('inventoryNotes').value.trim()};
 const button=$('inventoryAssetSave');button.disabled=true;
 try{
  await call(editId?'/assets/'+editId:'/assets',editId?'PUT':'POST',payload);
  form.reset();$('inventoryAssetEditId').value='';button.textContent='Add asset';
  await load();status(editId?'Asset updated in D1.':'Asset saved in D1.');
 }catch(e){status(e.message)}
 finally{button.disabled=false}
});
$('inventoryAssetCancel').addEventListener('click',()=>{
 $('inventoryAssetForm').reset();$('inventoryAssetEditId').value='';
 $('inventoryAssetSave').textContent='Add asset';
});
render();status('Sign in to manage your private customer environments.');
})();
