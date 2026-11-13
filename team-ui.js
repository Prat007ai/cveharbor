const root=document.querySelector('#teamAccess');
const status=document.querySelector('#teamStatus');
export const panel=document.querySelector('#teamPanel');
export const notice=text=>{status.textContent=text;};
export function element(tag,text='',className=''){
  const node=document.createElement(tag);node.textContent=text;
  if(className)node.className=className;
  return node;
}
export function button(text,handler,primary=false){
  const node=element('button',text,primary?'account-primary-button':'account-secondary-button');
  node.type='button';
  node.onclick=async()=>{
    node.disabled=true;notice('');
    try{await handler();}catch(error){notice(error.message);}finally{node.disabled=false;}
  };
  return node;
}
export function actions(...controls){
  const group=element('div','','team-actions');group.append(...controls);return group;
}
export function field(label,control){
  const wrapper=element('label',label,'team-field');wrapper.append(control);return wrapper;
}
export function select(options,value){
  const node=element('select');
  for(const [id,label] of options){const opt=element('option',label);opt.value=id;node.append(opt);}
  node.value=value;return node;
}
export function link(label,url){
  const a=element('a',label,'account-settings-link');a.href=url;return a;
}
export function table(headers,rows){
  const wrapper=element('div','','team-table-wrap'),t=element('table');
  const head=t.createTHead().insertRow();
  headers.forEach(h=>{const th=element('th',h);th.scope='col';head.append(th);});
  const body=t.createTBody();
  for(const row of rows){
    const tr=body.insertRow();
    for(const value of row){const td=tr.insertCell();if(value instanceof Node)td.append(value);else td.textContent=value??'—';}
  }
  wrapper.append(t);return wrapper;
}
export function display(...nodes){root.hidden=false;panel.replaceChildren(...nodes);}
let requests=new AbortController();
export function resetTeamSession(){requests.abort();requests=new AbortController();}
export async function api(path,method='GET',payload){
  const customer=method==='GET'&&/^(organizations\/[^/]+)\/customers\/([^/?]+)$/.exec(path);
  if(customer){
    const meta=await api(path+'?metadata=1');if(!meta.pagination)return meta;
    const {readInventory}=window.CVEHARBOR_INVENTORY_CLIENT||await import('/inventory-client.js');
    const result=await readInventory('inventory',{signal:requests.signal,customer:decodeURIComponent(customer[2]),resourceList:['environments','assets','statuses'],fetchPage:params=>api(customer[1]+'/inventory-page/'+customer[2]+'?'+params)});
    const environments=new Map(result.environments.map(e=>[e.id,e.name])),assets=new Map(result.assets.map(a=>[a.id,a.name]));
    return {...meta,environments:result.environments,assets:result.assets.map(a=>({...a,environment:environments.get(a.environment_id)})),findings:result.statuses.map(s=>({...s,asset:assets.get(s.asset_id)})),complete:true,revision:result.revision};
  }
  const network=method==='GET'&&/^(organizations\/[^/]+)\/server-network\/([^/?]+)$/.exec(path);
  if(network){
    const meta=await api(network[1]+'/customers/'+network[2]+'?metadata=1');
    if(meta.pagination){const {readInventory}=window.CVEHARBOR_INVENTORY_CLIENT||await import('/inventory-client.js');return readInventory('inventory/server-network',{signal:requests.signal,customer:decodeURIComponent(network[2]),fetchPage:params=>api(network[1]+'/inventory-page/'+network[2]+'?'+params)});}
  }
  const {signal}=requests;
  const result=await fetch('https://api.cveharbor.com/v1/team/'+path,{signal,method,credentials:'include',cache:'no-store',
    headers:payload?{'Content-Type':'application/json'}:{},body:payload?JSON.stringify(payload):undefined});
  const data=await result.json().catch(()=>({}));
  signal.throwIfAborted();
  if(!result.ok){const error=new Error(data.error||'Team access is temporarily unavailable.');error.status=result.status;throw error;}
  return data;
}
export const orgPath=id=>'organizations/'+encodeURIComponent(id);
export const workspaceLink=id=>'/workspace/?team='+encodeURIComponent(id);

export async function switchAccount(){
  const result=await fetch('https://api.cveharbor.com/v1/auth/logout',{method:'POST',credentials:'include'});
  if(!result.ok)throw Error('Sign out failed. Try again.');
  location.reload();
}

export function accountIdentity(email){
  const identity=element('span','','harbor-identity');
  const parts=email.split('@')[0].split(/[._+-]+/).filter(Boolean);
  const initials=parts.length>1?parts[0][0]+parts[1][0]:email.slice(0,2);
  const avatar=element('span',initials.toUpperCase(),'harbor-avatar');
  avatar.setAttribute('aria-hidden','true');
  identity.append(avatar,element('span',email));
  return identity;
}
