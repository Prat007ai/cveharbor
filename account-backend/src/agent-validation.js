import {normalizeSnapshot} from './server-network.js';
import {WorkflowError} from './remediation-workflow.js';
export class AgentError extends WorkflowError {}
export const fail=(message,status=400)=>{throw new AgentError(message,status);};
export const now=()=>Math.floor(Date.now()/1000);
export const hash=async value=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
export const token=()=>Array.from(crypto.getRandomValues(new Uint8Array(32)),b=>b.toString(16).padStart(2,'0')).join('');
export const roles=['Web','Database','Application','Active Directory','File','Print','Remote Desktop','Other'];
export function text(value,max,label,empty=false){
 if(typeof value!=='string'||value.length>max||(!empty&&!value.trim())||/[\x00-\x1f\x7f]/.test(value))fail('Invalid '+label);
 return value.trim();
}
export function exact(value,keys){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(k=>!keys.includes(k)))fail('Unexpected upload fields');
}
export async function readBody(req,max=2097152){
 if(!/^application\/json(?:;|$)/i.test(req.headers.get('content-type')||''))fail('JSON content type required',415);
 if(req.headers.has('content-encoding'))fail('Compressed requests are not accepted',415);
 const declared=Number(req.headers.get('content-length')||0);if(declared>max)fail('Upload exceeds size limit',413);
 const reader=req.body?.getReader();if(!reader)fail('Request body required');
 const decoder=new TextDecoder('utf-8',{fatal:true});let size=0,raw='';
 try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>max){await reader.cancel();fail('Upload exceeds size limit',413);}raw+=decoder.decode(value,{stream:true});}raw+=decoder.decode();}
 catch(error){if(error instanceof AgentError)throw error;fail('Invalid request encoding');}
 try{return JSON.parse(raw);}catch{fail('Invalid JSON upload');}
}
export function snapshot(raw){
 exact(raw,['schema','sequence','request','collected_at','hostname','agent_version','complete','products','network','warnings']);
 if(raw.schema!==1||!Number.isSafeInteger(raw.sequence)||raw.sequence<1||!Number.isSafeInteger(raw.request)||raw.request<0||typeof raw.complete!=='boolean')fail('Invalid collection metadata');
 const collected=text(raw.collected_at,40,'collection time');
 if(!/^\d{4}-\d\d-\d\dT/.test(collected)||!Number.isFinite(Date.parse(collected))||Date.parse(collected)>Date.now()+600000)fail('Collection time outside accepted window');
 if(Date.parse(collected)<Date.now()-7*86400000)fail('Stored collection expired. Poll and collect fresh inventory.',409);
 const hostname=text(raw.hostname,120,'hostname'),version=text(raw.agent_version,30,'agent version');
 if(!/^1\.\d+\.\d+$/.test(version))fail('Unsupported agent version');
 if(!Array.isArray(raw.products)||raw.products.length<1||raw.products.length>10000)fail('Inventory must contain 1–10,000 software entries');
 const keys=new Set(),products=raw.products.map(p=>{
  exact(p,['name','version','details']);const name=text(p.name,120,'software name'),version=text(p.version,80,'software version',true),details=text(p.details,500,'software details',true);
  const key=JSON.stringify([name.toLowerCase(),version.toLowerCase()]);if(keys.has(key))fail('Duplicate software entry');keys.add(key);
  return {name,version,details};
 }).sort((a,b)=>a.name.localeCompare(b.name)||a.version.localeCompare(b.version));
 if(!Array.isArray(raw.warnings)||raw.warnings.length>100)fail('Invalid collection warnings');
 const warnings=raw.warnings.map(v=>text(v,250,'collection warning'));
 let network=null;if(raw.network!==null){try{network=normalizeSnapshot(raw.network);}catch{fail('Invalid network inventory');}}
 return {schema:1,sequence:raw.sequence,request:raw.request,collected_at:collected,hostname,agent_version:version,complete:raw.complete,products,network,warnings};
}
export function changes(previous,next){
 const key=p=>JSON.stringify([p.name.toLowerCase(),p.version.toLowerCase()]);
 const old=new Map((previous?.products||[]).map(p=>[key(p),p])),current=new Map(next.products.map(p=>[key(p),p]));
 return {added:next.products.filter(p=>!old.has(key(p))).map(({name,version})=>({name,version})),removed:next.complete?[...old].filter(([k])=>!current.has(k)).map(([,p])=>({name:p.name,version:p.version})):[],incomplete:!next.complete};
}
export const activeAssets=(alias='t')=>` NOT EXISTS(SELECT 1 FROM inventory_agent_assets aa WHERE aa.asset_id=${alias}.id AND aa.active=0)`;
export const agentSchemaReady=async db=>!!await db.prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='inventory_agent_assets'").first();
