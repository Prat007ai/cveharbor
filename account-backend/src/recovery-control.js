import {inventoryReadDatabase} from './inventory-read-db.js';
import {dashboardReadDatabase,dashboardReadRequest} from './dashboard-read-db.js';
import {publicSourceCacheKey} from './public-source-status-cache.js';
// Recovery is fail-closed when configured. State is read on every entry, never cached.
export async function recoveryState(env){
 try{
  const row=await env.DB.prepare('SELECT write_hold,revision FROM operations_control WHERE id=1').first();
  if(!row)throw Error('Recovery control row missing');
  return row;
 }catch(error){
  if(env.RECOVERY_CONTROL_REQUIRED==='true')throw error;
  // Compatibility only for schemas preceding this release, not production config.
  const exists=await env.DB?.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='operations_control'").first();
  if(exists)throw error;
  return null;
 }
}
const unavailableResponse=error=>new Response(JSON.stringify({error}),{status:503,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Retry-After':'60','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
export const heldResponse=()=>unavailableResponse('CVEHarbor is temporarily paused for maintenance. Please retry shortly. Your records and assignment links are retained.');
const busyResponse=()=>unavailableResponse('The account service is temporarily unavailable. Please retry shortly.');
export function recoveryProtected(handler){
 async function execute(kind,input,env,ctx){
  const url=kind==='fetch'?new URL(input.url):null;
  const inventoryRead=url&&input.method==='GET'&&url.hostname!=='confirm.cveharbor.com'&&['/v1/inventory/page','/v1/inventory/status'].includes(url.pathname);
  const dashboardRead=kind==='fetch'&&dashboardReadRequest(input);
  if(inventoryRead||dashboardRead){const identity=publicSourceCacheKey(env);env={...env,CVIE_PUBLIC_CACHE_KEY:identity,DB:(inventoryRead?inventoryReadDatabase:dashboardReadDatabase)(env.DB,{cacheIdentity:identity})};}
  let state;try{state=await recoveryState(env);}catch{return kind==='fetch'?busyResponse():undefined;}
  if(state?.write_hold)return kind==='fetch'?heldResponse():undefined;
  if(inventoryRead&&state)env={...env,INVENTORY_READ_CACHE_IDENTITY:env.CVIE_PUBLIC_CACHE_KEY,INVENTORY_READ_CONTROL_REVISION:String(state.revision)};
  // These routes cannot mutate D1: enforce SELECT-only capabilities at runtime.
  // They still check the current hold and current session on every request.
  // Omit the background context and avoid creating write leases for pure reads.
  if(inventoryRead||dashboardRead)return handler.fetch(input,env,undefined);
  if(!state)return handler[kind](input,env,ctx);
  // Guest receipt/reviewer GETs remain strictly read-only; they cannot send email.
  const guestRead=url&&['GET','HEAD'].includes(input.method)&&(/^(?:\/v1)?\/acknowledge\//.test(url.pathname)||url.hostname==='confirm.cveharbor.com'&&url.pathname.startsWith('/assignment/'));
  if(guestRead)return handler.fetch(input,env,ctx);
  const lease=crypto.randomUUID();
  try{await env.DB.prepare('INSERT INTO operations_leases(id,kind) VALUES(?,?)').bind(lease,kind).run();}catch{return kind==='fetch'?busyResponse():undefined;}
  const pending=[];const tracked={waitUntil:p=>{const settled=Promise.resolve(p).then(()=>undefined,()=>{console.warn('CVEHarbor background task failed; retained delivery state must be checked before retrying.');});pending.push(settled);}};
  const drain=async()=>{while(pending.length)await Promise.all(pending.splice(0));await env.DB.prepare('DELETE FROM operations_leases WHERE id=?').bind(lease).run();};
  try{return await handler[kind](input,env,tracked);}finally{
   // The lease covers ALL background effects, including mail/provider calls.
   // A crashed worker leaves a lease behind; recovery never expires it automatically.
   if(kind==='fetch'&&ctx?.waitUntil)ctx.waitUntil(drain());else await drain();
  }
 }
 return {fetch:(req,env,ctx)=>execute('fetch',req,env,ctx),scheduled:(event,env,ctx)=>execute('scheduled',event,env,ctx)};
}
