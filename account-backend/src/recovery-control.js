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
export const heldResponse=()=>new Response(JSON.stringify({error:'CVEHarbor is temporarily paused for maintenance. Please retry shortly. Your records and assignment links are retained.'}),{status:503,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Retry-After':'60','Access-Control-Allow-Origin':'https://cveharbor.com','Access-Control-Allow-Credentials':'true'}});
export function recoveryProtected(handler){
 async function execute(kind,input,env,ctx){
  let state;try{state=await recoveryState(env);}catch{return kind==='fetch'?heldResponse():undefined;}
  if(state?.write_hold)return kind==='fetch'?heldResponse():undefined;
  if(!state)return handler[kind](input,env,ctx);
  // Guest receipt/reviewer GETs remain strictly read-only; they cannot send email.
  const url=kind==='fetch'?new URL(input.url):null;
  const guestRead=url&&['GET','HEAD'].includes(input.method)&&(/^(?:\/v1)?\/acknowledge\/[a-f0-9]{64}$/.test(url.pathname)||url.hostname==='confirm.cveharbor.com'&&url.pathname.startsWith('/assignment/'));
  if(guestRead)return handler.fetch(input,env,ctx);
  const lease=crypto.randomUUID();
  try{await env.DB.prepare('INSERT INTO operations_leases(id,kind) VALUES(?,?)').bind(lease,kind).run();}catch{return kind==='fetch'?heldResponse():undefined;}
  const pending=[];const tracked={waitUntil:p=>{const settled=Promise.resolve(p).then(()=>undefined,()=>undefined);pending.push(settled);}};
  const drain=async()=>{while(pending.length)await Promise.all(pending.splice(0));await env.DB.prepare('DELETE FROM operations_leases WHERE id=?').bind(lease).run();};
  try{return await handler[kind](input,env,tracked);}finally{
   // The lease covers ALL background effects, including mail/provider calls.
   // A crashed worker leaves a lease behind; recovery never expires it automatically.
   if(kind==='fetch'&&ctx?.waitUntil)ctx.waitUntil(drain());else await drain();
  }
 }
 return {fetch:(req,env,ctx)=>execute('fetch',req,env,ctx),scheduled:(event,env,ctx)=>execute('scheduled',event,env,ctx)};
}
