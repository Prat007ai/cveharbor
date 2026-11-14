// Isolated-test experiment only. No production imports or durable storage.
// Concurrent requests share one fresh primary SELECT, never a cached decision.
export const AUTHORITY_SQL='SELECT control.write_hold,control.revision,identity.* FROM operations_control control LEFT JOIN (SELECT users.id,users.email,sessions.id AS sid,sessions.expires_at FROM sessions JOIN users ON users.id=sessions.user_id JOIN user_totp ON user_totp.user_id=users.id AND user_totp.enabled=1 WHERE sessions.token_hash=? AND sessions.expires_at>?) identity ON 1=1 WHERE control.id=1';
export const BATCH_SQL=`SELECT inputs.key AS request_index,control.write_hold,control.revision,
 CASE WHEN user_totp.enabled=1 THEN users.id END AS id,users.email,sessions.id AS sid,sessions.expires_at
 FROM operations_control control CROSS JOIN json_each(?) inputs
 LEFT JOIN sessions ON sessions.token_hash=inputs.value AND sessions.expires_at>?
 LEFT JOIN users ON users.id=sessions.user_id
 LEFT JOIN user_totp ON user_totp.user_id=users.id AND user_totp.enabled=1
 WHERE control.id=1`;
const failure=(transient=false)=>Response.json({error:'Fresh authority unavailable',transient},{status:503});
export class CapacityAuthorityCoordinator {
 constructor(state,env){this.env=env;this.pending=[];this.timer=null;this.running=false;}
 async fetch(req){
  if(req.method!=='POST'||new URL(req.url).pathname!=='/check')return new Response('',{status:404});
  if(Number(req.headers.get('Content-Length'))>256)return new Response('',{status:413});
  const raw=await req.text();if(raw.length>256)return new Response('',{status:413});
  let input;try{input=JSON.parse(raw);}catch{return new Response('',{status:400});}
  if(!input||Object.keys(input).join(',')!=='token_hash'||! /^[a-f0-9]{64}$/.test(input.token_hash))return new Response('',{status:400});
  if(this.pending.length>=256)return failure();
  return new Promise(resolve=>{
   this.pending.push({hash:input.token_hash,resolve});
   if(!this.running&&!this.timer)this.timer=setTimeout(()=>this.flush(),10);
  });
 }
 async flush(){
  this.timer=null;if(this.running||!this.pending.length)return;
  this.running=true;const batch=this.pending.splice(0,128);
  try{
   const session=this.env.DB.withSession('first-primary');
   const result=await session.prepare(BATCH_SQL).bind(JSON.stringify(batch.map(x=>x.hash)),Math.floor(Date.now()/1000)).all();
   const bookmark=session.getBookmark(),rows=result.results||[];
   if(!bookmark||rows.length!==batch.length)throw Error('Incomplete fresh check');
   const positions=new Set(rows.map(r=>Number(r.request_index)));
   if(positions.size!==batch.length||batch.some((_,i)=>!positions.has(i)))throw Error('Invalid result positions');
   const byIndex=new Map(rows.map(({request_index,...row})=>[Number(request_index),row]));
   batch.forEach((item,i)=>item.resolve(Response.json({row:byIndex.get(i),bookmark,
    // Exactly one logical request accounts for the shared native query.
    meta:i===0?result.meta||{}:{rows_read:0,rows_written:0,duration:0},native_queries:Number(i===0),batch_size:batch.length},
    {headers:{'Cache-Control':'no-store'}})));
  }catch(error){const transient=/overload|too many resources consumed|10 second window|queued for too long|transient issue|object.*reset|7500/i.test([error?.message,error?.cause?.message].join(' '));for(const item of batch)item.resolve(failure(transient));}
  finally{this.running=false;if(this.pending.length&&!this.timer)this.timer=setTimeout(()=>this.flush(),10);}
 }
}

// Replace only the exact audited authority SELECT. All data reads, mutations,
// maintenance-only checks and other queries retain the native D1 behavior.
export function coordinatedAuthority(db,stub){
 return new Proxy(db,{get(target,key){
  if(key!=='withSession'){const value=target[key];return typeof value==='function'?value.bind(target):value;}
  return constraint=>{
   const session=target.withSession(constraint);let checkedBookmark=null;
   return new Proxy(session,{get(native,name){
    if(name==='getBookmark')return()=>checkedBookmark||native.getBookmark();
    if(name!=='prepare'){const value=native[name];return typeof value==='function'?value.bind(native):value;}
    return sql=>{
     if(constraint!=='first-primary'||sql!==AUTHORITY_SQL)return native.prepare(sql);
     const make=args=>({bind:(...values)=>make(values),async all(){
      if(args.length!==2||! /^[a-f0-9]{64}$/.test(args[0])||!Number.isSafeInteger(args[1]))throw Error('Invalid authority input');
      const response=await stub.fetch(new Request('https://capacity-authority.invalid/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({token_hash:args[0]})}));
      const result=await response.json();
      if(!response.ok)throw Error(result.transient?'D1 DB is overloaded':'Fresh authority unavailable');
      if(!result.row||typeof result.bookmark!=='string'||!result.bookmark)throw Error('Incomplete authority result');
      checkedBookmark=result.bookmark;
      return {success:true,results:[result.row],meta:{...result.meta,capacity_authority_native_queries:result.native_queries,capacity_authority_batch_size:result.batch_size}};
     },async first(column){const row=(await this.all()).results[0];return column===undefined?row:row[column];}});
     return make([]);
    };
   }});
  };
 }});
}

// The deployed test Worker has no public handler for the coordinator.
export default {fetch(){return new Response('',{status:404});}};
