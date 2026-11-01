// Public feed metadata only. Never cache account products, assets or findings.
// Each Worker isolate shares one bounded entry per database binding. Cold
// isolates read D1 normally; a cache miss never affects correctness.
const entries=new WeakMap();
export const PUBLIC_STATUS_TTL=30000;
export function invalidatePublicSourceStatus(env){entries.delete(env.DB);}
export async function publicSourceStatus(env,now,load){
 let entry=entries.get(env.DB);
 if(!entry||now<entry.started||now>=entry.expires){
  entry={started:now,expires:now+PUBLIC_STATUS_TTL};
  entry.promise=Promise.resolve().then(load).then(JSON.stringify);
  entries.set(env.DB,entry);
 }
 try{return JSON.parse(await entry.promise);}
 catch(error){if(entries.get(env.DB)===entry)entries.delete(env.DB);throw error;}
}
