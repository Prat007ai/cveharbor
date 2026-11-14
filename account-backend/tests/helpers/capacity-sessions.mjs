// Local SQLite approximation of D1 version bookmarks. No replica or cloud
// capacity claim: real Cloudflare routing is measured by the protected job.
export function capacitySessionBinding(fixture){
 const native=new WeakMap();
 return {...fixture.DB,withSession(constraint){
  let bookmark=constraint?.startsWith('first-')?null:constraint;
  const advance=()=>{bookmark=String(fixture.sql.prepare('SELECT total_changes() n').get().n).padStart(16,'0');};
  const wrap=statement=>{const proxy={bind:(...args)=>wrap(statement.bind(...args))};
   for(const method of ['first','all','run'])proxy[method]=async(...args)=>{const value=await statement[method](...args);advance();return value;};
   native.set(proxy,statement);return proxy;};
  return {prepare:sql=>wrap(fixture.DB.prepare(sql)),getBookmark:()=>bookmark,batch:async rows=>{const value=await fixture.DB.batch(rows.map(s=>native.get(s)));advance();return value;}};
 }};
}
