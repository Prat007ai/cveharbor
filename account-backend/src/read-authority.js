// One fresh primary snapshot for an audited read request's hold and identity.
// Results belong to the exact Request and request-local read capability only.
// Mutations and every subsequent request still perform their own current check.
const checked=new WeakMap();
const sessionSql='SELECT users.id,users.email,sessions.id AS sid FROM sessions JOIN users ON users.id=sessions.user_id JOIN user_totp ON user_totp.user_id=users.id AND user_totp.enabled=1 WHERE sessions.token_hash=? AND sessions.expires_at>?';
const token=req=>(req.headers.get('cookie')||'').split(';').map(x=>x.trim()).find(x=>x.startsWith('cvh_session='))?.slice(12)||'';
const valid=value=>/^[a-f0-9]{64}$/.test(value);
async function hash(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value)))].map(x=>x.toString(16).padStart(2,'0')).join('');}
const user=row=>row?.id&&row.expires_at>Math.floor(Date.now()/1000)?{id:row.id,email:row.email,sid:row.sid}:null;
export async function readAuthority(req,env){
 const value=token(req);
 const sql='SELECT control.write_hold,control.revision,identity.* FROM operations_control control LEFT JOIN ('+sessionSql.replace('sessions.id AS sid','sessions.id AS sid,sessions.expires_at')+') identity ON 1=1 WHERE control.id=1';
 const row=valid(value)?await env.DB.prepare(sql).bind(await hash(value),Math.floor(Date.now()/1000)).first():await env.DB.prepare('SELECT write_hold,revision FROM operations_control WHERE id=1').first();
 if(!row)throw Error('Recovery control row missing');
 checked.set(env.DB,{req,value,row});
 return {write_hold:row.write_hold,revision:row.revision};
}
export async function readCurrentUser(req,env){
 const value=token(req);if(!valid(value))return null;
 const current=checked.get(env.DB);
 if(current?.req===req&&current.value===value)return user(current.row);
 return env.DB.prepare(sessionSql).bind(await hash(value),Math.floor(Date.now()/1000)).first();
}
