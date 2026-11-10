import {DatabaseSync} from 'node:sqlite';
import fs from 'node:fs';
import {hashToken} from '../../src/assignment-acknowledgement.js';
export class AssignmentDB{
 constructor(){this.sql=new DatabaseSync(':memory:');this.queries=[];this.sql.exec('PRAGMA foreign_keys=ON');for(const file of ['schema.sql','totp-schema.sql','remediation-schema.sql','migrations/0024_assignment_acknowledgements.sql','migrations/0025_assignment_fyi.sql'])this.sql.exec(fs.readFileSync(new URL('../../'+file,import.meta.url),'utf8'));}
 prepare(sql){const db=this;const make=args=>({bind:(...values)=>make(values),async first(){db.queries.push(sql);return db.sql.prepare(sql).get(...args)||null},async all(){db.queries.push(sql);return {results:db.sql.prepare(sql).all(...args)}},async run(){db.queries.push(sql);const statement=db.sql.prepare(sql);if(statement.columns().length)return {results:statement.all(...args)};const r=statement.run(...args);return {meta:{changes:Number(r.changes)}}}});return make([]);}
 async batch(statements){this.sql.exec('BEGIN');try{const results=[];for(const s of statements)results.push(await s.run());this.sql.exec('COMMIT');return results}catch(error){this.sql.exec('ROLLBACK');throw error}}
}
export const fixtureCve='CVE-2026-81000';
export const fixtureRecord={dataType:'CVE_RECORD',cveMetadata:{cveId:fixtureCve,state:'PUBLISHED',datePublished:'2026-10-13T10:00:00Z',dateUpdated:'2026-10-31T10:00:00Z'},containers:{cna:{title:'Synthetic vulnerability for review testing',descriptions:[{lang:'en',value:'Synthetic public advisory. Not a real exposure finding.'}],affected:[{vendor:'Example',product:'Review service',versions:[{version:'1.0',lessThan:'1.2',status:'affected'}]}],metrics:[{cvssV3_1:{baseScore:8.8,baseSeverity:'HIGH'}}],problemTypes:[{descriptions:[{cweId:'CWE-79'}]}],references:[{url:'https://msrc.microsoft.com/update-guide/vulnerability/'+fixtureCve,name:'Official advisory'},{url:'https://untrusted.example/private',name:'Must be excluded'}]}}};
export async function assignmentFixture(){
 const DB=new AssignmentDB(),emails=[],session='a'.repeat(64),secondSession='b'.repeat(64),time=Math.floor(Date.now()/1000);
 for(const [id,email,token] of [['a','sender@example.test',session],['b','other@example.test',secondSession]]){
  DB.sql.prepare('INSERT INTO users(id,email) VALUES(?,?)').run(id,email);
  DB.sql.prepare('INSERT INTO user_totp(user_id,encrypted_secret,enabled,last_counter,created_at) VALUES(?,?,1,-1,1)').run(id,'test-only');
  DB.sql.prepare('INSERT INTO sessions(id,user_id,token_hash,expires_at,created_at) VALUES(?,?,?,?,1)').run('session-'+id,id,await hashToken(token),time+3600);
 }
 DB.sql.prepare("INSERT INTO remediations(user_id,cve_id,status,owner,due,notes,updated_at) VALUES('a',?,'Investigating','Review owner','2026-11-20','Private customer note NEVER public','2026-11-01')").run(fixtureCve);
 const env={DB,EMAIL_FROM:'alerts@cveharbor.com',SMTP2GO_API_KEY:'test-only',ASSIGNMENT_EMAIL_ENABLED:'true',ASSIGNMENT_ACK_ENABLED:'true',ASSIGNMENT_ACK_RATE_LIMITER:{limit:async()=>({success:true})}};
 let failMail=false;
 const fetcher=async(url,options={})=>{
  if(String(url).startsWith('https://cveawg.mitre.org/api/cve/')||String(url).startsWith('https://raw.githubusercontent.com/CVEProject/'))return new Response(JSON.stringify(fixtureRecord),{headers:{'Content-Type':'application/json'}});
  if(url==='https://api.smtp2go.com/v3/email/send'){const data=JSON.parse(options.body);emails.push(data);return new Response(JSON.stringify({data:{succeeded:failMail?0:1,failed:failMail?1:0,email_id:'fixture-provider-id'}}));}
  throw Error('Unexpected external request blocked');
 };
 const request=(path,method='GET',data,account='a')=>new Request('https://api.cveharbor.com/v1'+path,{method,headers:{Origin:'https://cveharbor.com',...(account?{Cookie:'cvh_session='+(account==='a'?session:secondSession)}:{}),...(data?{'Content-Type':'application/json'}:{})},...(data?{body:JSON.stringify(data)}:{})});
 const link=()=>emails.at(-1)?.text_body.match(/https:\/\/api\.cveharbor\.com\/v1\/acknowledge\/[a-f0-9]{64}/)?.[0];
 return {DB,env,emails,request,fetcher,link,setMailFailed:value=>failMail=value};
}
