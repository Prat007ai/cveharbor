// Synthetic records for local validation only. Not included in the public build.
export function workspaceFixture(){
 const seen=[],summary={scope:'account',inventory:{available:true,customers:2,environments:3,inventory_entries:9},remediation:{available:true,rows:[{status:'Open',count:3,overdue:1},{status:'Investigating',count:2,overdue:0},{status:'Remediated',count:4,overdue:0},{status:'Accepted Risk',count:1,overdue:0},{status:'Not Applicable',count:2,overdue:0}]},findings:{available:true,rows:[{status:'Needs Review',count:4},{status:'Fix in Progress',count:2},{status:'Fixed/Patched',count:1},{status:'Accepted Risk',count:2},{status:'Not Applicable',count:1}]},monitoring:{available:true,registered:3,enabled:2,last_checked_at:1793574000,errors:1,unchecked:0},notifications:{available:true,last_submission:{status:'sent',completed_at:1793574000,item_count:3}}};
 let authenticated=true,failed=false,empty=false;
 async function request(raw,method='GET'){const url=new URL(raw),path=url.pathname;seen.push({path,method});const reply=(body,status=200)=>({body,status});
 if(path==='/v1/me')return reply({authenticated,email:'workspace-review@example.test'},authenticated?200:401);
 if(!authenticated)return reply({error:'Sign in required'},401);
 if(path==='/v1/workspace/summary'){if(failed)return reply({error:'Unavailable'},503);if(empty)return reply({...summary,inventory:{available:true,customers:0,environments:0,inventory_entries:0},remediation:{available:true,rows:[]},findings:{available:true,rows:[]},monitoring:{available:true,registered:0},notifications:{available:true,last_submission:null}});return reply(summary);}
 if(path==='/v1/workspace/items'){if(failed)return reply({error:'Unavailable'},503);const view=url.searchParams.get('view'),offset=Number(url.searchParams.get('offset')||0),all=Array.from({length:7},(_,i)=>({id:'fixture-'+i,customer:'Review tenant',customer_id:'fixture-customer',environment:'Review environment',name:'Registered entry '+(i+1),technology:'PHP',previous_version:'8.3.0',version:'8.4.0',date:'2026-11-01T15:00:00Z',kind:'Production',cve_id:'CVE-2026-12345',status:'Needs Review'}));return reply({available:true,view,items:empty?[]:all.slice(offset,offset+5),offset,next_offset:!empty&&offset+5<all.length?offset+5:null});}
 return reply({error:'Unknown fixture route'},404);
 }
 return {seen,summary,request,setAuthenticated:v=>authenticated=v,setFailed:v=>failed=v,setEmpty:v=>empty=v};
}
