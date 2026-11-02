// Synthetic private records for automated review only; never copied into public/.
export function remediationFixture(){
 let authenticated=true,failed=false;
 const statuses=['Open','Investigating','Remediated','Accepted Risk','Not Applicable','Open'];
 let rows=statuses.map((status,i)=>({id:'CVE-2026-'+(81000+i),status,owner:i===5?'':'Review engineer '+(i+1),due:i%2?'':'2026-11-20',notes:'Review fixture — no production records.',updated:'2026-11-0'+(6-i)+'T12:00:00Z'}));
 const seen=[];
 async function request(raw,method='GET',payload){
  const path=new URL(raw).pathname;seen.push({path,method,payload});const reply=(body,status=200)=>({body,status});
  if(path==='/v1/me')return reply({authenticated,email:'remediation-review@example.test'},authenticated?200:401);
  if(!authenticated)return reply({error:'Sign in required'},401);
  if(path==='/v1/remediations/features')return reply({storage:'d1',version:2,assignments_available:true,assignment_email_enabled:true});
  if(path==='/v1/remediations'&&method==='GET')return failed?reply({error:'Unavailable'},503):reply({remediations:rows});
  const id=path.split('/')[3],data=typeof payload==='string'?JSON.parse(payload):payload;
  if(path.startsWith('/v1/remediations/')&&method==='PUT'){
   if(!data.owner?.trim())return reply({error:'Please select an owner.'},400);
   rows=[{...data,id,updated:'2026-11-07T12:00:00Z'},...rows.filter(r=>r.id!==id)];return reply({saved:true});
  }
  if(path.endsWith('/assign')&&method==='POST'){const row=rows.find(r=>r.id===id);if(row){row.assigned_to=data.email;row.assignment_status='sent';}return reply({assigned:true,notified:true});}
  if(path.startsWith('/v1/remediations/')&&method==='DELETE'){rows=rows.filter(r=>r.id!==id);return reply({removed:true});}
  if(path==='/v1/stack')return reply({stack:[]});
  if(path==='/v1/alerts')return reply({enabled:false});
  return reply({error:'Unknown fixture route'},404);
 }
 return {request,seen,setAuthenticated:value=>authenticated=value,setFailed:value=>failed=value,setEmpty:()=>{rows=[];}};
}
