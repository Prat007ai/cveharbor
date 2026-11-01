// Synthetic customer records for local UI tests; never load production accounts.
export function securityFixture(){
 const inventory={customers:[{id:'c1',name:'Fixture Harbor'},{id:'c2',name:'Other Customer'}],environments:[
  {id:'e1',customer_id:'c1',name:'Production',kind:'Production'},
  {id:'e2',customer_id:'c1',name:'Staging',kind:'Staging'},
  {id:'e3',customer_id:'c2',name:'Private Other',kind:'Production'}],assets:[
  {id:'a1',environment_id:'e1',name:'WEB01',asset_type:'Server',technology:'PHP',version:'8.4.1',notes:'Synthetic inventory'},
  {id:'a2',environment_id:'e2',name:'STAGE01',asset_type:'Server',technology:'PHP',version:'8.4.1'},
  {id:'a3',environment_id:'e3',name:'OTHER01',asset_type:'Server',technology:'PHP',version:'8.4.1'},
  {id:'a4',environment_id:'e1',name:'SITE01',asset_type:'Plugin',technology:'WordPress Plugin: Autoptimize',version:'3.1.0'}]};
 const advisories=[{id:'CVE-2026-12345',categories:['PHP'],title:'PHP fixture critical issue',summary:'Synthetic PHP runtime issue used for local testing.',affected:'PHP before 8.4.2',severity:'critical',published:'2026-10-24',sources:[{label:'Fixture advisory',url:'https://example.test/critical'}]},
 {id:'CVE-2026-12346',categories:['PHP'],title:'PHP fixture high issue',summary:'Synthetic PHP issue for remediation testing.',affected:'PHP before 8.4.2',severity:'high',published:'2026-10-20',sources:[{label:'Fixture advisory',url:'https://example.test/high'}]}];
 const statuses=new Map([['a1|CVE-2026-12345',{asset_id:'a1',cve_id:'CVE-2026-12345',status:'Needs Review',notes:'Retain reviewer evidence'}]]);
 const tickets=[{asset_id:'a1',cve_id:'CVE-2026-12345',ticket_number:'DEV-10'}];
 const seen=[],writes=[];
 let authenticated=true,ready=true,emailFails=false;
 async function request(url,options={}){
  const path=new URL(url).pathname.replace('/v1/',''),method=options.method||'GET';
  const data=options.body?JSON.parse(options.body):{};seen.push({path,method,data});
  const response=(body,status=200)=>({ok:status>=200&&status<300,status,json:async()=>body});
  if(path==='me')return response({authenticated,email:'fixture@example.test'},authenticated?200:401);
  if(!authenticated)return response({error:'Sign in required'},401);
  if(path==='inventory/status')return response({ready:true});
  if(path==='inventory')return response(inventory);
  if(path==='finding-statuses')return response({ready,statuses:[...statuses.values()]});
  if(path==='finding-tickets')return response({ready,append_ready:ready,tickets});
  if(path==='plugin-installation-status')return response({ready:true,statuses:[{asset_id:'a4',status:'Active'}]});
  if(path==='plugin-sources')return response({ready:true,sources:[{asset_id:'a4',vendor_url:'https://example.test/plugin'}]});
  if(path==='plugin-monitor')return response({ready:true,checks:[]});
  if(path==='customer-score-history')return response({ready:true,history:[]});
  if(path==='cvie/sync')return response({ready:true});
  if(path==='cvie')return response({ready:true,account_id:'fixture',products:[{
   id:'p1',name:'PHP',status:'ready',recent_count:0,history_count:0,
   recent_complete_at:Date.parse('2026-10-31T12:00:00Z'),history_complete_at:Date.parse('2026-10-31T12:00:00Z'),
   coverage:{kind:'product',limited:false,identities:[{label:'php / php'}],notes:['Coverage is limited to the listed source identities.']}
  }],evidence:{sources:[
   {id:'nvd',label:'NVD product history',status:'current',last_success_at:Date.parse('2026-10-31T12:00:00Z')},
   {id:'cisa_kev',label:'CISA KEV',status:'current',last_success_at:Date.parse('2026-10-31T12:00:00Z')},
   {id:'cve_program',label:'CVE Program / original disclosures',status:'catching_up',pending_records:9999}]}});
  if(path==='cvie/advisories')return response({account_id:'fixture',advisories:[],next:null});
  if(path.startsWith('finding-statuses/')&&method==='PUT'){
   const [,asset_id,cve_id]=path.split('/');writes.push({path,...data});statuses.set(asset_id+'|'+cve_id,{asset_id,cve_id,...data});return response({saved:true});
  }
  if(path.startsWith('finding-tickets/')&&method==='POST'){
   const [,asset_id,cve_id]=path.split('/');writes.push({path,...data});tickets.push({asset_id,cve_id,...data});return response({saved:true});
  }
  if(path==='customer-report-email'&&method==='POST'){writes.push({path,...data});return response(emailFails?{error:'Fixture email rejected'}:{sent:true},emailFails?503:200)}
  return response({error:'Unexpected fixture route '+path},404);
 }
 return {inventory,advisories,statuses,tickets,seen,writes,request,setAuthenticated:v=>authenticated=v,setReady:v=>ready=v,setEmailFails:v=>emailFails=v};
}
