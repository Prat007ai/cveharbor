(() => {
'use strict';
const $=id=>document.getElementById(id);
if(!$('operationsCentre'))return;
const key='cveharbor.remediation.v1',src=window.CVEHARBOR_DATA||{},base=window.CVEHARBOR_CATALOG||{},threats=window.CVEHARBOR_THREATS||{};
const elem=(tag,cls,value)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(value!==undefined)x.textContent=String(value);return x;};
const valid=id=>/^CVE-\d{4}-\d{4,}$/i.test(id);
const records=new Map();
for(const x of [...(base.advisories||[]),...(src.advisories||[])])if(x?.id)records.set(x.id,x);
let tasks=[];try{const a=JSON.parse(localStorage.getItem(key)||'[]');if(Array.isArray(a))tasks=a.filter(x=>x&&valid(x.id)).slice(0,250)}catch(_){}
function save(){try{localStorage.setItem(key,JSON.stringify(tasks));$('remediationStorage').textContent='Stored locally in this browser. Export for backup.'}catch(_){$('remediationStorage').textContent='Storage unavailable. Export before leaving.'}}
function render(){
 const target=$('remediationRows');target.replaceChildren();$('remediationCount').textContent=tasks.length+' tracked';
 if(!tasks.length){target.append(elem('p','ops-note','No CVEs tracked yet. Add an ID below.'));return}
 for(const task of tasks){
  const row=elem('article','ops-result'),head=elem('div','ops-result-top');
  head.append(elem('strong','',task.id),elem('span','ops-tag',task.status));
  const remove=elem('button','ops-remove','Remove');remove.type='button';
  remove.addEventListener('click',()=>{tasks=tasks.filter(x=>x.id!==task.id);save();render()});head.append(remove);row.append(head);
  row.append(elem('p','', 'Owner: '+(task.owner||'Unassigned')+' · Target: '+(task.due||'None')+' · Updated: '+(task.updated||'Unknown')));
  if(task.notes)row.append(elem('p','',task.notes));
  if(records.has(task.id))row.append(elem('p','ops-note',records.get(task.id).title||'Indexed vulnerability'));
  target.append(row);
 }
}
$('remediationForm').addEventListener('submit',event=>{
 event.preventDefault();const id=$('remediationCve').value.trim().toUpperCase();
 if(!valid(id)){$('remediationMessage').textContent='Enter a valid CVE ID, such as CVE-2026-12345.';return}
 const item={id,status:$('remediationStatus').value,owner:$('remediationOwner').value.trim().slice(0,100),
 due:$('remediationDue').value,notes:$('remediationNotes').value.trim().slice(0,1200),updated:new Date().toISOString().slice(0,10)};
 tasks=[item,...tasks.filter(x=>x.id!==id)].slice(0,250);save();render();$('remediationMessage').textContent=id+' saved locally.';
});
$('remediationExport').addEventListener('click',()=>{
 const csv=[['CVE','Status','Owner','Due','Notes','Updated'],...tasks.map(x=>[x.id,x.status,x.owner,x.due,x.notes,x.updated])]
 .map(fields=>fields.map(s=>'"'+String(s||'').replaceAll('"','""')+'"').join(',')).join('\r\n');
 const link=elem('a');link.href=URL.createObjectURL(new Blob([csv],{type:'text/csv;charset=utf-8'}));link.download='cveharbor-remediation.csv';
 document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(link.href),1000);
});
render();
const ecos=$('versionEcosystem');for(const name of ['npm','PyPI','Go','Maven','NuGet','RubyGems','crates.io','Packagist']){const option=elem('option','',name);option.value=name;ecos.append(option)}
$('versionForm').addEventListener('submit',async event=>{
 event.preventDefault();const name=$('versionPackage').value.trim(),version=$('versionValue').value.trim(),result=$('versionResult');
 result.replaceChildren();if(!name||!version||name.length>160||version.length>80){result.append(elem('p','ops-note','Enter a package name and exact version.'));return}
 $('versionCheck').disabled=true;result.append(elem('p','ops-note','Checking OSV for affected package versions...'));
 try{
  const response=await fetch('https://api.osv.dev/v1/query',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({package:{name,ecosystem:ecos.value},version})});
  if(!response.ok)throw Error('OSV HTTP '+response.status);
  const data=await response.json(),findings=Array.isArray(data.vulns)?data.vulns:[];
  result.replaceChildren();result.append(elem('strong','',findings.length?findings.length+' OSV vulnerability records returned':'No matching OSV records returned'));
  result.append(elem('p','ops-note',findings.length?'Confirm affected ranges and patch details against primary sources.':'No results does not prove the version secure or supported. OSV coverage may be incomplete.'));
  for(const f of findings.slice(0,25)){
   const row=elem('div','ops-result');row.append(elem('strong','',f.id||'OSV advisory'),elem('p','',f.summary||'See source details.'));
   const link=elem('a','ops-link','View source');link.href='https://osv.dev/vulnerability/'+encodeURIComponent(f.id||'');link.rel='noopener noreferrer';link.target='_blank';row.append(link);result.append(row);
  }
  if(data.next_page_token)result.append(elem('p','ops-note','Further results exist. Only the first page is shown.'));
 }catch(_){result.replaceChildren(elem('p','ops-note','OSV request could not be completed. Affected status is unknown. Confirm connectivity and consult OSV directly.'))}
 finally{$('versionCheck').disabled=false}
});
const snapshot=window.CVEHARBOR_LIFECYCLE||{},cycles=Array.isArray(snapshot.cycles)?snapshot.cycles:[];
$('lifecycleStatus').textContent=cycles.length?'Lifecycle snapshot: '+(snapshot.checked_at||'date unavailable')+'. Verify dates with vendors.':'Lifecycle feed unavailable. Use official vendor references below.';
for(const entry of cycles){
 const row=elem('article','ops-result'),header=elem('div','ops-result-top');
 header.append(elem('strong','',entry.product+' '+entry.cycle),elem('span','ops-tag',entry.eol===true?'EOL':entry.eol===false?'Supported per source':'Verify'));
 row.append(header,elem('p','', 'End of life: '+(entry.eol_date||'Not confirmed')+' · Support: '+(entry.support_date||'Not confirmed')));
 const a=elem('a','ops-link','Check lifecycle source');a.href=entry.url;a.target='_blank';a.rel='noopener noreferrer';row.append(a);$('lifecycleRows').append(row);
}
$('firewallObservedCount').textContent=(threats.indicators||[]).length+' reported IP indicators in the current snapshot';
for(const item of [['FortiGate initial','fortigate-suspicious-ip-initial.txt'],['FortiGate incremental','fortigate-suspicious-ip-incremental.txt'],['Sophos initial','sophos-suspicious-ip-initial.txt'],['Sophos incremental','sophos-suspicious-ip-incremental.txt']]){
 const a=elem('a','ops-download',item[0]);a.href=item[1];a.download=item[1];$('firewallDownloads').append(a);
}
})();