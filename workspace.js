(() => {
  'use strict';
  const $=id=>document.getElementById(id);
  const root=$('securityWorkspace');
  if(!root)return;
  const src=window.CVEHARBOR_DATA||{};
  const catalog=window.CVEHARBOR_CATALOG||{};
  const threats=window.CVEHARBOR_THREATS||{};
  const cats=(catalog.categories?.length?catalog.categories:src.categories)||[];
  const records=new Map();
  for(const item of [...(catalog.advisories||[]),...(src.advisories||[])]) {
    if(!item?.id)continue;
    const prior=records.get(item.id);
    records.set(item.id,prior?{...item,
      categories:[...new Set([...(prior.categories||[]),...(item.categories||[])])],
      known_exploited:!!(prior.known_exploited||item.known_exploited)
    }:item);
  }
  const advisories=[...records.values()];
  const key='cveharbor.stack.v1';
  let saved=[];
  try {
    const raw=JSON.parse(localStorage.getItem(key)||'[]');
    if(Array.isArray(raw))saved=raw.filter(x=>cats.some(c=>c.name===x)).slice(0,38);
  } catch (_) {saved=[];}
  const make=(tag,cls,value)=>{const node=document.createElement(tag);if(cls)node.className=cls;if(value!==undefined)node.textContent=String(value);return node;};
  const lookup=$('securityLookup');
  const output=$('securityLookupResults');
  const stackList=$('stackTechnologyList');
  const stackResults=$('stackAdvisories');
  const stackSummary=$('stackSummary');
  const stackCount=$('stackCount');
  const sourceNames=new Map((threats.indicators||[]).map(x=>[x.ip,x]));
  const severityWeight={critical:0,high:1,medium:2,low:3,bulletin:4};
  const priority=(a,b)=>Number(!!b.known_exploited)-Number(!!a.known_exploited)
    ||(severityWeight[a.severity]??5)-(severityWeight[b.severity]??5)
    ||String(b.published||'').localeCompare(String(a.published||''));
  const fmt=s=>/^\d{4}-\d{2}-\d{2}/.test(s||'')?s.slice(0,10):'Unknown publication date';
  function persist() {
    try {localStorage.setItem(key,JSON.stringify(saved));}
    catch (_) {$('stackStorageNote').textContent='Browser storage is unavailable. Selections last only for this page session.';}
  }
  function itemRow(item){
    const row=make('article','workspace-result');
    const head=make('div','workspace-result-header');
    const title=make('strong','',item.title||item.id);
    const severity=make('span','workspace-severity '+(item.severity||'bulletin'),String(item.severity||'unrated').toUpperCase());
    head.append(title,severity);row.append(head);
    row.append(make('p','',item.id+' · Published '+fmt(item.published)
      +' · '+(item.categories||[]).join(', ')));
    if(item.known_exploited)row.append(make('strong','workspace-kev','CISA KEV listed'));
    if(typeof item.epss==='number')row.append(make('p','workspace-epss','FIRST EPSS: '+(item.epss*100).toFixed(2)+'% predicted 30 day exploitation probability ('+(item.epss_as_of||'date unavailable')+')'));
    // Show the full indexed advisory in CVEHarbor instead of leaving the site.
    // The original vendor and indexed references remain available inside the dialog.
    const button=make('button','workspace-link workspace-detail-trigger','View details & sources');
    button.type='button';
    button.setAttribute('aria-haspopup','dialog');
    button.setAttribute('aria-controls','detailDialog');
    button.addEventListener('click',()=>window.dispatchEvent(
      new CustomEvent('cveharbor:review-advisory',{detail:{id:item.id}})
    ));
    row.append(button);
    return row;
  }
  function renderStack(){
    stackList.replaceChildren();
    for(const c of cats){
      const label=make('label','workspace-checkbox');
      const checkbox=document.createElement('input');checkbox.type='checkbox';
      checkbox.checked=saved.includes(c.name);
      checkbox.addEventListener('change',()=>{
        saved=checkbox.checked?[...new Set([...saved,c.name])]:saved.filter(x=>x!==c.name);
        saveSelection();
      });
      label.append(checkbox,make('span','',c.name));stackList.append(label);
    }
    const rows=advisories.filter(x=>(x.categories||[]).some(c=>saved.includes(c))).sort(priority);
    const latest=rows.filter(x=>/^\d{4}-\d{2}-\d{2}/.test(x.published||'')).sort((a,b)=>String(b.published).localeCompare(String(a.published)));
    stackCount.textContent=saved.length+' technologies selected';
    stackSummary.textContent=saved.length
      ? rows.length+' indexed matches · '+rows.filter(x=>x.known_exploited).length+' KEV listed · Most recent publication '+(latest.length?fmt(latest[0].published):'unknown')
      : 'Select the technologies you manage to see a filtered view of indexed advisories.';
    stackResults.replaceChildren();
    if(!saved.length)return;
    for(const item of rows.slice(0,8))stackResults.append(itemRow(item));
    if(rows.length>8)stackResults.append(make('p','workspace-note','Showing the eight highest priority indexed matches. Use the full advisory search to review more.'));
  }
  let lookupTimer=null,lookupAbort=null,lookupVersion=0;
  const validId=/^CVE-\d{4}-\d{4,10}$/i;
  function makeOfficialLinks(row,id,references=[]){
    const wrap=make('div','workspace-live-links');
    const links=[
      {label:'Open CVE Program record',url:'https://www.cve.org/CVERecord?id='+id},
      {label:'View NVD entry',url:'https://nvd.nist.gov/vuln/detail/'+id},
      ...(Array.isArray(references)?references.slice(0,4):[])
    ];
    for(const source of links){
      try {
        const u=new URL(source.url);
        if(u.protocol!=='https:')continue;
        const link=make('a','workspace-link',source.label||u.hostname);
        link.href=u.href;link.target='_blank';link.rel='noopener noreferrer';
        wrap.append(link);
      }catch(_){}
    }
    row.append(wrap);
  }
  function showExactStatus(id,message,isError=false){
    output.replaceChildren();
    const row=make('article','workspace-result workspace-live');
    row.append(make('strong','',id));
    row.append(make('p',isError?'workspace-error':'workspace-note',message));
    makeOfficialLinks(row,id);
    output.append(row);
  }
  function showExternalCve(record){
    output.replaceChildren();
    const card=make('article','workspace-result workspace-live');
    const head=make('div','workspace-result-header');
    head.append(make('strong','',record.title||record.id));
    const label=String(record.severity||'unrated').toLowerCase();
    head.append(make('span','workspace-severity '+label,label.toUpperCase()));
    card.append(head);
    card.append(make('p','workspace-live-id',record.id+' · Source: '+(record.source||'CVE Program')));
    const meta=[
      record.published?'Published '+String(record.published).slice(0,10):'',
      record.updated?'Updated '+String(record.updated).slice(0,10):'',
      record.cvss!==null&&record.cvss!==undefined?'CVSS '+record.cvss+(record.cvssVersion?' (v'+record.cvssVersion+')':''):'',
      record.cwe||''
    ].filter(Boolean);
    if(meta.length)card.append(make('p','workspace-note',meta.join(' · ')));
    if(record.description)card.append(make('p','workspace-live-description',record.description));
    const affected=Array.isArray(record.affected)?record.affected:[];
    if(affected.length){
      card.append(make('strong','workspace-live-heading','Reported affected products'));
      card.append(make('p','',affected.join(' · ')));
    }
    if(record.remediation){
      card.append(make('strong','workspace-live-heading','Vendor remediation information'));
      card.append(make('p','',record.remediation));
    }
    card.append(make('p','workspace-note','Live record from the CVE Program. Check affected versions and prerequisites before acting. This lookup does not scan your systems.'));
    makeOfficialLinks(card,record.id,record.references);
    output.append(card);
  }
  async function runExactLookup(id,version){
    const controller=new AbortController();
    lookupAbort=controller;
    try{
      const res=await fetch('https://api.cveharbor.com/v1/cve/'+id,{
        method:'GET',credentials:'omit',headers:{Accept:'application/json'},signal:controller.signal
      });
      let data={};try{data=await res.json()}catch(_){}
      if(version!==lookupVersion||controller.signal.aborted)return;
      if(res.ok&&data.status==='published'&&data.id===id)showExternalCve(data);
      else if(res.ok&&data.status==='rejected')showExactStatus(id,
        data.message||'The CVE Program rejected this identifier. It is not an active vulnerability record.');
      else if(res.status===404)showExactStatus(id,
        'No published record was found in the official CVE sources. The ID may be reserved, not yet published, or unavailable.');
      else showExactStatus(id,
        'The official CVE lookup is temporarily unavailable. The vulnerability may still exist. Use the CVE Program or NVD link below.',true);
    }catch(error){
      if(version!==lookupVersion||controller.signal.aborted)return;
      showExactStatus(id,'The live lookup could not connect. Try again or open the official CVE record below.',true);
    }finally{
      if(lookupAbort===controller)lookupAbort=null;
    }
  }
  function renderLookup(){
    const version=++lookupVersion;
    if(lookupTimer!==null){clearTimeout(lookupTimer);lookupTimer=null;}
    if(lookupAbort){lookupAbort.abort();lookupAbort=null;}
    const q=lookup.value.trim().toLowerCase();
    output.replaceChildren();
    if(q.length<2){
      output.append(make('p','workspace-note','Search indexed advisories or enter an exact CVE ID to look up the official public record.'));return;
    }
    const id=q.toUpperCase();
    const exact=validId.test(id);
    const found=advisories.filter(item=>[item.id,item.title,item.summary,item.affected,...(item.categories||[])].some(v=>String(v||'').toLowerCase().includes(q))).sort(priority).slice(0,12);
    const ips=(threats.indicators||[]).filter(x=>x.ip.includes(q)).slice(0,6);
    for(const entry of ips){
      const row=make('article','workspace-result');
      row.append(make('strong','',entry.ip),make('p','',entry.activity+' · '+entry.source));
      row.append(make('p','workspace-note','Source reported. Independently validate before blocking. Source last-seen time unavailable.'));
      output.append(row);
    }
    for(const record of found)output.append(itemRow(record));
    if(exact&&!found.some(item=>String(item.id).toUpperCase()===id)){
      const row=make('article','workspace-result workspace-live');
      row.append(make('strong','',id));
      row.append(make('p','workspace-note','Not in the local index. Checking the official CVE Program record...'));
      output.append(row);
      lookupTimer=setTimeout(()=>{lookupTimer=null;runExactLookup(id,version);},320);
    }else if(!found.length&&!ips.length){
      output.append(make('p','workspace-note','No matching records in the current indexed snapshot. For older or unindexed vulnerabilities, search by their complete CVE ID.'));
    }
  }
  function saveSelection(){
    persist();
    renderStack();
    window.dispatchEvent(new CustomEvent('cveharbor:stack-changed',{detail:{technologies:[...saved]}}));
  }
  window.CVEHARBOR_WATCHLIST={
    getSelected:()=>[...saved],
    loadFromCloud:values=>{
      const next=Array.isArray(values)?values:[];
      saved=[...new Set(next.filter(x=>typeof x==='string'&&cats.some(c=>c.name===x)))].slice(0,38);
      persist();renderStack();
    }
  };
  $('stackClear').addEventListener('click',()=>{
    if(!saved.length)return;
    if(!window.confirm('Clear all '+saved.length+' technologies? If this browser is connected to your account watchlist, the same change will be saved for email reports.'))return;
    saved=[];saveSelection();
  });
  lookup.addEventListener('input',renderLookup);
  renderStack();renderLookup();
})();
