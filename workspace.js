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
    const sources=(item.sources||[]).filter(x=>/^https:\/\//.test(x.url||''));
    if(sources.length){
      const link=make('a','workspace-link','Official / indexed source ↗');
      link.href=sources[0].url;link.target='_blank';link.rel='noopener noreferrer';row.append(link);
    }
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
        persist();renderStack();
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
  function renderLookup(){
    const q=lookup.value.trim().toLowerCase();
    output.replaceChildren();
    if(q.length<2){
      output.append(make('p','workspace-note','Enter at least two characters to search indexed CVEs, packages, products, or IP indicators.'));return;
    }
    const found=advisories.filter(item=>[item.id,item.title,item.summary,item.affected,...(item.categories||[])].some(v=>String(v||'').toLowerCase().includes(q))).sort(priority).slice(0,12);
    const ips=(threats.indicators||[]).filter(x=>x.ip.includes(q)).slice(0,6);
    for(const entry of ips){
      const row=make('article','workspace-result');
      row.append(make('strong','',entry.ip),make('p','',entry.activity+' · '+entry.source));
      row.append(make('p','workspace-note','Source reported. Independently validate before blocking. Source last-seen time unavailable.'));
      output.append(row);
    }
    for(const record of found)output.append(itemRow(record));
    if(!found.length&&!ips.length)output.append(make('p','workspace-note','No matching records in the indexed snapshot. This does not establish that a product or address is safe.'));
  }
  $('stackClear').addEventListener('click',()=>{saved=[];persist();renderStack();});
  lookup.addEventListener('input',renderLookup);
  renderStack();renderLookup();
})();
