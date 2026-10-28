(() => {
  'use strict';
  const state = { q: '', severity: 'all', tech: 'all' };
  const info = window.CVEHARBOR_DATA || {categories:[],advisories:[],mode:'awaiting_first_sync'};
  const items = info.advisories || [];
  const categories = info.categories || [];
  const $ = id => document.getElementById(id);
  const cveIDs = rows => [...new Set(rows.filter(x => /^CVE-\d{4}-\d+$/i.test(x.id)).map(x => x.id))];
  const text = (tag, className, content) => {const n=document.createElement(tag);if(className)n.className=className;n.textContent=content||'';return n;};
  const fmtDate = s => {if(!s||!/^\d{4}-\d{2}-\d{2}/.test(s))return 'Not available';let d=new Date(s.slice(0,10)+'T12:00:00Z');return Number.isFinite(d.getTime())?d.toLocaleDateString('en-CA',{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'}):'Not available';};
  const fmtStamp = s => {if(!s)return 'Never';let d=new Date(s);return Number.isFinite(d.getTime())?d.toLocaleString('en-CA',{dateStyle:'medium',timeStyle:'short',timeZone:'UTC'})+' UTC':'Not available';};
  const severityText=s=>({critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',bulletin:'BULLETIN'})[s]||'UNKNOWN';
  const stat=(id,num)=>{$(id).textContent=String(num);};
  stat('statTotal',cveIDs(items).length);
  stat('statCritical',cveIDs(items.filter(x=>x.severity==='critical')).length);
  stat('statHigh',cveIDs(items.filter(x=>x.severity==='high')).length);
  stat('statCategories',categories.length);
  $('year').textContent=new Date().getFullYear();
  const status=info.mode || 'awaiting_first_sync';
  const checked=info.last_checked_at, lastSuccess=info.last_successful_update;
  const lag=lastSuccess?(Date.now()-new Date(lastSuccess).getTime())/(60*60*1000):Infinity;
  let stateLabel='Awaiting first sync', headline='No live sync has completed', expl='The site taxonomy is ready, but the hourly collector has not yet populated verified source data. Zero means no indexed records, not no vulnerabilities.';
  if(status==='live'&&lag<=2.5){stateLabel='Feeds responding';headline='Sources updated';expl='Public advisory data was collected from GitHub Security Advisories, NVD and CISA KEV. Advisories describe software products, not visitor exposure.';}
  else if(status==='partial'&&lag<=2.5){stateLabel='Partial feed coverage';headline='One or more advisory sources unavailable';expl='Recent updates were retrieved from some sources. Other feeds failed and may be missing new records. Check each source below.';}
  else if(lastSuccess){stateLabel='Data may be stale';headline='Hourly refresh not confirmed';expl='The latest successful collection is older than expected or a source has failed. Consult official vendor advisories for time-sensitive decisions.';}
  $('feedStatus').textContent=stateLabel;
  $('feedHeadline').textContent=headline+'.';
  $('feedDescription').textContent=expl;
  $('snapshotDate').textContent='Last success: '+fmtStamp(lastSuccess);
  $('chartDateLabel').textContent=lastSuccess?'AS OF '+fmtDate(lastSuccess):'NO VERIFIED LIVE DATA';
  const sourceHealth=$('sourceHealth');
  Object.entries(info.sources||{}).forEach(([k,v])=>{let n=text('span','feed-chip '+(v.ok?'feed-ok':'feed-bad'),`${k.toUpperCase()}: ${v.ok?'OK':'UNAVAILABLE'}`);n.title='Last successful: '+fmtStamp(v.last_success);sourceHealth.append(n);});
  let frag=document.createDocumentFragment();categories.forEach(t=>{const el=document.createElement('option');el.value=t.name;el.textContent=t.name;frag.append(el);});$('technologyFilter').append(frag);
  function catCount(cat){return cveIDs(items.filter(x=>x.categories.includes(cat))).length;}
  function renderBars(){
    $('techBars').replaceChildren();const sorted=categories.map(x=>({...x,count:catCount(x.name)})).sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));const max=Math.max(1,...sorted.map(x=>x.count));
    sorted.forEach(x=>{const row=text('div','bar-item',''),track=text('div','bar-track',''),fill=text('div','bar-fill','');fill.style.width=x.count?Math.max(3,x.count/max*100)+'%':'0%';track.append(fill);row.append(text('span','',x.name),track,text('b','',String(x.count)));$('techBars').append(row);});
  }
  function renderCategories(){
    $('categoryGrid').replaceChildren();categories.forEach(x=>{const n=items.filter(a=>a.categories.includes(x.name)).length,b=document.createElement('button');b.type='button';b.className='category-item';b.append(text('span','category-icon',x.icon),text('span','category-label',x.name),text('span','category-count',n?`${n} indexed ${n===1?'record':'records'}`:'No matching indexed records'));b.addEventListener('click',()=>{state.tech=x.name;$('technologyFilter').value=x.name;render();$('advisories').scrollIntoView({behavior:'smooth'});});$('categoryGrid').append(b);});
  }
  function renderFocus(){
    const priorities=items.filter(x=>x.known_exploited||x.severity==='critical'||x.severity==='high').sort((a,b)=>Number(!!b.known_exploited)-Number(!!a.known_exploited)||({critical:0,high:1}[a.severity]??2)-({critical:0,high:1}[b.severity]??2)).slice(0,3);
    $('priorityList').replaceChildren();
    if(!priorities.length){$('priorityList').append(text('p','','No priority items indexed. This is not a security clearance.'));return;}
    priorities.forEach((x,i)=>{const row=text('div','focus',''),detail=text('div','','');detail.append(text('b','',x.title),text('p','',`${x.id}${x.known_exploited?' · CISA KEV listed':''} · ${x.categories[0]}`));row.append(text('span','rank',`0${i+1}`),detail);$('priorityList').append(row);});
  }
  function filterItems(){return items.filter(x=>{const query=[x.id,x.title,x.summary,x.affected,x.remediation,x.action,...x.categories].join(' ').toLowerCase();return(state.tech==='all'||x.categories.includes(state.tech))&&(state.severity==='all'||x.severity===state.severity)&&(!state.q||query.includes(state.q));});}
  function render(){const selected=filterItems();$('resultCount').textContent=`${selected.length} of ${items.length} indexed advisories`;$('advisoryCards').replaceChildren();$('noResults').hidden=selected.length!==0;selected.forEach(x=>{
    const card=text('article','advisory-card',''),head=text('div','card-head','');head.append(text('span','cat-badge',x.categories[0]),text('span','severity-badge '+x.severity,severityText(x.severity)));card.append(head);card.append(text('h3','',x.title),text('p','',x.summary));
    const meta=text('div','card-meta','');meta.append(text('span','',fmtDate(x.published)),text('span','',x.categories.length===1?'1 technology':`${x.categories.length} technologies`));if(x.cvss)meta.append(text('span','',`CVSS ${x.cvss}`));if(x.known_exploited)meta.append(text('span','kev-mark','CISA KEV'));card.append(meta);
    const foot=text('div','card-footer','');foot.append(text('small','',x.id));const btn=text('button','detail-btn','Review details ↗');btn.type='button';btn.addEventListener('click',()=>showDetail(x));foot.append(btn);card.append(foot);$('advisoryCards').append(card);
  });}
  function rowSpec(name,value){const el=text('div','spec','');el.append(text('small','',name),text('b','',value||'Not confirmed'));return el;}
  function showDetail(x){
    const root=$('dialogContent');root.replaceChildren();root.append(text('span','cat-badge',x.categories.join(' · ')),text('h2','',x.title));root.append(text('span','severity-badge '+x.severity,severityText(x.severity)));
    const specs=text('div','spec-grid','');specs.append(rowSpec('Advisory ID',x.id),rowSpec('First published',fmtDate(x.published)),rowSpec('Last source update',fmtDate(x.updated)),rowSpec('First indexed',fmtStamp(x.first_seen_at)),rowSpec('Exploitation',x.exploitation));if(x.cvss)specs.append(rowSpec('Reported CVSS',x.cvss));root.append(specs);
    function block(h,body){root.append(text('h3','',h),text('p','',body||'Not provided by the indexed source.'));}
    block('Description',x.summary);block('Affected software and versions',x.affected);block('Fix or workaround',x.remediation);block('Suggested next step',x.action);
    root.append(text('h3','','Public sources'));const list=document.createElement('ul');list.style.paddingLeft='20px';(x.sources||[]).forEach(s=>{try{const url=new URL(s.url);if(url.protocol!=='https:')return;const li=document.createElement('li'),a=text('a','',s.label);a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';li.append(a);list.append(li);}catch(_e){}});root.append(list);
    root.append(text('p','disclaimer','CVEHarbor aggregates public third-party advisory data. This record does not establish that your environment is vulnerable. Verify the primary vendor bulletin, affected versions, and patch applicability.'));
    const dlg=$('detailDialog');if(typeof dlg.showModal==='function')dlg.showModal();else dlg.setAttribute('open','');
  }
  function clear(){state.q='';state.tech='all';state.severity='all';$('search').value='';$('technologyFilter').value='all';$('severity').value='all';render();}
  $('search').addEventListener('input',e=>{state.q=e.target.value.trim().toLowerCase();render();});$('technologyFilter').addEventListener('change',e=>{state.tech=e.target.value;render();});$('severity').addEventListener('change',e=>{state.severity=e.target.value;render();});$('clearFilters').addEventListener('click',clear);$('resetEmpty').addEventListener('click',clear);
  $('closeDialog').addEventListener('click',()=>$('detailDialog').close());$('detailDialog').addEventListener('click',e=>{if(e.target===$('detailDialog'))$('detailDialog').close();});
  renderBars();renderFocus();renderCategories();render();
})();
