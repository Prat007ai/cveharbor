(() => {
  'use strict';
  const state = { q: '', severity: 'all', tech: 'all', period: 'published30' };
  const PAGE_SIZE = 6;
  const TABLE_PAGE_SIZE = 25;
  const isCVE = x => /^CVE-\d{4}-\d+$/i.test(x.id);
  let visibleCount = PAGE_SIZE;
  let tablePage = 0;
  let listMode = 'cards';
  let metricScope = 'all';
  const technologyGroups = {"microsoft":["Windows Server OS","Windows 11 OS",".NET / ASP.NET",".NET Core","Azure","Microsoft 365","Exchange SE"],"applications":["WordPress / Plugins","PHP","Python / PyPI","SQL Server","MySQL / MariaDB","Progress Telerik","Sitefinity"],"infrastructure":["Linux","Fortinet","Sophos Firewall","VMware","Veeam Backup & Replication","HyperV","Docker / Kubernetes"]};
  const featured = new Set(Object.values(technologyGroups).flat());
  const info = window.CVEHARBOR_DATA || {categories:[],advisories:[],mode:'awaiting_first_sync'};
  // The category taxonomy and historical vendor entries are published by the
  // static site build, independently from the hourly data feed.
  const catalog = window.CVEHARBOR_CATALOG || {categories:[],advisories:[]};
  const categories = (Array.isArray(catalog.categories) && catalog.categories.length ? catalog.categories : info.categories) || [];
  const records = new Map();
  for (const advisory of info.advisories || []) {
    if(advisory && advisory.id) records.set(advisory.id, advisory);
  }
  for (const baseline of catalog.advisories || []) {
    if(!baseline || !baseline.id) continue;
    const prior = records.get(baseline.id);
    if(!prior){ records.set(baseline.id, baseline); continue; }
    // A CVE may appear in both the hourly feeds and the older vendor baseline.
    // Keep one record and retain verified KEV status, source links and categories.
    const links = new Map();
    for(const ref of [...(prior.sources||[]), ...(baseline.sources||[])]){
      if(ref && ref.url) links.set(ref.url,ref);
    }
    records.set(baseline.id,{
      ...prior,
      categories:[...new Set([...(prior.categories||[]),...(baseline.categories||[])])],
      sources:[...links.values()].slice(0,8),
      affected:prior.source_type==='nvd' ? baseline.affected : (prior.affected||baseline.affected),
      remediation:prior.source_type==='nvd' ? baseline.remediation : (prior.remediation||baseline.remediation),
      known_exploited:Boolean(prior.known_exploited),
      status:prior.status||baseline.status,
    });
  }
  const items=[...records.values()].map(record=>{
    // .NET / ASP.NET is the inclusive overview. .NET Core remains a filter for
    // the modern subset, including advisories previously tagged only .NET Core.
    if((record.categories||[]).includes('.NET Core') && !(record.categories||[]).includes('.NET / ASP.NET'))
      return {...record,categories:['.NET / ASP.NET',...record.categories]};
    return record;
  }).sort((a,b)=>String(b.published||'').localeCompare(String(a.published||'')) || String(b.updated||'').localeCompare(String(a.updated||'')));
  const $ = id => document.getElementById(id);
  const cveIDs = rows => [...new Set(rows.filter(x => /^CVE-\d{4}-\d+$/i.test(x.id)).map(x => x.id))];
  const advisoryIDs = rows => [...new Set(rows.filter(x=>x&&x.id).map(x=>x.id))];
  // Publication date means original disclosure. A routine vendor/NVD metadata
  // update should not make a months-old vulnerability look newly published.
  const recentDate = (dateString,days) => {
    if (!/^\d{4}-\d{2}-\d{2}/.test(dateString||'')) return false;
    const published=Date.parse(dateString.slice(0,10)+'T23:59:59Z');
    return Number.isFinite(published) && published >= Date.now()-days*86400000;
  };
  const newlyPublished = (record,days=30) => recentDate(record.published,days) && record.source_type!=='cisa_kev';
  const recentRevision = (record,days=7) => recentDate(record.updated,days);
  const periodMatches = record => {
    if(state.period==='all') return true;
    if(state.period==='published7') return newlyPublished(record,7);
    if(state.period==='updated7') return recentRevision(record,7);
    return newlyPublished(record,30);
  };

  const text = (tag, className, content) => {const n=document.createElement(tag);if(className)n.className=className;n.textContent=content||'';return n;};
  const fmtDate = s => {if(!s||!/^\d{4}-\d{2}-\d{2}/.test(s))return 'Not available';let d=new Date(s.slice(0,10)+'T12:00:00Z');return Number.isFinite(d.getTime())?d.toLocaleDateString('en-CA',{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'}):'Not available';};
  const fmtStamp = s => {if(!s)return 'Never';let d=new Date(s);return Number.isFinite(d.getTime())?d.toLocaleString('en-CA',{dateStyle:'medium',timeStyle:'short',timeZone:'UTC'})+' UTC':'Not available';};
  const fmtEastern = s => {
    if (!s) return 'Not available';
    const d = new Date(s);
    if (!Number.isFinite(d.getTime())) return 'Not available';
    const date = new Intl.DateTimeFormat('en-CA',{month:'short',day:'numeric',year:'numeric',timeZone:'America/Toronto'}).format(d);
    const time = new Intl.DateTimeFormat('en-CA',{hour:'numeric',minute:'2-digit',hour12:true,timeZone:'America/Toronto'}).format(d);
    const zone = new Intl.DateTimeFormat('en-US',{timeZone:'America/Toronto',timeZoneName:'short'}).formatToParts(d).find(x=>x.type==='timeZoneName')?.value||'ET';
    return date+', '+time+' '+zone;
  };
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
  else if(status==='partial'&&lag<=2.5){stateLabel='Partial feed coverage';headline='Some sources failed during the last published collection';expl='The saved snapshot contains updates from available sources, but at least one feed failed during that collection. This is historical collection status, not evidence of a current provider outage.';}
  else if(lastSuccess){stateLabel='Data may be stale';headline='Hourly refresh not confirmed';expl='The latest successful collection is older than expected or a source has failed. Consult official vendor advisories for time-sensitive decisions.';}
  $('feedStatus').textContent=stateLabel;
  $('feedHeadline').textContent=headline+'.';
  $('feedDescription').textContent=expl;
  $('snapshotDate').textContent='Last success: '+fmtStamp(lastSuccess)+(lastSuccess?' ('+fmtEastern(lastSuccess)+')':'');
  $('chartDateLabel').textContent=lastSuccess?'AS OF '+fmtDate(lastSuccess):'NO VERIFIED LIVE DATA';
  const sourceHealth=$('sourceHealth');
  Object.entries(info.sources||{}).forEach(([k,v])=>{
    const label=k.toUpperCase()+': '+(v.ok?'OK AT LAST SYNC':'FAILED AT LAST SYNC');
    const n=text('span','feed-chip '+(v.ok?'feed-ok':'feed-bad'),label);
    const details=['Last attempted: '+fmtStamp(v.last_attempt),'Last successful: '+fmtStamp(v.last_success)];
    if(!v.ok && v.error) details.push('Saved error: '+String(v.error).slice(0,180));
    n.title=details.join(' | ');
    n.setAttribute('aria-label',label+'. '+details.join('. '));
    sourceHealth.append(n);
  });
  let frag=document.createDocumentFragment();categories.forEach(t=>{const el=document.createElement('option');el.value=t.name;el.textContent=t.name;frag.append(el);});$('technologyFilter').append(frag);
  function catCount(cat){return advisoryIDs(items.filter(x=>(x.categories||[]).includes(cat) && newlyPublished(x,30))).length;}
  function openTechnologyAdvisories(technology, cveOnly=false){
    // Synchronize all controls so an old search or severity filter cannot hide results.
    const recentAvailable=items.some(x=>(x.categories||[]).includes(technology)&&newlyPublished(x,30));
    const targetPeriod=recentAvailable?'published30':'all';
    state.tech=technology;state.q='';state.severity='all';state.period=targetPeriod;
    metricScope=cveOnly?'cves':'all';
    listMode='list';visibleCount=PAGE_SIZE;tablePage=0;
    $('technologyFilter').value=technology;
    $('search').value='';$('severity').value='all';$('dateRange').value=targetPeriod;
    render();
    $('advisories').scrollIntoView({behavior:'smooth',block:'start'});
  }
  function renderBars(){
    $('techBars').replaceChildren();
    const sorted=categories.map(x=>({...x,count:catCount(x.name)})).sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));
    const max=Math.max(1,...sorted.map(x=>x.count));
    sorted.forEach(x=>{
      const row=document.createElement('button');
      row.type='button';
      row.className='bar-item tech-chart-link';
      row.setAttribute('aria-label',`View ${x.count} security advisories newly disclosed within 30 days for ${x.name}`);
      row.title=`View ${x.name} advisories newly disclosed in the last 30 days`;
      const track=text('div','bar-track','');
      const fill=text('div','bar-fill','');
      fill.style.width=x.count?Math.max(3,x.count/max*100)+'%':'0%';
      track.append(fill);
      row.append(text('span','',x.name),track,text('b','',String(x.count)));
      row.addEventListener('click',()=>openTechnologyAdvisories(x.name,false));
      $('techBars').append(row);
    });
  }
  function renderCategories(){
    const main=$('categoryGrid'),extra=$('otherCategoryGrid');
    const q=$('technologySearch').value.trim().toLowerCase();
    main.replaceChildren();extra.replaceChildren();
    const matches=x=>!q||(x.name+' '+(x.description||'')).toLowerCase().includes(q);
    let visible=0,extraVisible=0;
    function row(x){
      const total=advisoryIDs(items.filter(a=>(a.categories||[]).includes(x.name))).length;
      const recent=advisoryIDs(items.filter(a=>(a.categories||[]).includes(x.name)&&newlyPublished(a,30))).length;
      const b=document.createElement('button');
      b.type='button';b.className='technology-row';
      b.setAttribute('aria-label',`View ${x.name}: ${recent} recent security advisories and ${total} total indexed`);
      const glyph=text('span','technology-glyph',x.icon||'◇');glyph.setAttribute('aria-hidden','true');
      const label=text('span','technology-row-main','');
      label.append(text('span','technology-row-name',x.name),text('span','technology-row-sub',x.description||'Security advisories'));
      const counts=text('span','technology-row-counts','');
      counts.append(text('span','technology-count-new'+(recent?' has-new':''),`${recent} new`),text('span','technology-count-all',`${total} total`));
      const arrow=text('span','technology-arrow','↗');arrow.setAttribute('aria-hidden','true');
      b.append(glyph,label,counts,arrow);
      b.addEventListener('click',()=>openTechnologyAdvisories(x.name));
      return b;
    }
    const headings={
      microsoft:['01 / PLATFORMS','Microsoft & Cloud','▦'],
      applications:['02 / SOFTWARE','Applications & Data','⌘'],
      infrastructure:['03 / OPERATIONS','Infrastructure & Security','⬡']
    };
    for(const [key,names] of Object.entries(technologyGroups)){
      const found=names.map(n=>categories.find(x=>x.name===n)).filter(x=>x&&matches(x));
      if(!found.length)continue;
      const panel=text('article','technology-panel','');panel.dataset.domain=key;
      const head=text('div','technology-panel-head','');
      const icon=text('span','technology-panel-icon',headings[key][2]);icon.setAttribute('aria-hidden','true');
      const title=text('div','technology-panel-heading','');
      title.append(text('span','',headings[key][0]),text('h3','',headings[key][1]));
      head.append(icon,title,text('span','technology-panel-total',String(found.length).padStart(2,'0')));
      const list=text('div','technology-panel-rows','');
      found.forEach(x=>list.append(row(x)));
      panel.append(head,list);main.append(panel);visible+=found.length;
    }
    for(const x of categories){
      if(featured.has(x.name)||!matches(x))continue;
      extra.append(row(x));visible++;extraVisible++;
    }
    const caption=document.querySelector('.technology-more-caption');
    if(caption) caption.textContent=(categories.length-featured.size)+' additional platforms';
    const more=$('additionalTech');
    more.hidden=Boolean(q)&&extraVisible===0;
    if(q&&extraVisible)more.open=true;
    $('technologyEmpty').hidden=visible!==0;
    $('technologyTotal').textContent=String(categories.length);
    $('technologySearchSummary').textContent=q
      ? `${visible} of ${categories.length} technology groups match your search`
      : `${featured.size} featured platforms and ${categories.length-featured.size} additional groups. Counts describe indexed security advisories, not visitor exposure.`;
  }
  function renderFocus(){
    const priorities=items.filter(x=>x.known_exploited||x.severity==='critical'||x.severity==='high').sort((a,b)=>Number(!!b.known_exploited)-Number(!!a.known_exploited)||({critical:0,high:1}[a.severity]??2)-({critical:0,high:1}[b.severity]??2)).slice(0,3);
    $('priorityList').replaceChildren();
    if(!priorities.length){$('priorityList').append(text('p','','No priority items indexed. This is not a security clearance.'));return;}
    priorities.forEach((x,i)=>{const row=text('div','focus',''),detail=text('div','','');detail.append(text('b','',x.title),text('p','',`${x.id}${x.known_exploited?' · CISA KEV listed':''} · ${x.categories[0]}`));row.append(text('span','rank',`0${i+1}`),detail);$('priorityList').append(row);});
  }
  function filterItems(){
    return items.filter(x=>{
      const query=[x.id,x.title,x.summary,x.affected,x.remediation,x.action,...x.categories].join(' ').toLowerCase();
      const metricMatches=metricScope==='all'||(isCVE(x)&&(metricScope==='cves'||x.severity===metricScope));
      return periodMatches(x) && metricMatches && (state.tech==='all'||(x.categories||[]).includes(state.tech)) && (state.severity==='all'||x.severity===state.severity) && (!state.q||query.includes(state.q));
    });
  }
  function render(){
    const selected=filterItems();
    if(state.period==='updated7') selected.sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||'')));
    $('resultCount').textContent=`${selected.length} of ${items.length} indexed advisories`;
    $('advisoryCards').replaceChildren();
    $('advisoryTableBody').replaceChildren();
    const full=listMode==='list';
    $('advisoryCards').hidden=full;
    $('advisoryTableWrap').hidden=!full;
    $('resultsPagination').hidden=full;
    $('tablePagination').hidden=!full || selected.length===0;
    $('cardViewBtn').classList.toggle('is-active',!full);
    $('listViewBtn').classList.toggle('is-active',full);
    $('cardViewBtn').setAttribute('aria-pressed',String(!full));
    $('listViewBtn').setAttribute('aria-pressed',String(full));
    const descriptions={all:'Latest indexed advisories',cves:'All indexed CVEs',critical:'Critical CVEs',high:'High severity CVEs'};
    const periodNames={published7:'new in the last 7 days',published30:'new in the last 30 days',updated7:'updated in the last 7 days',all:'from the indexed archive'};
    const title = state.tech!=='all'?state.tech+(metricScope==='cves'?' CVEs':' advisories'):(descriptions[metricScope]||descriptions.all);
    $('listContext').textContent=title+' · '+periodNames[state.period];
    const pages=Math.max(1,Math.ceil(selected.length/TABLE_PAGE_SIZE));
    tablePage=Math.min(tablePage,pages-1);
    const pageStart=tablePage*TABLE_PAGE_SIZE;
    if(full){
      selected.slice(pageStart,pageStart+TABLE_PAGE_SIZE).forEach(x=>{
        const row=document.createElement('tr');
        const cell=(value,className='')=>{
          const el=text('td',className,value);
          row.append(el);return el;
        };
        cell(x.id,'table-cve');
        const sev=cell(severityText(x.severity),'table-severity');
        sev.dataset.level=x.severity;
        cell(x.categories.join(' · '),'table-tech');
        cell(x.title||x.summary||'See source advisory','table-description');
        cell(fmtDate(x.published),'table-date');
        cell(x.known_exploited?'CISA KEV':'Not confirmed',x.known_exploited?'table-exploited':'table-unconfirmed');
        const action=cell('','table-action');
        const link=text('button','table-details','View ↗');
        link.type='button';
        link.setAttribute('aria-label','View details for '+x.id);
        link.addEventListener('click',()=>showDetail(x));
        action.append(link);
        $('advisoryTableBody').append(row);
      });
      $('tablePageSummary').textContent='Showing '+(selected.length?pageStart+1:0)+'–'+Math.min(pageStart+TABLE_PAGE_SIZE,selected.length)+' of '+selected.length+' advisories';
      $('tablePageNumber').textContent='Page '+(tablePage+1)+' of '+pages;
      $('pagePrevious').disabled=tablePage===0;
      $('pageNext').disabled=tablePage>=pages-1;
    }
    $('noResults').hidden=selected.length!==0;
    $('archiveEmpty').hidden=selected.length!==0 || state.period==='all';
    if(!full) selected.slice(0,visibleCount).forEach(x=>{
      const card=text('article','advisory-card',''),head=text('div','card-head','');
      head.append(text('span','cat-badge',x.categories[0]),text('span','severity-badge '+x.severity,severityText(x.severity)));
      card.append(head);card.append(text('h3','',x.title),text('p','',x.summary));
      const meta=text('div','card-meta','');
      meta.append(text('span','',fmtDate(x.published)),text('span','',x.categories.length===1?'1 technology':`${x.categories.length} technologies`));
      if(x.cvss)meta.append(text('span','',`CVSS ${x.cvss}`));
      if(x.known_exploited)meta.append(text('span','kev-mark','CISA KEV'));
      card.append(meta);
      const foot=text('div','card-footer','');
      foot.append(text('small','',x.id));
      const btn=text('button','detail-btn','Review details ↗');
      btn.type='button';btn.addEventListener('click',()=>showDetail(x));
      foot.append(btn);card.append(foot);$('advisoryCards').append(card);
    });
    const visible=Math.min(visibleCount,selected.length);
    $('resultsPagination').hidden=full||selected.length===0;
    $('pageSummary').textContent=`Showing ${visible} of ${selected.length} matching advisories`;
    $('showMore').hidden=visible>=selected.length;
    $('showFewer').hidden=visibleCount<=PAGE_SIZE;
    const remaining=Math.max(0,selected.length-visible);
    $('showMore').textContent=`Show ${Math.min(PAGE_SIZE,remaining)} more`;
  }
  function rowSpec(name,value){const el=text('div','spec','');el.append(text('small','',name),text('b','',value||'Not confirmed'));return el;}
  function showDetail(x){
    const root=$('dialogContent');root.replaceChildren();root.append(text('span','cat-badge',x.categories.join(' · ')),text('h2','',x.title));root.append(text('span','severity-badge '+x.severity,severityText(x.severity)));
    const specs=text('div','spec-grid','');specs.append(rowSpec('Advisory ID',x.id),rowSpec('First published',fmtDate(x.published)),rowSpec('Last source update',fmtDate(x.updated)),rowSpec('First indexed',fmtStamp(x.first_seen_at)),rowSpec('Source status',x.status||'Vendor/source verification required'),rowSpec('Exploitation',x.exploitation));if(x.cvss)specs.append(rowSpec('Reported CVSS',x.cvss));root.append(specs);
    function block(h,body){root.append(text('h3','',h),text('p','',body||'Not provided by the indexed source.'));}
    block('Description',x.summary);block('Affected software and versions',x.affected);block('Fix or workaround',x.remediation);block('Suggested next step',x.action);
    root.append(text('h3','','Public sources'));const list=document.createElement('ul');list.style.paddingLeft='20px';(x.sources||[]).forEach(s=>{try{const url=new URL(s.url);if(url.protocol!=='https:')return;const li=document.createElement('li'),a=text('a','',s.label);a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';li.append(a);list.append(li);}catch(_e){}});root.append(list);
    root.append(text('p','disclaimer','CVEHarbor aggregates public third-party advisory data. This record does not establish that your environment is vulnerable. Verify the primary vendor bulletin, affected versions, and patch applicability.'));
    const dlg=$('detailDialog');if(typeof dlg.showModal==='function')dlg.showModal();else dlg.setAttribute('open','');
  }
  function resetPaging(){visibleCount=PAGE_SIZE;tablePage=0;}
  function clear(){
    state.q='';state.tech='all';state.severity='all';state.period='published30';metricScope='all';resetPaging();
    $('search').value='';$('technologyFilter').value='all';$('severity').value='all';$('dateRange').value='published30';render();
  }
  $('search').addEventListener('input',e=>{state.q=e.target.value.trim().toLowerCase();resetPaging();render();});
  $('technologyFilter').addEventListener('change',e=>{state.tech=e.target.value;metricScope='all';resetPaging();render();});
  $('severity').addEventListener('change',e=>{state.severity=e.target.value;metricScope='all';resetPaging();render();});
  $('dateRange').addEventListener('change',e=>{state.period=e.target.value;resetPaging();render();});
  $('archiveEmpty').addEventListener('click',()=>{state.period='all';$('dateRange').value='all';resetPaging();render();});
  $('clearFilters').addEventListener('click',clear);$('resetEmpty').addEventListener('click',clear);
  $('showMore').addEventListener('click',()=>{visibleCount+=PAGE_SIZE;render();});
  $('showFewer').addEventListener('click',()=>{visibleCount=PAGE_SIZE;render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});});
  $('cardViewBtn').addEventListener('click',()=>{listMode='cards';resetPaging();render();});
  $('listViewBtn').addEventListener('click',()=>{listMode='list';resetPaging();render();});
  $('pagePrevious').addEventListener('click',()=>{if(tablePage>0){tablePage--;render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});}});
  $('pageNext').addEventListener('click',()=>{if((tablePage+1)*TABLE_PAGE_SIZE<filterItems().length){tablePage++;render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});}});
  document.querySelectorAll('[data-metric]').forEach(btn=>{
    btn.addEventListener('click',()=>{
      const scope=btn.dataset.metric;
      if(scope==='technologies'){
        $('additionalTech').open=true;
        $('technology').scrollIntoView({behavior:'smooth',block:'start'});
        return;
      }
      state.q='';state.tech='all';state.severity='all';state.period='all';
      $('search').value='';$('technologyFilter').value='all';$('severity').value='all';$('dateRange').value='all';
      metricScope=scope==='all'?'cves':scope;
      listMode='list';resetPaging();render();
      $('advisories').scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
  $('closeDialog').addEventListener('click',()=>$('detailDialog').close());$('detailDialog').addEventListener('click',e=>{if(e.target===$('detailDialog'))$('detailDialog').close();});
  $('technologySearch').addEventListener('input',renderCategories);
  renderBars();renderFocus();renderCategories();render();
})();
