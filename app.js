(() => {
  'use strict';
  const state = { q: '', severity: 'all', tech: 'all', group: 'all', period: 'published30' };
  const PAGE_SIZE = 10;
  const TABLE_PAGE_SIZE = 25;
  const isCVE = x => /^CVE-\d{4}-\d+$/i.test(x.id);
  let visibleCount = PAGE_SIZE;
  let tablePage = 0;
  let listMode = 'cards';
  let metricScope = 'all';
  let chartPeriod = 'all';
  let chartShowAll = false;
  const technologyGroups = {"microsoft":["Windows Server OS","Windows 11 OS","Azure","Microsoft 365","Exchange SE","SharePoint / SharePoint Server","Microsoft Power Platform","Dynamics 365","Microsoft Fabric / Power BI","Azure AI / AI SDK"],"applications":[".NET / ASP.NET",".NET Core","WordPress / Plugins","PHP","Python / PyPI","Angular","React / Next.js","JavaScript / TypeScript","Node.js / npm","Drupal / CMS"],"infrastructure":["Linux","Fortinet","Sophos Firewall","VMware","Veeam Backup & Replication","HyperV","Docker / Kubernetes","AWS","Windows"],"data":["SQL Server","MySQL / MariaDB","NoSQL / MongoDB","Progress Telerik","Sitefinity","Kendo UI","jQuery / Bootstrap","Application dependencies","iOS / Android"]};
  const featured = new Set(Object.values(technologyGroups).flat());
  const groupTitles = {microsoft:'Microsoft & Cloud',applications:'Applications & Frameworks',infrastructure:'Infrastructure & Security',data:'Data, UI & Dependencies'};
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
      known_exploited:Boolean(prior.known_exploited||baseline.known_exploited),
      exploitation:(prior.known_exploited||baseline.known_exploited)?'Confirmed: listed in CISA KEV':(prior.exploitation||baseline.exploitation),
      status:prior.status||baseline.status,
    });
  }
  let personalized=null;let catalogueSignedIn=false;
  const customGroup='custom';
  technologyGroups[customGroup]=[];
  groupTitles[customGroup]='My Additional Products';
  const customMatching = name => {
    const needle=String(name||'').toLowerCase().trim();
    if(needle.length<3)return [];
    // Search titles/affected text only; these remain unverified investigation leads.
    return items.filter(a=>[a.title,a.affected].some(v=>String(v||'').toLowerCase().includes(needle)));
  };
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
  // Disclosure badge uses the ORIGINAL published date, never first-indexed
  // or last-modified metadata. Source records frequently have date precision
  // only, so label day groups in Toronto rather than claim an exact 72h SLA.
  const disclosureAgeLabel = (record, now = new Date()) => {
    const published = record && record.published;
    if (!/^\d{4}-\d{2}-\d{2}(?:$|T)/.test(published||'')) return '';
    const date = published.slice(0,10);
    const parsed = new Date(date + 'T00:00:00Z');
    if (!Number.isFinite(parsed.getTime()) || parsed.toISOString().slice(0,10)!==date) return '';
    const parts = new Intl.DateTimeFormat('en-US',{
      timeZone:'America/Toronto',year:'numeric',month:'2-digit',day:'2-digit'
    }).formatToParts(now);
    const get = type => parts.find(x=>x.type===type)?.value;
    const localDay = Date.UTC(Number(get('year')),Number(get('month'))-1,Number(get('day')));
    const age = Math.round((localDay - parsed.getTime())/86400000);
    if(age===0) return 'TODAY';
    if(age===1) return 'YESTERDAY';
    if(age===2) return '72 HOURS';
    return '';
  };
  const makeDisclosureBadge = record => {
    const label=disclosureAgeLabel(record);
    if(!label) return null;
    const badge=text('span','fresh-disclosure-badge',label);
    badge.title='Original publication date: '+fmtDate(record.published)+'. Dates grouped by Toronto calendar day. Exact disclosure hour may be unavailable.';
    badge.setAttribute('aria-label','New advisory '+label.toLowerCase()+', first published '+fmtDate(record.published));
    return badge;
  };

  // Calendar-day categories always use the original first-publication date,
  // not source update, crawl time, or KEV catalog entry time.
  const matchesDisclosureDay = (record, label) =>
    record.source_type!=='cisa_kev' && disclosureAgeLabel(record)===label;
  const recentRevision = (record,days=7) => recentDate(record.updated,days);
  const periodMatches = record => {
    if(state.period==='all') return true;
    if(state.period==='today') return matchesDisclosureDay(record,'TODAY');
    if(state.period==='yesterday') return matchesDisclosureDay(record,'YESTERDAY');
    if(state.period==='twoDays') return matchesDisclosureDay(record,'72 HOURS');
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
  const severityText=s=>({critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW',bulletin:'BULLETIN'})[s]||'UNKNOWN';
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
  if(info.coverage_limited){stateLabel='Indexed archive limited';expl+=' The public index has reached its record cap and does not display every candidate advisory.';}
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
  function chartRecordMatches(item){
    if(chartPeriod==='published30')return newlyPublished(item,30);
    if(chartPeriod==='updated7')return recentRevision(item,7);
    return true;
  }
  function catCount(tech){
    return advisoryIDs(items.filter(x=>(x.categories||[]).includes(tech)&&chartRecordMatches(x))).length;
  }
  function openTechnologyAdvisories(technology,cveOnly=false,periodOverride=null){
    const recentAvailable=items.some(x=>(x.categories||[]).includes(technology)&&newlyPublished(x,30));
    const selectedPeriod=periodOverride||(recentAvailable?'published30':'all');
    state.tech=technology;state.group='all';state.q='';state.severity='all';state.period=selectedPeriod;
    metricScope=cveOnly?'cves':'all';listMode='list';visibleCount=PAGE_SIZE;tablePage=0;
    $('technologyFilter').value=technology;
    $('search').value='';$('severity').value='all';$('dateRange').value=selectedPeriod;
    render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});
  }
  function openTechnologyGroup(group){
    const members=technologyGroups[group]||[];
    if(!members.length)return;
    const recentAvailable=items.some(x=>(x.categories||[]).some(t=>members.includes(t))&&newlyPublished(x,30));
    const selectedPeriod=recentAvailable?'published30':'all';
    state.group=group;state.tech='all';state.q='';state.severity='all';state.period=selectedPeriod;
    metricScope='all';listMode='list';resetPaging();
    $('technologyFilter').value='all';
    $('search').value='';$('severity').value='all';$('dateRange').value=selectedPeriod;
    render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});
  }
  function renderBars(){
    const host=$('techBars');host.replaceChildren();
    const sorted=categories.map(x=>({...x,count:catCount(x.name)}))
      .sort((a,b)=>b.count-a.count||a.name.localeCompare(b.name));
    const nonzero=sorted.filter(x=>x.count>0);
    const displayed=chartShowAll?sorted:nonzero.slice(0,15);
    const max=Math.max(1,...displayed.map(x=>x.count));
    displayed.forEach(x=>{
      const b=document.createElement('button');
      b.type='button';b.className='bar-item tech-chart-link';
      b.setAttribute('aria-label',`Open ${x.name}, ${x.count} indexed advisories in the selected period`);
      b.title=`Open ${x.name} advisories`;
      const track=text('div','bar-track',''),fill=text('div','bar-fill','');
      fill.style.width=x.count?Math.max(3,x.count/max*100)+'%':'0%';
      track.append(fill);
      b.append(text('span','',x.name),track,text('b','',String(x.count)));
      b.addEventListener('click',()=>openTechnologyAdvisories(x.name,false,chartPeriod));
      host.append(b);
    });
    const caption=chartPeriod==='all'?'all indexed advisories':chartPeriod==='updated7'?'advisories modified in the past seven days':'advisories originally disclosed in the last 30 days';
    $('chartModeDescription').textContent='CVE and GHSA records by technology, showing '+caption+'.';
    $('chartShowAll').hidden=categories.length<=15;
    $('chartShowAll').textContent=chartShowAll?'Show top 15':'Show all '+categories.length+' technologies';
    $('chartNoRecords').hidden=displayed.length!==0;
    const insights=$('chartInsights');
    if(insights){
      insights.replaceChildren();
      const periodItems=items.filter(chartRecordMatches);
      const periodLabel=chartPeriod==='published30'?'New in 30 days':chartPeriod==='updated7'?'Updated in 7 days':'Indexed archive';
      const total=advisoryIDs(periodItems).length;
      const critical=advisoryIDs(periodItems.filter(a=>a.severity==='critical')).length;
      const high=advisoryIDs(periodItems.filter(a=>a.severity==='high')).length;
      const technologies=categories.filter(c=>periodItems.some(a=>(a.categories||[]).includes(c.name))).length;
      const h=text('h4','chart-insights-title','Snapshot insights');
      const intro=text('p','chart-insights-sub','Calculated from the same indexed records as the chart. Select a metric to open the matching advisory list.');
      insights.append(h,intro);
      const metrics=text('div','chart-insight-grid','');
      const definitions=[
        ['Advisories',total,'all'],
        ['Critical',critical,'critical'],
        ['High',high,'high'],
        ['Active technologies',technologies,'technologies']
      ];
      for(const [label,value,scope] of definitions){
        const button=text('button','chart-insight','');
        button.type='button';
        button.append(text('span','chart-insight-number',String(value)),text('span','chart-insight-label',label));
        button.setAttribute('aria-label','Open '+label.toLowerCase()+' in '+periodLabel);
        button.addEventListener('click',()=>{
          if(scope==='technologies'){
            $('technology').scrollIntoView({behavior:'smooth',block:'start'});return;
          }
          state.q='';state.tech='all';state.group='all';state.severity=scope==='all'?'all':scope;state.period=chartPeriod;
          metricScope='all';listMode='list';resetPaging();
          $('search').value='';$('technologyFilter').value='all';$('severity').value=state.severity;
          $('dateRange').value=state.period;
          render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});
        });
        metrics.append(button);
      }
      insights.append(metrics);
      const latest=periodItems.filter(a=>/^\d{4}-\d{2}-\d{2}/.test(a.published||'')).sort((a,b)=>String(b.published).localeCompare(String(a.published)))[0];
      insights.append(text('p','chart-insights-foot',latest?'Latest originally published advisory in this selection: '+fmtDate(latest.published)+'.':'No source-dated advisories found in this selection.'));
    }

    document.querySelectorAll('[data-chart-period]').forEach(button=>{
      const selected=button.dataset.chartPeriod===chartPeriod;
      button.classList.toggle('is-active',selected);
      button.setAttribute('aria-pressed',String(selected));
    });
  }
  function renderCategories(){
    const main=$('categoryGrid'),q=$('technologySearch').value.trim().toLowerCase();
    main.replaceChildren();
    const matches=x=>!q||(x.name+' '+(x.description||'')).toLowerCase().includes(q);
    const enabled=x=>!personalized||personalized.defaults.includes(x.name);
    let visible=0;
    function makeRow(x){
      const categoryRecords=x.custom?customMatching(x.name):items.filter(a=>(a.categories||[]).includes(x.name));
      const total=advisoryIDs(categoryRecords).length;
      const recent=advisoryIDs(categoryRecords.filter(a=>newlyPublished(a,30))).length;
      const ages={'TODAY':0,'YESTERDAY':0,'72 HOURS':0};
      categoryRecords.forEach(a=>{
        if(a.source_type==='cisa_kev')return;
        const label=disclosureAgeLabel(a);
        if(Object.hasOwn(ages,label))ages[label]++;
      });
      const dated=categoryRecords.filter(a=>a.source_type!=='cisa_kev' && /^\d{4}-\d{2}-\d{2}/.test(a.published||''))
        .map(a=>a.published.slice(0,10)).sort().reverse();
      const latest=dated[0]||'';
      const button=document.createElement('button');
      button.type='button';button.className='technology-row';
      button.setAttribute('aria-label',`View ${x.name}: ${ages.TODAY} published today, ${ages.YESTERDAY} yesterday, ${ages['72 HOURS']} two days ago, ${recent} new in 30 days, ${total} total`);
      const icon=text('span','technology-glyph',x.icon||'◇');icon.setAttribute('aria-hidden','true');
      const label=text('span','technology-row-main','');
      const freshness=text('span','technology-row-fresh','');
      for(const [age,cls,display] of [['TODAY','today','Today'],['YESTERDAY','yesterday','Yesterday'],['72 HOURS','two-days','2 days ago']]){
        if(!ages[age])continue;
        const badge=text('span','technology-age-badge '+cls,display+' '+ages[age]);
        badge.title=ages[age]+' advisories originally published '+display.toLowerCase()+'. Open the category to review.';
        freshness.append(badge);
      }
      if(!freshness.children.length){
        freshness.append(text('span','technology-age-muted',latest?'Latest '+fmtDate(latest):'No dated advisories'));
      }
      label.append(text('span','technology-row-name',x.name),freshness);
      const counts=text('span','technology-row-counts','');
      counts.append(text('span','technology-count-new'+(recent?' has-new':''),`${recent} new`),
                    text('span','technology-count-all',`${total} total`));
      const arrow=text('span','technology-arrow','↗');arrow.setAttribute('aria-hidden','true');
      button.append(icon,label,counts,arrow);
      // Open the most recent disclosure day shown by this technology's badge.
      const openPeriod=ages.TODAY?'today':ages.YESTERDAY?'yesterday':ages['72 HOURS']?'twoDays':recent?'published30':'all';
      button.addEventListener('click',()=>{if(x.custom){state.q=x.name;state.tech='all';state.group='all';state.period='all';$('search').value=x.name;$('dateRange').value='all';render();$('advisories').scrollIntoView({behavior:'smooth',block:'start'});}else openTechnologyAdvisories(x.name,false,openPeriod)});
      return button;
    }
    const meta={
      microsoft:['01 / PLATFORMS','Microsoft & Cloud','▦'],
      applications:['02 / APPLICATIONS','Applications & Frameworks','⌘'],
      infrastructure:['03 / OPERATIONS','Infrastructure & Security','⬡'],
      data:['04 / DATA & UI','Data, UI & Dependencies','◫'],
      custom:['05 / CUSTOM','My Additional Products','＋']
    };
    for(const [name,techs] of Object.entries(technologyGroups)){
      const candidates=name===custom?(personalized?.products||[]).map(x=>({...x,custom:true,icon:'＋'})):techs.map(label=>categories.find(x=>x.name===label));
      const matched=candidates.filter(x=>x&&matches(x)&&(x.custom||enabled(x)));
      if(!matched.length)continue;
      const panel=text('article','technology-panel','');panel.dataset.domain=name;
      const head=text('button','technology-panel-head','');
      head.type='button';
      head.setAttribute('aria-label','View all '+groupTitles[name]+' advisories');
      head.title='Open all advisories in '+groupTitles[name];
      head.addEventListener('click',()=>openTechnologyGroup(name));
      const glyph=text('span','technology-panel-icon',meta[name][2]);glyph.setAttribute('aria-hidden','true');
      const label=text('div','technology-panel-heading','');
      label.append(text('span','',meta[name][0]),text('h3','',meta[name][1]));
      head.append(glyph,label,text('span','technology-panel-total',String(matched.length).padStart(2,'0')));
      const rows=text('div','technology-panel-rows','');
      matched.forEach(x=>rows.append(makeRow(x)));
      panel.append(head,rows);main.append(panel);visible+=matched.length;
    }
    $('technologyEmpty').hidden=visible!==0;
    $('technologyTotal').textContent=String(visible);
    $('technologyRecentMetric').textContent=String(advisoryIDs(items.filter(x=>newlyPublished(x,30))).length);
    $('technologyIndexedMetric').textContent=String(advisoryIDs(items).length);
    $('technologyCriticalMetric').textContent=String(advisoryIDs(items.filter(x=>x.severity==='critical')).length);
    $('technologySearchSummary').textContent=q
      ? `${visible} of ${categories.length} technologies match your search`
      : `${visible} selected technologies shown. Recent means first published within 30 days. Custom product matches are unverified leads. Zero indexed does not mean secure.`;
  }
  function renderFocus(){
    const root=$('priorityList');root.replaceChildren();
    const ranked=items.filter(x=>x.known_exploited||x.severity==='critical'||x.severity==='high');
    const newest=(a,b)=>String(b.published||'').localeCompare(String(a.published||''))||String(b.updated||'').localeCompare(String(a.updated||''));
    const bySeverity=(a,b)=>({critical:0,high:1,medium:2,low:3,bulletin:4}[a.severity]??5)-({critical:0,high:1,medium:2,low:3,bulletin:4}[b.severity]??5)||newest(a,b);
    const added=new Set();
    const priority=[];
    const add=(group,records,limit)=>{
      let used=0;
      for(const x of records){
        if(added.has(x.id)||used>=limit)continue;
        added.add(x.id);priority.push({record:x,group});used++;
      }
    };
    add('Recently disclosed',ranked.filter(x=>newlyPublished(x,30)&&['critical','high'].includes(x.severity)).sort(bySeverity),4);
    add('Known exploited',ranked.filter(x=>x.known_exploited).sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||''))||newest(a,b)),3);
    add('Recently updated',ranked.filter(x=>recentRevision(x,7)).sort((a,b)=>String(b.updated||'').localeCompare(String(a.updated||''))),2);
    add('Other high priority',ranked.sort(bySeverity),Math.max(0,9-priority.length));
    if(!priority.length){root.append(text('p','','No high priority advisories are indexed. This does not establish that any technology is secure.'));return;}
    for(const [i,entry] of priority.entries()){
      const x=entry.record;
      const row=text('button','focus focus-action','');
      row.type='button';
      row.setAttribute('aria-label','View '+x.id+', '+severityText(x.severity)+', '+x.title);
      const rank=text('span','rank',String(i+1).padStart(2,'0'));
      const detail=text('span','focus-content','');
      const top=text('span','focus-top','');
      top.append(text('span','focus-group',entry.group),text('span','severity-badge '+x.severity,severityText(x.severity)));
      if(x.known_exploited)top.append(text('span','focus-kev','CISA KEV'));
      detail.append(top,text('b','focus-title',x.title||x.id),
        text('span','focus-meta',x.id+' · '+(x.categories||[]).slice(0,2).join(' / ')+' · Published '+fmtDate(x.published)));
      row.append(rank,detail);
      row.addEventListener('click',()=>showDetail(x));
      root.append(row);
    }
  }
  function filterItems(){
    return items.filter(x=>{
      const query=[x.id,x.title,x.summary,x.affected,x.remediation,x.action,...x.categories].join(' ').toLowerCase();
      const metricMatches=metricScope==='all'||(isCVE(x)&&(metricScope==='cves'||x.severity===metricScope));
      return periodMatches(x) && metricMatches && (state.group==='all'||(technologyGroups[state.group]||[]).some(t=>(x.categories||[]).includes(t))) && (state.tech==='all'||(x.categories||[]).includes(state.tech)) && (state.severity==='all'||x.severity===state.severity) && (!state.q||query.includes(state.q));
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
    const periodNames={today:'originally published today',yesterday:'originally published yesterday',twoDays:'originally published two days ago',published7:'new in the last 7 days',published30:'new in the last 30 days',updated7:'updated in the last 7 days',all:'from the indexed archive'};
    const title = state.group!=='all'?groupTitles[state.group]+' advisories':state.tech!=='all'?state.tech+(metricScope==='cves'?' CVEs':' advisories'):(descriptions[metricScope]||descriptions.all);
    $('listContext').textContent=title+' · '+periodNames[state.period];
    const pages=Math.max(1,Math.ceil(selected.length/TABLE_PAGE_SIZE));
    tablePage=Math.min(tablePage,pages-1);
    const pageStart=tablePage*TABLE_PAGE_SIZE;
    if(full){
      selected.slice(pageStart,pageStart+TABLE_PAGE_SIZE).forEach(x=>{
        const row=document.createElement('tr');
        const cell=(value,className='')=>{
          const el=text('td',className,value);
          const labels=['Advisory','Severity','Technology','Description','Published','Details'];
          el.dataset.label=labels[row.children.length]||'';
          row.append(el);return el;
        };
        const idCell=cell(x.id,'table-cve');
        const firstPublished=makeDisclosureBadge(x);
        if(firstPublished) idCell.append(firstPublished);
        const sev=cell(severityText(x.severity),'table-severity');
        sev.dataset.level=x.severity;
        cell(x.categories.join(' · '),'table-tech');
        cell(x.title||x.summary||'See source advisory','table-description');
        cell(fmtDate(x.published),'table-date');
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
      const markers=text('div','card-labels','');
      const freshness=makeDisclosureBadge(x);
      if(freshness) markers.append(freshness);
      markers.append(text('span','severity-badge '+x.severity,severityText(x.severity)));
      head.append(text('span','cat-badge',x.categories[0]),markers);
      if(freshness) card.classList.add('has-fresh-disclosure');
      card.append(head);card.append(text('h3','',x.title),text('p','card-summary',x.summary));
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
    const root=$('dialogContent');root.replaceChildren();
    root.append(text('span','cat-badge',x.categories.join(' · ')),text('h2','',x.title));
    const detailMarkers=text('div','detail-labels','');
    const firstPublished=makeDisclosureBadge(x);
    if(firstPublished)detailMarkers.append(firstPublished);
    detailMarkers.append(text('span','severity-badge '+x.severity,severityText(x.severity)));
    root.append(detailMarkers);
    const specs=text('div','spec-grid','');specs.append(rowSpec('Advisory ID',x.id),rowSpec('First published',fmtDate(x.published)),rowSpec('Last source update',fmtDate(x.updated)),rowSpec('First indexed',fmtStamp(x.first_seen_at)),rowSpec('Source status',x.status||'Vendor/source verification required'),rowSpec('Exploitation',x.exploitation));if(x.cvss)specs.append(rowSpec('Reported CVSS',x.cvss));if(typeof x.epss==='number')specs.append(rowSpec('FIRST EPSS, 30 day exploitation probability',(x.epss*100).toFixed(2)+'% ('+(x.epss_as_of||'date not available')+')'));root.append(specs);
    function block(h,body){root.append(text('h3','',h),text('p','',body||'Not provided by the indexed source.'));}
    if(typeof x.epss==='number')root.append(text('p','epss-note','EPSS estimates exploitation probability within 30 days. It is not a vulnerability severity score or proof that your environment is affected. Source: FIRST EPSS.'));block('Description',x.summary);block('Affected software and versions',x.affected);block('Fix or workaround',x.remediation);block('Suggested next step',x.action);
    root.append(text('h3','','Original advisory and source references'));
    root.append(text('p','source-note','You can review the available advisory details here. The source links below are optional and open in a new tab.'));
    const list=document.createElement('ul');list.className='detail-source-links';
    list.style.paddingLeft='20px';
    const links=[...(x.sources||[])];
    if(/^CVE-\d{4}-\d{4,}$/i.test(String(x.id||''))){
      links.push({label:'CVE Program record',url:'https://www.cve.org/CVERecord?id='+x.id});
      links.push({label:'NVD vulnerability record',url:'https://nvd.nist.gov/vuln/detail/'+x.id});
    }
    const seenLinks=new Set();
    links.forEach(s=>{
      try{
        const url=new URL(s.url);
        if(url.protocol!=='https:'||seenLinks.has(url.href))return;
        seenLinks.add(url.href);
        const li=document.createElement('li'),a=text('a','',s.label||url.hostname);
        a.href=url.href;a.target='_blank';a.rel='noopener noreferrer';
        li.append(a);list.append(li);
      }catch(_e){}
    });
    if(list.childElementCount)root.append(list);
    else root.append(text('p','','No direct source URLs were included in this indexed record.'));
    if(/^CVE-\d{4}-\d{4,}$/i.test(String(x.id||''))){
      const assign=text('button','ops-download remediation-detail-assign','Assign vulnerability by email');
      assign.type='button';
      assign.addEventListener('click',()=>{
        const dialog=$('detailDialog');
        if(typeof dialog.close==='function')dialog.close();else dialog.removeAttribute('open');
        window.dispatchEvent(new CustomEvent('cveharbor:assign-remediation',{detail:{id:x.id}}));
      });
      root.append(assign);
    }
    root.append(text('p','disclaimer','CVEHarbor aggregates public third-party advisory data. This record does not establish that your environment is vulnerable. Verify the primary vendor bulletin, affected versions, and patch applicability.'));
    const dlg=$('detailDialog');if(typeof dlg.showModal==='function')dlg.showModal();else dlg.setAttribute('open','');
  }
  // The watchlist and search share this same on-site advisory details dialog.
  window.addEventListener('cveharbor:review-advisory',event=>{
    const id=String(event.detail?.id||'');
    const item=items.find(x=>x.id===id);
    if(item)showDetail(item);
  });
  function resetPaging(){visibleCount=PAGE_SIZE;tablePage=0;}
  function clear(){
    state.q='';state.tech='all';state.group='all';state.severity='all';state.period='published30';metricScope='all';resetPaging();
    $('search').value='';$('technologyFilter').value='all';$('severity').value='all';$('dateRange').value='published30';render();
  }
  $('search').addEventListener('input',e=>{state.q=e.target.value.trim().toLowerCase();resetPaging();render();});
  $('technologyFilter').addEventListener('change',e=>{state.tech=e.target.value;state.group='all';metricScope='all';resetPaging();render();});
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
        // Every technology is already visible in the main explorer.
        $('technology').scrollIntoView({behavior:'smooth',block:'start'});
        return;
      }
      state.q='';state.tech='all';state.group='all';state.severity='all';state.period='all';
      $('search').value='';$('technologyFilter').value='all';$('severity').value='all';$('dateRange').value='all';
      metricScope=scope==='all'?'cves':scope;
      listMode='list';resetPaging();render();
      $('advisories').scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
  $('closeDialog').addEventListener('click',()=>$('detailDialog').close());$('detailDialog').addEventListener('click',e=>{if(e.target===$('detailDialog'))$('detailDialog').close();});
  document.querySelectorAll('[data-chart-period]').forEach(button=>{
    button.addEventListener('click',()=>{chartPeriod=button.dataset.chartPeriod;chartShowAll=false;renderBars();});
  });
  $('chartShowAll').addEventListener('click',()=>{chartShowAll=!chartShowAll;renderBars();});
  // The public default catalogue remains unchanged for visitors who are not signed in.
  // Preferences are only stored on the authenticated account and never in shared data.
  const catalogueAPI='https://api.cveharbor.com/v1/technology-catalogue';
  const defaultNames=categories.map(x=>x.name);
  const manageButton=$('technologyManageButton');
  const customizeStatus=$('technologyCustomizeStatus');
  const customForm=$('technologyAddForm');
  let draft=null;
  const statusMessage=s=>{customizeStatus.textContent=s};
  function drawCustomizer(){
    if(!draft)return;
    const choices=$('technologyDefaultChoices');choices.replaceChildren();
    for(const x of categories){
      const label=document.createElement('label'),input=document.createElement('input');
      input.type='checkbox';input.checked=draft.defaults.includes(x.name);
      input.addEventListener('change',()=>{draft.defaults=input.checked?[...draft.defaults,x.name]:draft.defaults.filter(n=>n!==x.name)});
      label.append(input,text('span','',x.name));choices.append(label);
    }
    const list=$('technologyCustomList');list.replaceChildren();
    for(const p of draft.products){
      const row=text('div','technology-custom-item','');
      row.append(text('span','',p.name+(p.version?' · '+p.version:'')+' · Public feed coverage not verified'));
      const remove=text('button','','Remove');remove.type='button';
      remove.addEventListener('click',()=>{draft.products=draft.products.filter(x=>x.name!==p.name);drawCustomizer()});
      row.append(remove);list.append(row);
    }
  }
  manageButton.addEventListener('click',()=>{draft=JSON.parse(JSON.stringify(personalized||{defaults:defaultNames,products:[]}));drawCustomizer();$('technologyCustomizer').hidden=false;$('technologyCustomizer').scrollIntoView({block:'start',behavior:'smooth'})});
  $('technologyManageClose').addEventListener('click',()=>{$('technologyCustomizer').hidden=true});
  $('technologyResetButton').addEventListener('click',()=>{draft={defaults:[...defaultNames],products:[]};drawCustomizer();statusMessage('Defaults restored in the editor. Save to apply.')});
  customForm.addEventListener('submit',e=>{e.preventDefault();const name=$('technologyAddName').value.trim(),version=$('technologyAddVersion').value.trim();if(!name||!draft)return;
    if(draft.products.some(x=>x.name.toLowerCase()===name.toLowerCase())){statusMessage('Product already added.');return}
    if(draft.products.length>=50){statusMessage('Maximum of 50 additional products.');return}
    draft.products.push({name,version});customForm.reset();drawCustomizer();statusMessage('Product added to the editor. Save to apply.')
  });
  $('technologySaveButton').addEventListener('click',async()=>{if(!draft)return;statusMessage('Saving account preferences...');
    try{const r=await fetch(catalogueAPI,{method:'PUT',credentials:'include',headers:{'content-type':'application/json'},body:JSON.stringify(draft)});
      const data=await r.json();if(!r.ok)throw Error(data.error||'Unable to save');
      personalized=JSON.parse(JSON.stringify(draft));renderCategories();statusMessage('Saved to your CVEHarbor account.');
    }catch(e){statusMessage('Unable to save: '+e.message)}
  });
  fetch('https://api.cveharbor.com/v1/me',{credentials:'include'}).then(r=>r.ok?r.json():null).then(async me=>{
    if(!me?.authenticated)return;
    catalogueSignedIn=true;
    const r=await fetch(catalogueAPI,{credentials:'include'});
    if(!r.ok)return;
    const data=await r.json();
    personalized={defaults:Array.isArray(data.defaults)?data.defaults:defaultNames,products:Array.isArray(data.products)?data.products:[]};
    manageButton.hidden=false;renderCategories();
  }).catch(()=>{});
  $('technologySearch').addEventListener('input',renderCategories);
  renderBars();renderFocus();renderCategories();render();
})();
