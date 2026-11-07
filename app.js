(() => {
  'use strict';
  const state = { q: '', severity: 'all', tech: 'all', group: 'all', period: 'published3m' };
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
    return items.filter(a=>(a.cvie_products||[]).some(p=>p.toLowerCase().trim()===needle));
  };
  let items=[...records.values()].map(record=>{
    // .NET / ASP.NET is the inclusive overview. .NET Core remains a filter for
    // the modern subset, including advisories previously tagged only .NET Core.
    if((record.categories||[]).includes('.NET Core') && !(record.categories||[]).includes('.NET / ASP.NET'))
      return {...record,categories:['.NET / ASP.NET',...record.categories]};
    return record;
  }).sort((a,b)=>String(b.published||'').localeCompare(String(a.published||'')) || String(b.updated||'').localeCompare(String(a.updated||'')));
  const $ = id => document.getElementById(id);
  const baseItems=items.slice();
  const monthCutoff=months=>{const now=new Date(),day=now.getUTCDate();now.setUTCDate(1);now.setUTCMonth(now.getUTCMonth()-months);now.setUTCDate(Math.min(day,new Date(Date.UTC(now.getUTCFullYear(),now.getUTCMonth()+1,0)).getUTCDate()));return now.getTime();};
  const inMonths=(record,months)=>{const date=Date.parse(record.published||'');return Number.isFinite(date)&&date>=monthCutoff(months)&&date<=Date.now();};
  const handleCvieUpdate=event=>{
    if(window.CVEHARBOR_CVIE.sessionKnown&&!window.CVEHARBOR_CVIE.signedIn){personalized=null;catalogueSignedIn=false;}
    items=window.CVEHARBOR_CVIE.merge(baseItems);
    if(personalized){const names=new Set([...personalized.defaults,...personalized.products.filter(p=>p.enabled!==false).map(p=>p.name)].map(n=>n.toLowerCase()));items=items.filter(r=>[...(r.categories||[]),...(r.cvie_products||[])].some(n=>names.has(n.toLowerCase())));}
    const names=(window.CVEHARBOR_CVIE.products||[]).map(p=>p.name);
    for(const option of [...$('technologyFilter').options])if(option.dataset.cvie)option.remove();
    for(const name of names)if(!categories.some(c=>c.name===name)){const option=document.createElement('option');option.value=name;option.textContent=name;option.dataset.cvie='true';$('technologyFilter').append(option);}
    if(state.period==='published3m'||state.period==='published12m'){state.period=window.CVEHARBOR_CVIE.months===12?'published12m':'published3m';$('dateRange').value=state.period;}
    if([...$('technologyFilter').options].some(o=>o.value===state.tech))$('technologyFilter').value=state.tech;else state.tech='all';
    renderCategories();
    if(event.detail?.recordsChanged){renderBars();renderFocus();render();}
  };
  window.addEventListener('cvie:updated',handleCvieUpdate);
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
    if(state.period==='published3m')return inMonths(record,3)||record.retained_exploited;
    if(state.period==='published12m')return inMonths(record,12)||record.retained_exploited;
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
  const severityText=s=>({critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW',unrated:'UNRATED',bulletin:'BULLETIN'})[s]||'UNKNOWN';
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
  // Keep overview drill-down filters when moving to the dedicated advisory page.
  function revealAdvisories(){
    if(location.pathname.replace(/\/index\.html$/,'/').replace(/\/$/,'')==='/intelligence'){
      const params=new URLSearchParams({technology:state.tech,severity:state.severity,period:state.period,scope:metricScope,group:state.group});
      location.assign('/vulnerabilities/?'+params.toString()+'#advisories');
      return;
    }
    $('advisories').scrollIntoView({behavior:window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth',block:'start'});
  }
  function openTechnologyAdvisories(technology,cveOnly=false,periodOverride=null){
    const recentAvailable=items.some(x=>(x.categories||[]).includes(technology)&&newlyPublished(x,30));
    const selectedPeriod=periodOverride||(window.CVEHARBOR_CVIE?.months===12?'published12m':'published3m');
    state.tech=technology;state.group='all';state.q='';state.severity='all';state.period=selectedPeriod;
    metricScope=cveOnly?'cves':'all';listMode='list';visibleCount=PAGE_SIZE;tablePage=0;
    $('technologyFilter').value=technology;
    $('search').value='';$('severity').value='all';$('dateRange').value=selectedPeriod;
    render();revealAdvisories();
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
    render();revealAdvisories();
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
            if(location.pathname.startsWith('/intelligence')){location.assign('/vulnerabilities/#technology');return;}
            $('technology').scrollIntoView({behavior:window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth',block:'start'});return;
          }
          state.q='';state.tech='all';state.group='all';state.severity=scope==='all'?'all':scope;state.period=chartPeriod;
          metricScope='all';listMode='list';resetPaging();
          $('search').value='';$('technologyFilter').value='all';$('severity').value=state.severity;
          $('dateRange').value=state.period;
          render();revealAdvisories();
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
  const customCategoryNames={microsoft:'Microsoft & Cloud',applications:'Applications & Frameworks',infrastructure:'Infrastructure & Security',data:'Data, UI & Dependencies'};
  const inferProductCategory=name=>{
    const value=String(name||'').toLowerCase();
    if(/microsoft|windows|azure|sharepoint|exchange|dynamics|power bi|fabric/.test(value))return 'microsoft';
    if(/postgres|mysql|maria|mongo|sql|redis|database|oracle|telerik|kendo|jquery|bootstrap|android|ios/.test(value))return 'data';
    if(/fortinet|sonicwall|sophos|veeam|vmware|hyper.?v|linux|docker|kubernetes|nginx|apache http server|firewall|aws/.test(value))return 'infrastructure';
    if(/apache tomcat|jenkins|wordpress|drupal|php|python|node|react|angular|next.js|\.net|java|gitlab/.test(value))return 'applications';
    return '';
  };
  let addedHighlight=null;
  let explorerMetricSignature='';
  function renderExplorerMetrics(groupCounts){
    const unique=[...new Map(items.map(item=>[item.id,item])).values()];
    const recent=unique.filter(item=>newlyPublished(item,30));
    const critical=unique.filter(item=>item.severity==='critical');
    const totals={technologies:Object.values(groupCounts).reduce((sum,n)=>sum+n,0),recent:recent.length,indexed:unique.length,critical:critical.length};
    const series=rows=>{
      const today=new Date().toISOString().slice(0,10),last=Date.parse(today+'T00:00:00Z');
      const counts=new Map();for(const row of rows){const day=String(row.published||'').slice(0,10);counts.set(day,(counts.get(day)||0)+1);}
      // A rolling 30-day interval crosses 31 UTC calendar-date buckets.
      return Array.from({length:31},(_,i)=>{const day=new Date(last-(30-i)*86400000).toISOString().slice(0,10);return {label:day,value:counts.get(day)||0};});
    };
    const severities=['critical','high','medium','low','other'].map(key=>({key,label:key==='other'?'Other / unrated':severityText(key),value:unique.filter(x=>key==='other'?!['critical','high','medium','low'].includes(x.severity):x.severity===key).length}));
    const daily=series(recent),criticalDaily=series(recent.filter(x=>x.severity==='critical'));
    const signature=JSON.stringify([groupCounts,totals,daily,criticalDaily,severities]);
    if(signature===explorerMetricSignature)return;explorerMetricSignature=signature;
    const svgNode=(tag,attrs={},label='')=>{const el=document.createElementNS('http://www.w3.org/2000/svg',tag);for(const [key,value] of Object.entries(attrs))el.setAttribute(key,String(value));if(label)el.textContent=label;return el;};
    const chart=()=>svgNode('svg',{viewBox:'0 0 200 48',preserveAspectRatio:'none',focusable:'false'});
    function hint(mark,label,value){mark.dataset.chartLabel=label+': '+value;mark.dataset.chartValue=String(value);mark.append(svgNode('title',{},label+': '+value));return mark;}
    const technologyChart=chart(),maxGroup=Math.max(1,...Object.values(groupCounts));
    Object.entries(groupCounts).forEach(([key,value],i)=>{
      const x=i*50+8,height=value/maxGroup*31;
      technologyChart.append(hint(svgNode('rect',{x,y:34-height,width:34,height,rx:3,class:'kpi-bar'}),groupTitles[key],value),svgNode('text',{x:x+17,y:46,'text-anchor':'middle'},['MS','Apps','Infra','Data'][i]));
    });
    function dailyChart(points,line=false){
      const svg=chart(),max=Math.max(1,...points.map(p=>p.value));
      svg.append(svgNode('path',{d:'M0 43H200',class:'kpi-baseline'}));
      if(line){
        const path=points.map((p,i)=>(i?'L':'M')+(i*200/30).toFixed(2)+' '+(42-p.value/max*37).toFixed(2)).join(' ');
        svg.append(svgNode('path',{d:path+' L200 46 L0 46Z',class:'kpi-area'}),svgNode('path',{d:path,class:'kpi-line',pathLength:1}));
        const latest=points.at(-1);svg.append(svgNode('circle',{cx:198,cy:42-latest.value/max*37,r:2.5,class:'kpi-beacon'}));
      }
      points.forEach((point,i)=>{
        const x=i*200/31,height=point.value/max*39;
        if(!line)svg.append(hint(svgNode('rect',{x:x+1,y:43-height,width:200/31-2,height,rx:1,class:'kpi-bar'}),point.label,point.value));
        svg.append(hint(svgNode('rect',{x,y:0,width:200/31,height:48,class:'kpi-hit'}),point.label,point.value));
      });return svg;
    }
    const severityChart=chart();let offset=0;
    for(const entry of severities){
      const width=unique.length?entry.value/unique.length*200:0;
      if(width)severityChart.append(hint(svgNode('rect',{x:offset,y:13,width,height:22,class:'kpi-severity kpi-severity-'+entry.key}),entry.label,entry.value));
      offset+=width;
    }
    if(!unique.length)severityChart.append(svgNode('path',{d:'M0 24H200',class:'kpi-baseline'}));
    const charts={technologies:technologyChart,recent:dailyChart(daily),indexed:severityChart,critical:dailyChart(criticalDaily,true)};
    const labels={technologies:'Browse '+totals.technologies+' technologies',recent:'View '+totals.recent+' advisories originally published in the last 30 days',indexed:'View all '+totals.indexed+' indexed advisories',critical:'View all '+totals.critical+' critical advisories'};
    document.querySelectorAll('[data-technology-metric]').forEach(button=>{
      const key=button.dataset.technologyMetric,host=button.querySelector('.kpi-chart');host.replaceChildren(charts[key]);
      button.setAttribute('aria-label',labels[key]);
      button.title=labels[key]+'. '+(key==='technologies'?'Chart shows technology groups.':key==='indexed'?'Chart shows current severity distribution.':'Chart shows daily original disclosures, not attack activity.');
      const insight=button.querySelector('.kpi-insight');insight.dataset.default=key==='technologies'?'By technology group':key==='indexed'?'Severity mix · indexed':'Daily disclosures · 30d';insight.textContent=insight.dataset.default;
    });
  }
  function renderCategories(){
    const main=$('categoryGrid'),q=$('technologySearch').value.trim().toLowerCase();
    main.replaceChildren();
    const matches=x=>!q||(x.name+' '+(x.description||'')).toLowerCase().includes(q);
    const enabled=x=>!personalized||personalized.defaults.includes(x.name);
    let visible=0;const groupCounts={microsoft:0,applications:0,infrastructure:0,data:0};
    // Curated product mark lookup. Unknown customer products receive a neutral initial badge.
    // Never construct image URLs from untrusted customer supplied names or domains.
    const productMarks=[
      [/windows server|windows 11|^windows$|hyper[\s-]?v/i,'windows11'],[/^azure|microsoft fabric/i,'microsoftazure'],
      [/microsoft 365|exchange|sharepoint|power platform|dynamics 365/i,'microsoft'],
      [/^\.net|asp\.net/i,'dotnet'],[/wordpress/i,'wordpress'],[/^php$/i,'php'],[/python|pypi/i,'python'],
      [/angular/i,'angular'],[/react|next\.js/i,'react'],[/javascript|typescript/i,'javascript'],
      [/node\.js|npm/i,'nodedotjs'],[/linux/i,'linux'],[/fortinet/i,'fortinet'],[/sophos/i,'sophos'],
      [/vmware/i,'vmware'],[/veeam/i,'veeam'],[/docker|kubernetes/i,'docker'],[/^aws$/i,'amazonaws'],
      [/^sql server/i,'microsoftsqlserver'],[/mysql|mariadb/i,'mysql'],[/mongo/i,'mongodb'],
      [/telerik|kendo/i,'progress'],[/sitefinity/i,'progress'],[/jquery|bootstrap/i,'bootstrap'],
      [/ios|android/i,'android'],[/apache tomcat/i,'apachetomcat'],[/postgresql/i,'postgresql'],
      [/jenkins/i,'jenkins'],[/nginx/i,'nginx'],[/redis/i,'redis'],[/sonicwall/i,'sonicwall'],
      [/drupal/i,'drupal'],[/gitlab/i,'gitlab'],[/grafana/i,'grafana'],[/elastic/i,'elastic'],
    ];
    function productIcon(x){
      const name=String(x.name||'');
      const resolvedSlug=window.CVEHARBOR_CVIE?.product(name)?.icon_slug;
      const slug=resolvedSlug&&/^[a-z0-9]+$/.test(resolvedSlug)?resolvedSlug:productMarks.find(([pattern])=>pattern.test(name))?.[1];
      const node=text('span','technology-glyph technology-brand-icon','');
      node.setAttribute('aria-hidden','true');
      // Use product-specific brand vectors rather than placeholder letter tiles.
      // For unsupported marks the existing neutral initials fallback remains.
      // Local product-specific marks prevent CDN failures from collapsing Microsoft
      // product icons into initials. These identify product families; keep names next
      // to the graphics and do not describe them as licensed official brand artwork.
      const msSvg=(paths)=>'<svg viewBox="0 0 32 32" width="30" height="30" aria-hidden="true" focusable="false">'+paths+'</svg>';
      const microsoftMarks=[
        [/windows server|windows 11|^windows$|hyper[\s-]?v/i,msSvg('<path fill="#00A4EF" d="M2 5 14 3v12H2zm14-2L30 1v14H16zM2 17h12v12L2 27zm14 0h14v14l-14-2z"/>')],
        [/^azure/i,msSvg('<path fill="#0078D4" d="M15 2h9L12 28H3z"/><path fill="#50B1F5" d="m18 11 11 17H13l-4-6h11z"/>')],
        [/microsoft 365/i,msSvg('<path fill="#F35325" d="M2 2h13v13H2z"/><path fill="#81BC06" d="M17 2h13v13H17z"/><path fill="#05A6F0" d="M2 17h13v13H2z"/><path fill="#FFBA08" d="M17 17h13v13H17z"/>')],
        [/exchange/i,msSvg('<path fill="#0078D4" d="M8 3h19a2 2 0 0 1 2 2v22a2 2 0 0 1-2 2H8z"/><path fill="#4DB8E8" d="M3 8h19v16H3z"/><path fill="#FFF" d="M8 12h11v3H11v2h7v3h-7v2h8v2H8z"/>')],
        [/sharepoint/i,msSvg('<circle cx="19" cy="9" r="8" fill="#13B5A6"/><circle cx="22" cy="22" r="8" fill="#047D81"/><circle cx="9" cy="17" r="8" fill="#0D9B91"/><path fill="#fff" d="M5 13h10v2H8v2h6v2H8v2h7v2H5z"/>')],
        [/power platform/i,msSvg('<path fill="#B884F0" d="M4 21 18 3h10L14 21z"/><path fill="#7A3EBA" d="M8 29 22 10h8L16 29z"/><path fill="#E5C3FF" d="M3 21h11l-5 8H3z"/>')],
        [/dynamics/i,msSvg('<path fill="#1769C2" d="M6 2 26 15 6 30z"/><path fill="#41B0FA" d="M6 2 17 12 6 18z"/><path fill="#063A82" d="m6 18 20-3L6 30z"/>')],
        [/fabric|power bi/i,msSvg('<rect x="3" y="17" width="6" height="12" rx="2" fill="#EAAF08"/><rect x="11" y="10" width="6" height="19" rx="2" fill="#F5C728"/><rect x="19" y="4" width="7" height="25" rx="2" fill="#FFD84F"/>')]
      ];
      const microsoftMark=microsoftMarks.find(([pattern])=>pattern.test(name));
      if(microsoftMark){node.classList.add('brand-local');node.innerHTML=microsoftMark[1];return node}
      if(!slug){node.textContent=name.slice(0,2).toUpperCase()||'◇';return node}
      const img=document.createElement('img');
      // Curated icon identifiers only, never a user-provided arbitrary URL.
      // Simple Icons serves the brand's original colour when no colour override is used.
      img.src='https://cdn.simpleicons.org/'+slug;
      img.alt='';img.loading='lazy';img.decoding='async';
      img.addEventListener('error',()=>{img.remove();node.textContent=name.slice(0,2).toUpperCase()||'◇'});
      node.append(img);return node;
    }
    function makeRow(x){
      const horizon=window.CVEHARBOR_CVIE?.months||3;
      const categoryRecords=(x.custom?customMatching(x.name):items.filter(a=>(a.categories||[]).includes(x.name))).filter(a=>inMonths(a,horizon));
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
      const button=document.createElement('div');
      button.className='technology-row';
      button.setAttribute('aria-label',`View ${x.name}: ${ages.TODAY} published today, ${ages.YESTERDAY} yesterday, ${ages['72 HOURS']} two days ago, ${recent} new in 30 days, ${total} total`);
      const icon=productIcon(x);
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
      const nameLine=text('span','technology-name-line',''),nameButton=text('button','technology-row-name technology-name-action',x.name);nameButton.type='button';
      nameButton.addEventListener('click',event=>{event.stopPropagation();const p=window.CVEHARBOR_CVIE?.product(x.name);if(p&&(p.status==='needs_identity'||!p.cpe))window.CVEHARBOR_CVIE.openIdentity(x.name);else openTechnologyAdvisories(x.name,false,horizon===12?'published12m':'published3m')});nameLine.append(nameButton);
      if(catalogueSignedIn&&personalized){const remove=text('button','technology-remove','×');remove.type='button';remove.title='Remove '+x.name+' from my catalogue';remove.setAttribute('aria-label',remove.title);remove.disabled=catalogueSaving;remove.addEventListener('click',event=>{event.stopPropagation();void removeTechnology(x.name)});nameLine.append(remove)}
      label.append(nameLine,freshness);
      const scan=window.CVEHARBOR_CVIE?.product(x.name);
      if(scan){const choosing=scan.status==='needs_identity'||!scan.cpe;const status=text(choosing?'button':'span','cvie-row-state '+scan.status,choosing?'Choose the exact product':window.CVEHARBOR_CVIE.statusFor(scan));if(choosing){status.type='button';status.classList.add('technology-choose');status.addEventListener('click',event=>{event.stopPropagation();window.CVEHARBOR_CVIE.openIdentity(x.name)})}label.append(status);button.setAttribute('aria-label',`View ${x.name}: ${window.CVEHARBOR_CVIE.statusFor(scan)}`);}
      const counts=text('span','technology-row-counts','');
      counts.append(text('span','technology-count-new'+(recent?' has-new':''),`${recent} new`),
                    text('span','technology-count-all',`${scan&&!(horizon===12?scan.history_complete_at:scan.recent_complete_at)&&!total?'—':total} / ${horizon} months`));
      const arrow=text('span','technology-arrow','›');arrow.setAttribute('aria-hidden','true');
      button.append(icon,label,counts,arrow);
      if(x.custom && addedHighlight===x.name){button.classList.add('technology-just-added');button.dataset.customProduct=x.name;}
      // Open the most recent disclosure day shown by this technology's badge.
      const openPeriod=horizon===12?'published12m':'published3m';
      button.addEventListener('click',()=>openTechnologyAdvisories(scan?.name||x.name,false,openPeriod));
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
      if(name===customGroup)continue;
      const additional=new Map((personalized?.products||[]).filter(x=>x.enabled!==false).map(x=>[catalogueKey(x.name),x]));
      // Inventory/watchlist registrations must never become catalogue selections.
      const candidates=[...[...additional.values()].filter(x=>(x.category||inferProductCategory(x.name)||'applications')===name).map(x=>({...x,custom:true,icon:'＋'})),...techs.filter(label=>!additional.has(catalogueKey(label))).map(label=>categories.find(x=>x.name===label))];
      const matched=candidates.filter(x=>x&&matches(x)&&(x.custom||enabled(x)));
      groupCounts[name]=matched.length;
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
      const descriptions={microsoft:'Microsoft products, cloud platforms and enterprise services.',applications:'Development frameworks, runtimes and application platforms.',infrastructure:'Infrastructure, security, virtualization and IT operations.',data:'Databases, language runtimes, UI libraries and dependencies.',custom:'Products added to your private catalogue.'};
      label.append(text('p','technology-panel-description',descriptions[name]||''));
      const totalBox=text('span','technology-panel-total','');
      totalBox.append(text('strong','',String(matched.length).padStart(2,'0')),text('small','','total'));
      head.append(glyph,label,totalBox);
      const rows=text('div','technology-panel-rows','');
      matched.forEach(x=>rows.append(makeRow(x)));
      panel.append(head,rows);main.append(panel);visible+=matched.length;
    }
    $('technologyEmpty').hidden=visible!==0;
    $('technologyEmpty').textContent=personalized&&!personalized.defaults.length&&!personalized.products.some(p=>p.enabled!==false)?'No technologies selected. Customize technologies to choose your catalogue. Shared sources and inventory monitoring continue independently.':'No matching technologies. Try another name or product.';
    main.setAttribute('aria-label',visible+' technologies by group');
    $('technologyTotal').textContent=String(visible);
    $('technologyRecentMetric').textContent=String(advisoryIDs(items.filter(x=>newlyPublished(x,30))).length);
    $('technologyIndexedMetric').textContent=String(advisoryIDs(items).length);
    $('technologyCriticalMetric').textContent=String(advisoryIDs(items.filter(x=>x.severity==='critical')).length);
    renderExplorerMetrics(groupCounts);
    $('technologySearchSummary').textContent=q
      ? `${visible} of ${categories.length} technologies match your search`
      : `${visible} technologies shown. History covers the last ${window.CVEHARBOR_CVIE?.months||3} months. CVIE checks affected product identities for your registered products. Public category totals are limited to the shared index. Zero results do not mean secure.`;
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
    if(['published3m','published12m'].includes(state.period))selected.sort((a,b)=>Number(!!b.retained_exploited)-Number(!!a.retained_exploited)||Number(!!b.known_exploited)-Number(!!a.known_exploited)||String(b.published||'').localeCompare(String(a.published||'')));
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
    const periodNames={published3m:'last 3 months, plus older KEV-listed advisories',published12m:'last 12 months, plus older KEV-listed advisories',today:'originally published today',yesterday:'originally published yesterday',twoDays:'originally published two days ago',published7:'new in the last 7 days',published30:'new in the last 30 days',updated7:'updated in the last 7 days',all:'from the indexed archive'};
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
        if(x.retained_exploited)idCell.append(text('span','kev-mark','Older · CISA KEV'));
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
  function showDetail(x){
    window.CVEHARBOR_ADVISORY_DETAILS.render($('dialogContent'),x,{
      disclosureBadge:makeDisclosureBadge(x),
      onAssign:()=>{
        const dialog=$('detailDialog');
        if(typeof dialog.close==='function')dialog.close();else dialog.removeAttribute('open');
        window.dispatchEvent(new CustomEvent('cveharbor:assign-remediation',{detail:{id:x.id}}));
      }
    });
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
    state.q='';state.tech='all';state.group='all';state.severity='all';state.period='published3m';metricScope='all';resetPaging();
    $('search').value='';$('technologyFilter').value='all';$('severity').value='all';$('dateRange').value='published3m';void window.CVEHARBOR_CVIE?.setMonths(3);render();
  }
  $('search').addEventListener('input',e=>{state.q=e.target.value.trim().toLowerCase();resetPaging();render();});
  $('technologyFilter').addEventListener('change',e=>{state.tech=e.target.value;state.group='all';metricScope='all';resetPaging();render();});
  $('severity').addEventListener('change',e=>{state.severity=e.target.value;metricScope='all';resetPaging();render();});
  $('dateRange').addEventListener('change',e=>{state.period=e.target.value;if(['published3m','published12m'].includes(state.period))void window.CVEHARBOR_CVIE?.setMonths(state.period==='published12m'?12:3);resetPaging();render();});
  $('archiveEmpty').addEventListener('click',()=>{state.period='all';$('dateRange').value='all';resetPaging();render();});
  $('clearFilters').addEventListener('click',clear);$('resetEmpty').addEventListener('click',clear);
  $('showMore').addEventListener('click',()=>{visibleCount+=PAGE_SIZE;render();});
  $('showFewer').addEventListener('click',()=>{visibleCount=PAGE_SIZE;render();revealAdvisories();});
  $('cardViewBtn').addEventListener('click',()=>{listMode='cards';resetPaging();render();});
  $('listViewBtn').addEventListener('click',()=>{listMode='list';resetPaging();render();});
  $('pagePrevious').addEventListener('click',()=>{if(tablePage>0){tablePage--;render();revealAdvisories();}});
  $('pageNext').addEventListener('click',()=>{if((tablePage+1)*TABLE_PAGE_SIZE<filterItems().length){tablePage++;render();revealAdvisories();}});
  document.querySelectorAll('[data-technology-metric]').forEach(button=>{
    const insight=button.querySelector('.kpi-insight');
    button.addEventListener('pointerover',event=>{const point=event.target.closest?.('[data-chart-label]');if(point)insight.textContent=point.dataset.chartLabel;});
    button.addEventListener('pointerleave',()=>{insight.textContent=insight.dataset.default;});
    button.addEventListener('blur',()=>{insight.textContent=insight.dataset.default;});
    button.addEventListener('click',()=>{
      const key=button.dataset.technologyMetric;
      if(key==='technologies'){
        $('technologySearch').value='';renderCategories();
        $('categoryGrid').setAttribute('tabindex','-1');$('categoryGrid').focus({preventScroll:true});
        $('categoryGrid').scrollIntoView({behavior:window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth',block:'start'});return;
      }
      state.q='';state.tech='all';state.group='all';state.severity=key==='critical'?'critical':'all';state.period=key==='recent'?'published30':'all';metricScope='all';
      $('search').value='';$('technologyFilter').value='all';$('severity').value=state.severity;$('dateRange').value=state.period;
      listMode='list';resetPaging();render();revealAdvisories();$('search').focus({preventScroll:true});
    });
  });
  document.querySelectorAll('[data-metric]').forEach(btn=>{
    btn.addEventListener('click',()=>{
      const scope=btn.dataset.metric;
      if(scope==='technologies'){
        // Every technology is already visible in the main explorer.
        if(location.pathname.startsWith('/intelligence')){location.assign('/vulnerabilities/#technology');return;}
        $('technology').scrollIntoView({behavior:window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth',block:'start'});
        return;
      }
      state.q='';state.tech='all';state.group='all';state.severity='all';state.period='all';
      $('search').value='';$('technologyFilter').value='all';$('severity').value='all';$('dateRange').value='all';
      metricScope=scope==='all'?'cves':scope;
      listMode='list';resetPaging();render();
      revealAdvisories();
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
  let draft=null,catalogueSaving=false,catalogueRevision,catalogueEpoch=0;
  const catalogueChanges=typeof BroadcastChannel==='function'?new BroadcastChannel('cveharbor-catalogue-changed'):null;
  const statusMessage=s=>{customizeStatus.textContent=s;$('technologyActionStatus').textContent=s;$('technologyActionStatus').hidden=!$('technologyCustomizer').hidden};
  let draftRevision;
  function catalogueKey(name){return name.normalize('NFKC').trim().toLowerCase().replace(/\s+/g,' ')}
  function selectedSummary(catalogue){
    const names=[...catalogue.defaults,...catalogue.products.filter(p=>p.enabled!==false).map(p=>p.name)];
    const count=new Set(names.map(catalogueKey)).size;
    return count+(count===1?' technology selected':' technologies selected');
  }
  function comparableCatalogue(catalogue){
    return JSON.stringify({defaults:[...catalogue.defaults].sort(),products:catalogue.products.map(p=>({...p,enabled:p.enabled!==false}))});
  }
  function updateSelection(){
    $('technologySelectedCount').textContent=selectedSummary(draft);
    statusMessage('');
    $('technologyScanStatus').textContent='';
  }
  function selectAll(enabled){
    draft.defaults=enabled?[...defaultNames]:[];
    for(const product of draft.products)product.enabled=enabled;
    drawCustomizer();
    updateSelection();
  }
  $('technologySelectAll').addEventListener('click',()=>selectAll(true));
  $('technologyUnselectAll').addEventListener('click',()=>selectAll(false));
  function drawCustomizer(){
    if(!draft)return;
    $('technologySelectedCount').textContent=selectedSummary(draft);
    const choices=$('technologyDefaultChoices');choices.replaceChildren();
    for(const [group,names] of Object.entries(technologyGroups)){
     if(group===customGroup)continue;
     const section=text('fieldset','technology-choice-group','');section.append(text('legend','',groupTitles[group]));choices.append(section);
     for(const x of categories.filter(x=>names.includes(x.name))){
      const label=document.createElement('label'),input=document.createElement('input');
      input.type='checkbox';input.checked=draft.defaults.includes(x.name);
      input.addEventListener('change',()=>{draft.defaults=input.checked?[...new Set([...draft.defaults,x.name])]:draft.defaults.filter(n=>n!==x.name);updateSelection()});
      label.append(input,text('span','',x.name));section.append(label);
     }
    }
    const list=$('technologyCustomList');list.replaceChildren();
    if(!draft.products.length)list.append(text('p','technology-editor-hint','No custom products added.'));
    for(const p of draft.products){
      const row=text('div','technology-custom-item','');
      const label=document.createElement('label');row.append(label);
      const selected=document.createElement('input');selected.type='checkbox';selected.checked=p.enabled!==false;selected.setAttribute('aria-label','Monitor '+p.name);selected.addEventListener('change',()=>{p.enabled=selected.checked;updateSelection()});label.append(selected);
      const scan=window.CVEHARBOR_CVIE?.product(p.name);
      const description=[p.name,p.version,customCategoryNames[p.category||inferProductCategory(p.name)||'applications']];
      if(selected.checked&&scan)description.push(window.CVEHARBOR_CVIE.statusFor(scan));
      label.append(text('span','technology-custom-description',description.filter(Boolean).join(' · ')));
      const remove=text('button','','Remove');remove.type='button';
      remove.addEventListener('click',()=>{draft.products=draft.products.filter(x=>x.name!==p.name);drawCustomizer();updateSelection()});
      row.append(remove);list.append(row);
    }
  }
  manageButton.addEventListener('click',()=>{if(!catalogueSignedIn){$('technologySignInDialog').showModal();return}if(catalogueSaving)return;draft=JSON.parse(JSON.stringify(personalized||{defaults:defaultNames,products:[]}));draftRevision=catalogueRevision;updateSelection();drawCustomizer();$('technologyCustomizer').hidden=false;$('technologyActionStatus').hidden=true;$('technologyCustomizer').scrollIntoView({block:'start',behavior:window.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches?'auto':'smooth'})});
  $('technologySignInClose').addEventListener('click',()=>$('technologySignInDialog').close());
  $('technologySignInDialog').addEventListener('click',event=>{if(event.target===$('technologySignInDialog'))$('technologySignInDialog').close()});
  $('technologyManageClose').addEventListener('click',()=>{$('technologyCustomizer').hidden=true;$('technologyActionStatus').hidden=false});
  $('technologyResetButton').addEventListener('click',()=>{draft={defaults:[...defaultNames],products:[]};drawCustomizer();updateSelection();statusMessage('Defaults restored in the editor. Save to apply.')});
  customForm.addEventListener('reset',()=>queueMicrotask(()=>$('technologyAddName').dispatchEvent(new Event('input'))));
  customForm.addEventListener('submit',async e=>{e.preventDefault();const name=$('technologyAddName').value.trim(),version=$('technologyAddVersion').value.trim();if(!name||!draft||catalogueSaving)return;
    if(draft.products.some(x=>catalogueKey(x.name)===catalogueKey(name))){statusMessage('Product already added.');return}
    if(draft.products.length>=50){statusMessage('Maximum of 50 additional products.');return}
    const category=$('technologyAddCategory').value||inferProductCategory(name)||'applications';
    const vendor=$('technologyAddVendor')?.value.trim()||'',cpe=$('technologyAddCpe')?.value.trim()||'';
    const product={name,version,category,vendor,cpe,...($('technologyAddName').dataset.cvieIdentity?{identity_id:$('technologyAddName').dataset.cvieIdentity}:{})};
    draft.products.push(product);
    customForm.reset();
    drawCustomizer();
    if(!personalized){statusMessage('Reload the saved catalogue before adding a product.');return}
    // Register this product without committing other checkbox edits.
    const products=personalized.products.filter(p=>catalogueKey(p.name)!==catalogueKey(name));
    const added={defaults:personalized.defaults,products:[...products,product]};
    if(await saveCatalogue(added,draftRevision)&&comparableCatalogue(draft)!==comparableCatalogue(added)){
      statusMessage(customizeStatus.textContent+' Other selections are still unsaved.');
    }
  });
  async function saveCatalogue(submission=draft,revision=submission===draft?draftRevision:catalogueRevision){
    if(!submission||catalogueSaving)return false;
    const conflict='Another tab saved a newer catalogue. Your selections are still here. Compare them with the saved catalogue in a new tab, then reload and reapply your changes.';
    $('technologyScanStatus').textContent='';
    if(revision===undefined){statusMessage('Unable to confirm the saved catalogue. Reload before editing.');return false}
    if(revision!==catalogueRevision){statusMessage(conflict);return false}
    if(personalized&&comparableCatalogue(submission)===comparableCatalogue(personalized)){
      statusMessage('No changes to save.');return true;
    }
    const submitted=JSON.parse(JSON.stringify(submission)),epoch=catalogueEpoch;
    const controls=document.querySelectorAll('#technologyCustomizer input, #technologyCustomizer select, #technologyCustomizer button, .technology-remove');
    catalogueSaving=true;
    controls.forEach(el=>el.disabled=true);
    statusMessage('Saving…');
    try{
      const r=await fetch(catalogueAPI,{method:'PUT',credentials:'include',headers:{'content-type':'application/json'},body:JSON.stringify({...submitted,revision})});
      if(epoch!==catalogueEpoch)return false;
      if(r.status===409){statusMessage(conflict);return false}
      const data=await r.json();
      if(epoch!==catalogueEpoch)return false;
      if(!r.ok||data.saved!==true)throw Error(data.error||'The server did not confirm the save.');
      const newest=submitted.products.find(p=>!personalized?.products.some(old=>catalogueKey(old.name)===catalogueKey(p.name)));
      personalized=submitted;catalogueRevision=data.revision;
      if(submission===draft||draftRevision===revision)draftRevision=data.revision;
      addedHighlight=newest?.name||null;applyPersonalized();
      window.CVEHARBOR_CVIE?.applyCatalogue?.(personalized);
      catalogueChanges?.postMessage({changed:true});
      statusMessage(data.unchanged?'No changes to save.':'Catalogue saved. '+selectedSummary(submitted)+'.');
      if(data.cvie?.ready===false){
        $('technologyScanStatus').textContent='Vulnerability checks are pending. See the intelligence panel for scan status.';
      }else if(data.cvie?.queued>0){
        $('technologyScanStatus').textContent='Products registered for vulnerability checks. See the intelligence panel for progress.';
      }
      if(newest)setTimeout(()=>{addedHighlight=null;document.querySelectorAll('.technology-just-added').forEach(x=>x.classList.remove('technology-just-added'))},10000);
      return true;
    }catch(e){
      statusMessage('Unable to save: '+e.message+' Your selections are still here. Try Save my catalogue again.');
      return false;
    }finally{
      catalogueSaving=false;controls.forEach(el=>el.disabled=false);drawCustomizer();renderCategories();
    }
  }
  async function removeTechnology(name){
    if(!personalized||catalogueSaving)return;
    const key=catalogueKey(name);
    const without=state=>({...state,defaults:state.defaults.filter(n=>catalogueKey(n)!==key),products:state.products.map(p=>catalogueKey(p.name)===key?{...p,enabled:false}:p)});
    if(await saveCatalogue(without(personalized))){if(draft){draft=without(draft);drawCustomizer()}statusMessage(name+' removed from your monitored catalogue.');manageButton.focus();}
  }
  $('technologySaveButton').addEventListener('click',()=>{
    if([...customForm.querySelectorAll('input,select')].some(field=>field.value.trim())){
      statusMessage('Your custom product form has entries. Use “Add and scan product” to save it, or “Clear form” before saving your catalogue.');
      return;
    }
    void saveCatalogue();
  });
  function applyPersonalized(){
    const allowed=new Set([...(personalized?.defaults||[]),...(personalized?.products||[]).filter(p=>p.enabled!==false).map(p=>p.name)].map(n=>n.toLowerCase()));
    items=(window.CVEHARBOR_CVIE?.merge(baseItems)||baseItems).filter(r=>!personalized||[...(r.categories||[]),...(r.cvie_products||[])].some(n=>allowed.has(n.toLowerCase())));
    for(const option of $('technologyFilter').options){option.hidden=option.value!=='all'&&!!personalized&&!allowed.has(option.value.toLowerCase());option.disabled=option.hidden}
    if(personalized&&state.tech!=='all'&&!allowed.has(state.tech.toLowerCase())){state.tech='all';$('technologyFilter').value='all'}
    renderCategories();renderBars();renderFocus();render();
  }
  async function loadCatalogue(){
    const epoch=++catalogueEpoch;
    try{
      const me=await fetch('https://api.cveharbor.com/v1/me',{credentials:'include'}).then(r=>r.ok?r.json():null);
      if(epoch!==catalogueEpoch)return;
      if(!me?.authenticated){catalogueSignedIn=false;personalized=null;catalogueRevision=undefined;applyPersonalized();return}
      catalogueSignedIn=true;
      const r=await fetch(catalogueAPI,{credentials:'include'});if(!r.ok)throw Error('Unable to load your saved catalogue.');
      const data=await r.json();if(epoch!==catalogueEpoch)return;
      personalized={defaults:Array.isArray(data.defaults)?data.defaults:defaultNames,products:Array.isArray(data.products)?data.products:[]};catalogueRevision=data.revision;
      manageButton.hidden=false;applyPersonalized();window.CVEHARBOR_CVIE?.applyCatalogue?.(personalized);
    }catch(e){if(epoch===catalogueEpoch)statusMessage(e.message)}
  }
  if(typeof fetch==='function')void loadCatalogue();
  window.addEventListener('cveharbor:account-state',event=>{
    catalogueEpoch++;
    if(!event.detail?.authenticated){catalogueSignedIn=false;personalized=null;draft=null;customForm.reset();catalogueRevision=undefined;$('technologyCustomizer').hidden=true;applyPersonalized();}
    else void loadCatalogue();
  });
  window.addEventListener('focus',()=>{if(!catalogueSaving)void loadCatalogue()});
  if(catalogueChanges)catalogueChanges.onmessage=event=>{if(event.data?.changed&&!catalogueSaving)void loadCatalogue()};
  $('technologySearch').addEventListener('input',renderCategories);
  if(location.pathname.startsWith('/vulnerabilities/')){
    const params=new URLSearchParams(location.search);
    const technology=params.get('technology'),severity=params.get('severity'),period=params.get('period'),scope=params.get('scope'),group=params.get('group');
    if(technology==='all'||categories.some(c=>c.name===technology))state.tech=technology;
    if(['all','critical','high','medium','low'].includes(severity))state.severity=severity;
    if([...$('dateRange').options].some(o=>o.value===period))state.period=period;
    if(['all','cves','critical','high','medium','low'].includes(scope))metricScope=scope;
    if(group==='all'||Object.prototype.hasOwnProperty.call(technologyGroups,group))state.group=group;
    $('technologyFilter').value=state.tech;$('severity').value=state.severity;$('dateRange').value=state.period;
    if(params.has('scope')||params.has('technology'))listMode='list';
  }
  renderBars();renderFocus();renderCategories();render();
  if(window.CVEHARBOR_CVIE?.ready)handleCvieUpdate({detail:{recordsChanged:true}});
})();
