// Shared read-only advisory content for the explorer and customer finding dialogs.
(()=>{
'use strict';
  const text = (tag, className, content) => {const n=document.createElement(tag);if(className)n.className=className;n.textContent=content??'';return n;};
  const fmtDate = s => {if(!s||!/^\d{4}-\d{2}-\d{2}/.test(s))return 'Not available';let d=new Date(s.slice(0,10)+'T12:00:00Z');return Number.isFinite(d.getTime())?d.toLocaleDateString('en-CA',{year:'numeric',month:'short',day:'numeric',timeZone:'UTC'}):'Not available';};
  const fmtStamp = s => {if(!s)return 'Never';let d=new Date(s);return Number.isFinite(d.getTime())?d.toLocaleString('en-CA',{dateStyle:'medium',timeStyle:'short',timeZone:'UTC'})+' UTC':'Not available';};
  const severityText=s=>({critical:'CRITICAL',high:'HIGH',medium:'MEDIUM',low:'LOW',unrated:'UNRATED',bulletin:'BULLETIN'})[s]||'UNKNOWN';
  function rowSpec(name,value){const el=text('div','spec','');el.append(text('small','',name),text('b','',value===null||value===undefined||value===''?'Not confirmed':value));return el;}
  function render(root,x,options={}){
    root.replaceChildren();
    root.append(text('span','cat-badge',(x.categories||[]).join(' · ')),text('h2','',x.title||x.id));
    const detailMarkers=text('div','detail-labels','');
    const firstPublished=options.disclosureBadge;
    if(firstPublished)detailMarkers.append(firstPublished);
    detailMarkers.append(text('span','severity-badge '+x.severity,severityText(x.severity)));
    root.append(detailMarkers);
    if(options.context)root.append(options.context);
    const specs=text('div','spec-grid','');specs.append(rowSpec('Advisory ID',x.id),rowSpec('First published',fmtDate(x.published)),rowSpec('Last source update',fmtDate(x.updated)),rowSpec('First indexed',x.first_seen_at?fmtStamp(x.first_seen_at):'Not available'),rowSpec('Source status',x.status||'Vendor/source verification required'),rowSpec('Exploitation',x.exploitation));if(x.cvss!==null&&x.cvss!==undefined&&x.cvss!=='')specs.append(rowSpec('Reported CVSS',x.cvss));if(typeof x.epss==='number')specs.append(rowSpec('FIRST EPSS, 30 day exploitation probability',(x.epss*100).toFixed(2)+'% ('+(x.epss_as_of||'date not available')+')'));root.append(specs);
    function block(h,body){root.append(text('h3','',h),text('p','',body||'Not provided by the indexed source.'));}
    if(typeof x.epss==='number')root.append(text('p','epss-note','EPSS estimates exploitation probability within 30 days. It is not a vulnerability severity score or proof that your environment is affected. Source: FIRST EPSS.'));block('Description',x.summary||x.title);block('Affected software and versions',x.affected);block('Fix or workaround',x.remediation);block('Suggested next step',x.action);
    if(x.source_conflicts?.length)block('Source differences requiring review',x.source_conflicts.join(' '));
    if(x.kev_added)block('CISA exploitation evidence','Added to KEV: '+x.kev_added+'. '+(x.kev_required_action||'Review the CISA entry and vendor guidance.')+(x.kev_due_date?' CISA catalogue due date: '+x.kev_due_date+'.':''));
    if(x.provenance?.length)block('Source verification',x.provenance.map(p=>p.source+' · checked '+fmtStamp(p.checked_at)+' · source revision '+(p.updated||'not stated')).join('\n'));
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
    if(options.onAssign&&/^CVE-\d{4}-\d{4,}$/i.test(String(x.id||''))){
      const assign=text('button','ops-download remediation-detail-assign','Assign vulnerability by email');
      assign.type='button';assign.addEventListener('click',options.onAssign);root.append(assign);
    }
    root.append(text('p','disclaimer','CVEHarbor aggregates public third-party advisory data. This record does not establish that your environment is vulnerable. Verify the primary vendor bulletin, affected versions, and patch applicability.'));
  }
  window.CVEHARBOR_ADVISORY_DETAILS={render};
})();
