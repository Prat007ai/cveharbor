(() => {
'use strict';
// Shared DOM remains available for legacy popup and data scripts while
// page-specific layouts are split across canonical GitHub Pages URLs.
const map={
  technology:'/vulnerabilities/',advisories:'/vulnerabilities/',dashboard:'/',
  securityWorkspace:'/alerts/',disclosureTrend:'/alerts/',
  'threat-intelligence':'/threats/','malware-intelligence':'/malware/',
  lifecycleMonitor:'/lifecycle/',inventoryWorkspace:'/environments/',
  operationsCentre:'/admin-tools/',patchTracker:'/admin-tools/',
  versionChecker:'/admin-tools/',firewallCentre:'/admin-tools/',
  remediationTracker:'/remediation/',methodology:'/'
};
const pages=new Set(['/','/vulnerabilities/','/alerts/','/threats/','/malware/','/lifecycle/',
 '/environments/','/admin-tools/','/remediation/']);
const path=window.location.pathname.replace(/\/index\.html$/,'/');
const page=pages.has(path)?path:'/';
document.body.dataset.page=page==='/'?'home':page.slice(1,-1);
const section=window.location.hash.slice(1);
if(path==='/'&&section&&map[section]&&map[section]!=='/'){
 window.location.replace(map[section]+'#'+encodeURIComponent(section));
 return;
}
document.addEventListener('click',event=>{
 // The homepage overview cards previously scrolled to a list that is now
 // located on a dedicated page. Keep the action meaningful after migration.
 if(path==='/'&&event.target.closest?.('button.metric-action,button.tech-chart-link,.chart-insight')){
  event.preventDefault();
  event.stopImmediatePropagation();
  window.location.assign('/vulnerabilities/#advisories');
  return;
 }

 const link=event.target.closest?.('a[href^="#"]');
 if(!link)return;
 const target=decodeURIComponent(link.getAttribute('href').slice(1));
 const destination=map[target];
 if(destination&&destination!==path){
  event.preventDefault();window.location.assign(destination+'#'+encodeURIComponent(target));
 }
});
const titles={
 '/':'Vulnerability Intelligence Dashboard',
 '/vulnerabilities/':'Vulnerability Search & Technology Coverage',
 '/alerts/':'My Technology Watchlist & Security Alerts',
 '/threats/':'Threat IP Intelligence',
 '/malware/':'Malware & Ransomware Intelligence',
 '/lifecycle/':'End of Support & Patch Watch',
 '/environments/':'My Customer Environments',
 '/admin-tools/':'Security Administration Toolkit',
 '/remediation/':'Vulnerability Remediation Tracker'
};
if(titles[path]&&path!=='/')document.title=titles[path]+' | CVEHarbor';
const heading=document.getElementById('pageSectionIntro');
if(heading){
 heading.hidden=path==='/';
 const label=heading.querySelector('h1');
 if(label)label.textContent=titles[path]||'CVEHarbor';
}
const nav=document.querySelector('.topnav');
nav?.querySelectorAll('a').forEach(link=>{
 try{
  const dest=new URL(link.href,location.origin);
  if(dest.pathname===path&&path!=='/')link.setAttribute('aria-current','page');
 }catch(_){}
});
})();
