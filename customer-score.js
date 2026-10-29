(function(root){'use strict';
// Versioned, conservative customer inventory assessment. Never score unknown coverage as safe.
const SCORE_VERSION='1.0';
const clamp=(v,min=0,max=100)=>Math.max(min,Math.min(max,v));
function assessCustomer({assets=[],issues=[],checks={},statuses={}}={}){
 const total=assets.length;
 const withVersion=assets.filter(a=>String(a.version||'').trim()&&!/^(unknown|n\/a)$/i.test(a.version)).length;
 const pluginAssets=assets.filter(a=>String(a.technology||'').startsWith('WordPress Plugin: '));
 const monitored=pluginAssets.filter(a=>checks[a.id]?.status==='checked'&&checks[a.id]?.installed_version===a.version);
 const coverage=total?Math.round(100*(withVersion-pluginAssets.length+monitored.length+pluginAssets.filter(a=>!String(a.version||'').trim()).length)/total):0;
 const coverageBound=clamp(coverage);
 const versionCandidates=issues.filter(i=>i.level==='version_review');
 // A reviewer must document applicability before candidate advisories can determine a risk score.
 const evidenceCount=versionCandidates.filter(i=>statuses[i.asset_id+'|'+i.id]==='Fixed/Patched').length;
 const riskReady=total>=1&&coverageBound>=70&&versionCandidates.length>=1;
 const confidence=coverageBound>=90?'High':coverageBound>=70?'Medium':'Low';
 const open=versionCandidates.filter(i=>!['Fixed/Patched','Not Applicable'].includes(statuses[i.asset_id+'|'+i.id]));
 const weights={critical:12,high:7,medium:4,low:2};
 const exposure=Math.min(50,open.reduce((sum,i)=>sum+(weights[String(i.severity||'').toLowerCase()]||3)*(i.known_exploited?1.5:1),0));
 const outdated=pluginAssets.filter(a=>checks[a.id]?.release?.update_status==='Update Available').length;
 const currency=Math.min(25,outdated*2);
 const remediation=versionCandidates.length?Math.min(15,Math.round(15*open.length/versionCandidates.length)):0;
 const coveragePenalty=Math.round((100-coverageBound)/10);
 const parts={exposure:Math.round(exposure),currency,remediation,monitoring:coveragePenalty};
 const score=riskReady?clamp(100-Object.values(parts).reduce((a,b)=>a+b,0)):null;
 return {version:SCORE_VERSION,score,confidence,coverage:coverageBound,parts,
  total_assets:total,checked_plugins:monitored.length,plugin_assets:pluginAssets.length,
  candidates:versionCandidates.length,open_candidates:open.length,reviewed_fixes:evidenceCount,
  explanation:score===null?'Insufficient Data: monitoring coverage or version evidence is insufficient.':'Provisional inventory based assessment. Candidate findings require independent verification.'};
}

root.CVEHARBOR_SCORE={assessCustomer,SCORE_VERSION};
})(window);
