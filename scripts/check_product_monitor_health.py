"""Read-only independent watchdog, reused by the existing hourly GitHub workflow."""
import json
import time

def assess(report, now):
    problems=[]
    if not report.get('last_run') or now-report['last_run']>3*3600000:problems.append('Product monitoring scheduler has no completed run within three hours')
    if report.get('stale_sources',0):problems.append('Subscribed official sources are stale or failing')
    if report.get('oldest_pending') and now-report['oldest_pending']>2*86400000:problems.append('Notification backlog exceeds two days')
    if report.get('unknown_submissions',0):problems.append('SMTP2GO submission acceptance requires reconciliation; do not resend automatically')
    if report.get('recent_messages',0)>=5 and report.get('recent_failures',0)/report['recent_messages']>=0.2:problems.append('SMTP2GO failure/suppression rate is at least twenty percent')
    return problems

def main():
    import os
    from deploy_site_gate import cloudflare
    from verify_cvie_production import query
    settings=cloudflare('/accounts/'+os.environ['CLOUDFLARE_ACCOUNT_ID']+'/workers/scripts/cveharbor-accounts/settings')
    flags={b.get('name'):b.get('text') for b in settings.get('bindings',[]) if b.get('type')=='plain_text' and b.get('name')=='PRODUCT_MONITOR_CHECKS_ENABLED'}
    if flags.get('PRODUCT_MONITOR_CHECKS_ENABLED')!='true':
        print('Product monitoring activation is pending; no source, customer or notification rows queried.')
        return
    now=int(time.time()*1000)
    report=query('SELECT MAX(completed_at) AS last_run FROM lifecycle_monitor_runs')[0]
    report.update(query("SELECT COUNT(*) AS stale_sources FROM lifecycle_monitor_sources x WHERE (x.last_success_at IS NULL OR x.last_success_at<"+str(now-3*86400000)+" OR x.failures>0) AND EXISTS(SELECT 1 FROM lifecycle_monitor_products p JOIN lifecycle_watch_settings s ON s.product_id=p.id WHERE p.source_id=x.id AND s.status='enabled')")[0])
    report.update(query("SELECT MIN(n.created_at) AS oldest_pending FROM lifecycle_monitor_notifications n LEFT JOIN lifecycle_monitor_messages m ON m.id=n.message_id WHERE n.state='pending' OR (n.state='queued' AND m.state IN('pending','submitting'))")[0])
    report.update(query("SELECT SUM(CASE WHEN state='submission_unknown' THEN 1 ELSE 0 END) AS unknown_submissions,COUNT(*) AS recent_messages,SUM(CASE WHEN state IN('failed','suppressed') THEN 1 ELSE 0 END) AS recent_failures FROM lifecycle_monitor_messages WHERE created_at>"+str(now-86400000))[0])
    report={k:(v or 0) for k,v in report.items()}
    print(json.dumps({'monitoring_health':report,'production_writes':0}))
    problems=assess(report,now)
    if problems:raise SystemExit('; '.join(problems)+'. This GitHub Actions failure is independent of SMTP2GO; repository failure notifications must be enabled by an administrator.')
    print('PASS: product monitoring scheduler, source freshness, backlog and submission health')

if __name__=='__main__':main()
