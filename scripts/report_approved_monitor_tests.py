"""Read only the two approved test receipts; no key values or customer rows."""
import json, time, os
from datetime import datetime, timezone
from pathlib import Path
from verify_cvie_production import query
PREFIX='monitor-approved-20261101:'
if datetime.now(timezone.utc)>=datetime(2026,11,3,tzinfo=timezone.utc):
    print('One-time approved test window has expired; no tests requested by this release.')
    raise SystemExit(0)
report={}
for attempt in range(10):
    rows=query("SELECT key FROM auth_rate_limits WHERE key LIKE 'monitor-approved-20261101:%:result:%'")
    report={}
    for row in rows:
        key=row['key']; index=key[len(PREFIX):].split(':',1)[0]
        report['gmail' if index=='0' else 'work']=json.loads(key.split(':result:',1)[1])
    if len(report)==2 and all(item.get('state')!='submitted' or item.get('checks',0)>=6 for item in report.values()):break
    if attempt<9:time.sleep(20)
Path('work').mkdir(exist_ok=True)
Path('work/approved-monitor-tests.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
if os.environ.get('GITHUB_STEP_SUMMARY'):
    with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as out:out.write('\n### Approved Worker SMTP2GO tests\n\n```json\n'+json.dumps(report,indent=2)+'\n```\nSubmitted is provider acceptance; delivered is recipient-server acknowledgment, not inbox placement.\n')
if not report:raise SystemExit('No Worker test receipts yet; no email success claimed. Inspect scheduled execution.')
