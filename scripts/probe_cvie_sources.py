#!/usr/bin/env python3
"""Read-only NVD compatibility probe. Never modifies runtime or customer data."""
import json
import calendar
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

now=datetime.now(timezone.utc)
month=now.month-3
year=now.year
if month<1:month+=12;year-=1
start=now.replace(year=year,month=month,day=min(now.day,calendar.monthrange(year,month)[1]))
params={'virtualMatchString':'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*',
        'pubStartDate':start.isoformat(timespec='milliseconds').replace('+00:00','Z'),
        'pubEndDate':now.isoformat(timespec='milliseconds').replace('+00:00','Z'),
        'resultsPerPage':5,'startIndex':0}
report={'checked_at':now.isoformat(),'provider':'NVD','ok':False,'operation':'read-only product history query','parameters':params}
try:
    headers={'Accept':'application/json','User-Agent':'CVEHarbor-CVIE-Compatibility/1.0'}
    if os.environ.get('NVD_API_KEY'):headers['apiKey']=os.environ['NVD_API_KEY']
    url='https://services.nvd.nist.gov/rest/json/cves/2.0?'+urllib.parse.urlencode(params)
    with urllib.request.urlopen(urllib.request.Request(url,headers=headers),timeout=30) as response:data=json.loads(response.read(3000000))
    if not isinstance(data.get('vulnerabilities'),list) or not isinstance(data.get('totalResults'),int):raise ValueError('Invalid NVD page')
    report.update(ok=True,total_results=data['totalResults'],sample=data['vulnerabilities'],start_index=data.get('startIndex'))
except urllib.error.HTTPError as exc:report['error']='NVD HTTP '+str(exc.code)
except Exception as exc:report['error']=type(exc).__name__
Path('data/cvie-provider-check.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({key:value for key,value in report.items() if key!='sample'}))
