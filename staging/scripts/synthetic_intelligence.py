"""Synthetic publication fixtures. No customer or live provider input is accepted."""
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import feed_snapshot as f

def synthetic_files(age=0):
 stamp=(datetime.now(timezone.utc)-timedelta(hours=age)).isoformat();day=stamp[:10]
 advisory={'snapshotDate':day,'advisories':[{'id':'CVE-2099-12345','published':day,'updated':day,'severity':'critical','categories':['PHP'],'sources':[]}], 'last_successful_update':stamp,'mode':'live'}
 files={name:f.encoded({}) if name.endswith('.json') or name in f.GLOBALS else b'192.0.2.1\n' for name in f.FILES}
 files.update({'data.js':f.encoded(advisory),'data/advisories.json':f.encoded(advisory),
  'data/feed-health.json':f.encoded({'last_successful_update':stamp,'mode':'live'}),
  'workspace-intelligence.json':f.encoded(f.project(advisory)),
  'lifecycle.js':f.encoded({'checked_at':stamp,'cycles':[{'slug':'php','product':'PHP','cycle':'8.3','latest':'8.3.10'}],'errors':[]}),
  'patch-notes.js':f.encoded({'checked_at':stamp,'releases':[{'slug':'php','version':'8.3.10','url':'https://example.invalid/release'}],'errors':[]}),
  'malware-data.js':f.encoded({'sources':{'synthetic':{'ok':True}},'samples':[]}),
  'threat-data.js':f.encoded({'mode':'live','sources':{'synthetic':{'ok':True}},'indicators':[]}),
  'data/threat-ip-history.json':f.encoded({'historical_marker':'preserve me','all_ips':['192.0.2.1']}),
  'data/ip-geolocation-cache.json':f.encoded({'192.0.2.1':{'country':'synthetic'}})})
 return files

