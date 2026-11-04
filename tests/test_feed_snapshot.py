import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import feed_snapshot as f

class MemoryStore:
 def __init__(self):self.data={};self.fail=None
 def get(self,key):
  value=self.data.get(key);return value,f.digest(value) if value is not None else None
 def immutable(self,key,body):
  if self.fail and key.startswith(self.fail):raise OSError('simulated upload failure')
  if key in self.data and self.data[key]!=body:raise ValueError('immutable')
  self.data[key]=body
 def compare_set(self,key,body,etag):
  if self.fail=='pointer':raise OSError('simulated promotion failure')
  if self.get(key)[1]!=etag:raise ValueError('concurrent publication')
  self.data[key]=body

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

class SnapshotTests(unittest.TestCase):
 def setUp(self):self.store=MemoryStore();self.files=synthetic_files();self.first=f.publish(self.store,self.files,None)
 def test_complete_atomic_publish_restore_and_history(self):
  changed=dict(self.files);changed['attack-scanning-current.txt']=b'192.0.2.2\n';_,etag=f.pointer(self.store)
  second=f.publish(self.store,changed,etag,self.first['manifest'])
  self.assertEqual(f.load_files(self.store,f.load_manifest(self.store,self.first['manifest'])),self.files)
  with tempfile.TemporaryDirectory() as temp:
   _,_,restored=f.restore(self.store,Path(temp));self.assertEqual(restored,changed)
   self.assertEqual((Path(temp)/'data/threat-ip-history.json').read_bytes(),self.files['data/threat-ip-history.json'])
  self.assertEqual(second['previous'],self.first['manifest'])
 def test_upload_failure_retains_current(self):
  self.store.fail='objects/';p,_=f.pointer(self.store)
  with self.assertRaises(OSError):f.publish(self.store,self.files,self.store.get('current.json')[1],p['manifest'])
  self.assertEqual(f.pointer(self.store)[0],p)
 def test_manifest_failure_retains_current(self):
  self.store.fail='manifests/';p,e=f.pointer(self.store)
  with self.assertRaises(OSError):f.publish(self.store,self.files,e,p['manifest'])
  self.assertEqual(f.pointer(self.store)[0],p)
 def test_promotion_failure_retains_current(self):
  self.store.fail='pointer';p,e=f.pointer(self.store)
  with self.assertRaises(OSError):f.publish(self.store,self.files,e,p['manifest'])
  self.assertEqual(f.pointer(self.store)[0],p)
 def test_stale_writer_cannot_overwrite(self):
  p,e=f.pointer(self.store);f.publish(self.store,self.files,e,p['manifest'])
  with self.assertRaisesRegex(ValueError,'concurrent'):f.publish(self.store,self.files,e,p['manifest'])
 def test_corruption_fails_before_restore(self):
  m=f.load_manifest(self.store,self.first['manifest']);self.store.data[m['files']['data.js']['key']]=b'bad'
  with tempfile.TemporaryDirectory() as temp:
   with self.assertRaises(ValueError):f.restore(self.store,Path(temp))
   self.assertEqual(list(Path(temp).iterdir()),[])
 def test_incomplete_snapshot_rejected(self):
  files=dict(self.files);files.pop('lifecycle.js')
  with self.assertRaises(ValueError):f.publish(self.store,files,None)
 def test_script_injection_is_not_data(self):
  with self.assertRaises(ValueError):f.decode('data.js',b'window.CVEHARBOR_DATA = {}; alert(1);')
  body=f.restore_body('data.js',f.encoded({'x':'</script><script>alert(1)</script>'}))
  self.assertNotIn(b'</script>',body)
 def test_retained_data_is_not_retimestamped(self):
  with tempfile.TemporaryDirectory() as temp:
   def failure(script):raise TimeoutError()
   report=f.collect(self.store,Path(temp),failure)
   self.assertTrue(report['degraded'])
   self.assertEqual(f.load_files(self.store,f.load_manifest(self.store,report['current']['manifest'])),self.files)
 def test_successful_collection_independent_of_deployment(self):
  with tempfile.TemporaryDirectory() as temp:
   result=f.collect(self.store,Path(temp),lambda _:SimpleNamespace(returncode=0))
   self.assertFalse(result['degraded'])
   self.assertEqual(set(result['collection']),set(f.GROUPS))
 def test_stale_advisories_rejected_not_relabelled(self):
  with self.assertRaisesRegex(ValueError,'Stale'):f.validate_group('advisories',synthetic_files(9))
 def test_partial_lifecycle_retains_failed_product_and_timestamp(self):
  old=synthetic_files(30);fresh=copy.deepcopy(self.files)
  obj=json.loads(fresh['lifecycle.js']);obj['cycles']=[{'slug':'wordpress','latest':'7.0'}];obj['errors']=[{'product':'php'}];fresh['lifecycle.js']=f.encoded(obj)
  result=f.preserve_partial('lifecycle',fresh,old);rows=json.loads(result['lifecycle.js'])['cycles']
  self.assertEqual(rows[-1]['_feed_last_success'],json.loads(old['lifecycle.js'])['checked_at'])
  self.assertEqual(rows[0]['slug'],'wordpress')
 def test_partial_patch_notes_preserve_failed_vendor(self):
  old=synthetic_files(30);fresh=dict(self.files);data=json.loads(fresh['patch-notes.js']);data['releases']=[{'slug':'dotnet','version':'12.0'}];data['errors']=[{'source':'php/php-src'}];fresh['patch-notes.js']=f.encoded(data)
  rows=json.loads(f.preserve_partial('patch_notes',fresh,old)['patch-notes.js'])['releases']
  self.assertEqual(rows[-1]['slug'],'php');self.assertEqual(rows[-1]['_feed_last_success'],json.loads(old['patch-notes.js'])['checked_at'])
 def test_known_group_failure_does_not_block_other_updates(self):
  with tempfile.TemporaryDirectory() as temp:
   def run(script):
    if script=='update_lifecycle.py':raise TimeoutError()
    return SimpleNamespace(returncode=0)
   result=f.collect(self.store,Path(temp),run)
   self.assertEqual(result['collection']['lifecycle']['status'],'retained');self.assertEqual(result['collection']['advisories']['status'],'published')
 def test_allowlist_cannot_overwrite_source(self):
  with self.assertRaises(ValueError):f.decode('account-backend/src/index.js',b'{}')

class StagingTargetTests(unittest.TestCase):
 def test_staging_target_denies_production_or_nonempty_unknown_target(self):
  from rehearse_intelligence_r2 import validate_target
  env={'FEED_R2_ACCOUNT_ID':'a'*32,'PRODUCTION_ACCOUNT_ID':'b'*32,'FEED_R2_BUCKET':'cveharbor-intelligence-staging-synthetic','FEED_STAGING_DISPOSABLE':'true'}
  validate_target(env)
  for changes in [{'PRODUCTION_ACCOUNT_ID':'a'*32},{'PRODUCTION_ACCOUNT_ID':''},{'FEED_R2_BUCKET':'cveharbor-intelligence'},{'FEED_STAGING_DISPOSABLE':'false'}]:
   with self.assertRaises(ValueError):validate_target(dict(env,**changes))

class S3ContractTests(unittest.TestCase):
 def test_production_adapter_requires_conditional_writes_and_scoped_endpoint(self):
  import io
  from unittest.mock import patch
  from types import ModuleType
  calls=[]
  class ClientError(Exception):pass
  class Client:
   def put_object(self,**kwargs):calls.append(kwargs)
   def get_object(self,**kwargs):return {'Body':io.BytesIO(b'fixture'),'ETag':'"etag"'}
  boto=ModuleType('boto3');boto.client=lambda *args,**kw:(calls.append(kw) or Client())
  config=ModuleType('botocore.config');config.Config=lambda **kw:kw
  errors=ModuleType('botocore.exceptions');errors.ClientError=ClientError
  env={'FEED_R2_ACCOUNT_ID':'a'*32,'FEED_R2_BUCKET':'cveharbor-intelligence-staging-fixture','FEED_R2_ACCESS_KEY_ID':'synthetic','FEED_R2_SECRET_ACCESS_KEY':'synthetic'}
  with patch.dict(sys.modules,{'boto3':boto,'botocore.config':config,'botocore.exceptions':errors}),patch.dict(f.os.environ,env):
   store=f.S3Store();store.immutable('objects/test',b'test');store.compare_set('current.json',b'{}','"expected"');store.compare_set('current.json',b'{}',None)
   self.assertEqual(store.get('current.json'),(b'fixture','"etag"'))
  self.assertEqual(calls[0]['endpoint_url'],'https://'+'a'*32+'.r2.cloudflarestorage.com')
  self.assertEqual(calls[1]['IfNoneMatch'],'*');self.assertEqual(calls[2]['IfMatch'],'"expected"');self.assertEqual(calls[3]['IfNoneMatch'],'*')
