#!/usr/bin/env python3
"""Versioned data-only snapshots. No repository writes, deployments, mail or D1.

R2 S3 credentials must be limited to the dedicated bucket. Conditional writes
are mandatory: an endpoint without If-Match support must fail staging validation.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from build_workspace_intelligence import project

ROOT = Path(__file__).resolve().parents[1]
GLOBALS = {'data.js':'CVEHARBOR_DATA', 'malware-data.js':'CVEHARBOR_MALWARE',
           'threat-data.js':'CVEHARBOR_THREATS', 'lifecycle.js':'CVEHARBOR_LIFECYCLE',
           'patch-notes.js':'CVEHARBOR_PATCH_NOTES'}
GROUPS = {
 'advisories':['data/advisories.json','data/feed-health.json','data.js','workspace-intelligence.json'],
 'malware':['malware-data.js'],
 'threats':['threat-data.js','data/threat-ip-history.json','data/ip-geolocation-cache.json',
            'attack-scanning-current.txt','attack-scanning-current.csv','attack-scanning-current.json',
            'fortigate-threat-ip-objects.txt','sophos-threat-ip-api.txt',
            'fortigate-suspicious-ip-initial.txt','fortigate-suspicious-ip-incremental.txt',
            'sophos-suspicious-ip-initial.txt','sophos-suspicious-ip-incremental.txt'],
 'lifecycle':['lifecycle.js'], 'patch_notes':['patch-notes.js']}
FILES = set(sum(GROUPS.values(), []))
SCRIPTS = dict(zip(GROUPS, ['update.py','update_malware.py','update_threats.py','update_lifecycle.py','update_patch_notes.py']))
MAX_BYTES = 32 * 1024 * 1024

def encoded(value):
 return json.dumps(value,ensure_ascii=False,separators=(',',':'),sort_keys=True,allow_nan=False).encode()
def digest(body): return hashlib.sha256(body).hexdigest()
def decode(name, body):
 if name not in FILES or len(body)>MAX_BYTES: raise ValueError('Unknown/oversized feed file')
 text=body.decode('utf-8')
 if name in GLOBALS:
  match=re.fullmatch(r'(?:/\*[^*]*\*/\s*)?window\.'+GLOBALS[name]+r'\s*=\s*(\{[\s\S]*\})\s*;\s*',text)
  if not match: raise ValueError('Invalid data assignment: '+name)
  value=json.loads(match[1])
 elif name.endswith('.json'): value=json.loads(text)
 else: return body
 if not isinstance(value,dict): raise ValueError('Feed object required: '+name)
 return encoded(value)
def restore_body(name, body):
 if name in GLOBALS:
  # Never execute stored text: parse JSON and construct only a fixed assignment.
  value=json.loads(body)
  return ('window.'+GLOBALS[name]+' = '+encoded(value).decode().replace('<','\\u003c')+';\n').encode()
 return body

def check_manifest(manifest):
 if manifest.get('schema')!=1 or set(manifest.get('files',{}))!=FILES: raise ValueError('Incomplete/unknown snapshot')
 for entry in manifest['files'].values():
  if not re.fullmatch(r'[a-f0-9]{64}',entry.get('sha256','')) or entry.get('key')!='objects/'+entry['sha256'] or not isinstance(entry.get('bytes'),int) or not 0<=entry['bytes']<=MAX_BYTES:
   raise ValueError('Invalid snapshot entry')
 return manifest

def pointer(store):
 body,etag=store.get('current.json')
 if body is None:return None,None
 p=json.loads(body)
 if p.get('schema')!=1 or not re.fullmatch(r'manifests/[a-f0-9]{64}\.json',p.get('manifest','')):raise ValueError('Invalid current pointer')
 return p,etag

def load_manifest(store,key):
 if not re.fullmatch(r'manifests/[a-f0-9]{64}\.json',key):raise ValueError('Invalid manifest key')
 body,_=store.get(key)
 if body is None or digest(body)!=key[10:-5]:raise ValueError('Missing/corrupt manifest')
 return check_manifest(json.loads(body))

def load_files(store,manifest):
 result={}
 for name,entry in manifest['files'].items():
  body,_=store.get(entry['key'])
  if body is None or len(body)!=entry['bytes'] or digest(body)!=entry['sha256']:raise ValueError('Missing/corrupt object: '+name)
  result[name]=body
 return result

def restore(store,root):
 p,etag=pointer(store)
 if not p:raise ValueError('No initialized snapshot; seed explicitly from a reviewed complete baseline')
 manifest=load_manifest(store,p['manifest']); files=load_files(store,manifest)
 # Validate everything before changing the disposable collection workspace.
 for name,body in files.items():
  target=root/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(restore_body(name,body))
 return p,etag,files

def publish(store,files,expected,previous=None,report=None):
 if set(files)!=FILES:raise ValueError('Complete snapshot required')
 entries={}
 for name,body in sorted(files.items()):
  if len(body)>MAX_BYTES:raise ValueError('Object too large')
  sha=digest(body);key='objects/'+sha
  store.immutable(key,body)
  actual,_=store.get(key)
  if actual!=body:raise ValueError('Object readback failed')
  entries[name]={'key':key,'sha256':sha,'bytes':len(body)}
 manifest={'schema':1,'created_at':datetime.now(timezone.utc).isoformat(),
           'source_revision':os.environ.get('GITHUB_SHA','local'), 'files':entries,
           'previous':previous,'collection':report or {}}
 raw=encoded(manifest);key='manifests/'+digest(raw)+'.json';store.immutable(key,raw)
 load_manifest(store,key)
 current={'schema':1,'manifest':key,'previous':previous}
 store.compare_set('current.json',encoded(current),expected)
 return current

def group_files(root,group):
 if group=='advisories':
  obj=json.loads((root/'data/advisories.json').read_text());(root/'workspace-intelligence.json').write_bytes(encoded(project(obj)))
 return {name:decode(name,(root/name).read_bytes()) for name in GROUPS[group]}

def preserve_partial(group,fresh,previous):
 if group not in ('lifecycle','patch_notes'):return fresh
 name=GROUPS[group][0];data=json.loads(fresh[name]);old=json.loads(previous[name]);field='cycles' if group=='lifecycle' else 'releases'
 if group=='lifecycle':
  failed={e.get('product') for e in data.get('errors',[]) if e.get('product')!='product-directory'}
  if any(e.get('product')=='product-directory' for e in data.get('errors',[])):data['available_products']=old.get('available_products',[])
 else:
  sources={'dotnet/runtime':'dotnet','PowerShell/PowerShell':'powershell','php/php-src':'php','WordPress/wordpress-develop':'wordpress','MariaDB/server':'mariadb','kubernetes/kubernetes':'kubernetes','Microsoft SQL Server official servicing index':'mssqlserver'}
  failed={sources.get(e.get('source'),'unknown') for e in data.get('errors',[])}
 rows=[dict(row,_feed_last_success=data['checked_at']) for row in data.get(field,[]) if row.get('slug') not in failed]
 if not rows:raise ValueError('No successful lifecycle/release sources')
 rows += [dict(row,_feed_last_success=row.get('_feed_last_success') or old['checked_at']) for row in old.get(field,[]) if row.get('slug') in failed]
 data[field]=rows;fresh[name]=encoded(data);return fresh

def validate_group(group,files):
 if group=='advisories':
  data=json.loads(files['data.js']);health=json.loads(files['data/feed-health.json'])
  if data!=json.loads(files['data/advisories.json']) or not isinstance(data.get('advisories'),list):raise ValueError('Advisory mismatch')
  if data.get('last_successful_update')!=health.get('last_successful_update'):raise ValueError('Health timestamp mismatch')
  age=datetime.now(timezone.utc).timestamp()-datetime.fromisoformat(health['last_successful_update'].replace('Z','+00:00')).timestamp()
  if age< -300 or age>8*3600 or health.get('mode') not in ('live','partial'):raise ValueError('Stale/unavailable vulnerability collection')
 elif group in ('lifecycle','patch_notes'):
  obj=json.loads(files[GROUPS[group][0]]);field='cycles' if group=='lifecycle' else 'releases'
  if not isinstance(obj.get(field),list) or not obj[field]:raise ValueError('Incomplete lifecycle/release collection')
  age=datetime.now(timezone.utc).timestamp()-datetime.fromisoformat(obj['checked_at'].replace('Z','+00:00')).timestamp()
  if age< -300 or age>3*86400:raise ValueError('Stale lifecycle/release collection')
 elif group=='threats':
  obj=json.loads(files['threat-data.js'])
  if obj.get('mode') not in ('live','partial') or not any(x.get('ok') for x in obj.get('sources',{}).values()):raise ValueError('Threat sources unavailable')
 elif group=='malware':
  obj=json.loads(files['malware-data.js'])
  if not any(x.get('ok') for x in obj.get('sources',{}).values()):raise ValueError('Malware sources unavailable')

def collect(store,root=ROOT,runner=None):
 p,etag,files=restore(store,root);report={}
 for group,script in SCRIPTS.items():
  try:
   result=(runner or (lambda script:subprocess.run([sys.executable,str(root/'scripts'/script)],timeout=2100)))(script)
   # Some collectors return nonzero for partial provider coverage; validate data.
   if result.returncode not in (0,1):raise ValueError('Collector process failed')
   fresh=preserve_partial(group,group_files(root,group),files);validate_group(group,fresh);files.update(fresh)
   report[group]={'status':'published','collector_exit':result.returncode}
   if group=='advisories' and json.loads(fresh['data/feed-health.json']).get('mode')!='live':report[group]['partial']=True
   if group=='malware' and not all(x.get('ok') for x in json.loads(fresh['malware-data.js']).get('sources',{}).values()):report[group]['partial']=True
   if group in ('lifecycle','patch_notes') and json.loads(fresh[GROUPS[group][0]]).get('errors'):report[group]['partial']=True
  except Exception as exc:
   report[group]={'status':'retained','reason':type(exc).__name__}
   for name in GROUPS[group]:(root/name).write_bytes(restore_body(name,files[name]))
 current=publish(store,files,etag,p['manifest'],report)
 return {'current':current,'collection':report,'degraded':any(x['status']=='retained' or x.get('collector_exit')!=0 or x.get('partial') for x in report.values())}

class S3Store:
 def __init__(self):
  import boto3
  from botocore.config import Config
  account=os.environ['FEED_R2_ACCOUNT_ID'];self.bucket=os.environ['FEED_R2_BUCKET']
  if not re.fullmatch(r'[a-f0-9]{32}',account) or not re.fullmatch(r'cveharbor-intelligence(?:-[a-z0-9-]+)?',self.bucket):raise ValueError('Invalid dedicated feed target')
  self.client=boto3.client('s3',endpoint_url=f'https://{account}.r2.cloudflarestorage.com',region_name='auto',
   aws_access_key_id=os.environ['FEED_R2_ACCESS_KEY_ID'],aws_secret_access_key=os.environ['FEED_R2_SECRET_ACCESS_KEY'],
   config=Config(connect_timeout=10,read_timeout=30,retries={'mode':'standard','max_attempts':5},request_checksum_calculation='when_required',response_checksum_validation='when_required'))
 def get(self,key):
  from botocore.exceptions import ClientError
  try:
   r=self.client.get_object(Bucket=self.bucket,Key=key);body=r['Body'].read(MAX_BYTES+1)
   if len(body)>MAX_BYTES:raise ValueError('Oversized object')
   return body,r['ETag']
  except ClientError as e:
   if e.response['Error']['Code'] in ('NoSuchKey','404'):return None,None
   raise
 def immutable(self,key,body):
  from botocore.exceptions import ClientError
  try:self.client.put_object(Bucket=self.bucket,Key=key,Body=body,ContentType='application/octet-stream',IfNoneMatch='*')
  except ClientError as e:
   if e.response['ResponseMetadata']['HTTPStatusCode']!=412:raise
   if self.get(key)[0]!=body:raise ValueError('Immutable object mismatch')
 def compare_set(self,key,body,etag):
  options={'IfMatch':etag} if etag else {'IfNoneMatch':'*'}
  self.client.put_object(Bucket=self.bucket,Key=key,Body=body,ContentType='application/json',CacheControl='no-store',**options)

def main():
 parser=argparse.ArgumentParser();parser.add_argument('operation',choices=['collect','seed','inspect','rollback']);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--manifest');parser.add_argument('--expected-manifest');args=parser.parse_args();store=S3Store()
 if args.operation=='inspect':
  p,_=pointer(store)
  if not p:raise ValueError('Uninitialized feed')
  manifest=load_manifest(store,p['manifest']);load_files(store,manifest);print(json.dumps({'current':p,'created_at':manifest['created_at'],'collection':manifest['collection']}));return
 if args.operation=='seed':
  p,etag=pointer(store)
  if p:raise ValueError('Refusing to seed an initialized bucket')
  files={}
  for group in GROUPS:
   fresh=group_files(args.root,group);validate_group(group,fresh);files.update(fresh)
  print(json.dumps(publish(store,files,etag)));return
 if args.operation=='rollback':
  p,etag=pointer(store)
  if not p or p['manifest']!=args.expected_manifest:raise ValueError('Rollback requires current expected manifest')
  manifest=load_manifest(store,args.manifest);load_files(store,manifest)
  # Deliberately do not refresh timestamps or reset any email delivery state.
  store.compare_set('current.json',encoded({'schema':1,'manifest':args.manifest,'previous':p['manifest']}),etag);return
 result=collect(store,args.root)
 # The website release verifies the exact immutable objects a data run published.
 receipt=os.environ.get('FEED_RECEIPT_PATH')
 if receipt:
  manifest=load_manifest(store,result['current']['manifest'])
  Path(receipt).write_bytes(encoded({'manifest':result['current']['manifest'],'files':manifest['files'],'collection':result['collection']}))
 print(json.dumps(result));raise SystemExit(1 if result['degraded'] else 0)
if __name__=='__main__':main()
