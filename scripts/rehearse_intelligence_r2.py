#!/usr/bin/env python3
"""Explicit synthetic rehearsal ONLY in an empty, separate-account staging bucket.
Does not create resources, delete objects, send emails, deploy or contact D1.
"""
import os
import re
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from feed_snapshot import S3Store,publish,pointer,load_manifest,load_files,restore,encoded
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tests'))
from test_feed_snapshot import synthetic_files

def validate_target(env):
 account=env.get('FEED_R2_ACCOUNT_ID','');production=env.get('PRODUCTION_ACCOUNT_ID','')
 if not all(re.fullmatch(r'[a-f0-9]{32}',x) for x in (account,production)) or account==production:
  raise ValueError('Verified separate staging/production account IDs required')
 if not re.fullmatch(r'cveharbor-intelligence-staging-[a-z0-9-]+',env.get('FEED_R2_BUCKET','')) or env.get('FEED_STAGING_DISPOSABLE')!='true':
  raise ValueError('Explicit disposable staging bucket required')

def main():
 validate_target(os.environ);store=S3Store()
 if store.client.list_objects_v2(Bucket=store.bucket,MaxKeys=1).get('KeyCount',0):raise ValueError('Rehearsal requires a fresh empty bucket; no existing data may be modified')
 files=synthetic_files();first=publish(store,files,None);p,etag=pointer(store)
 newer=dict(files);newer['attack-scanning-current.txt']=b'192.0.2.2\n'
 second=publish(store,newer,etag,p['manifest'])
 try:store.compare_set('current.json',encoded(first),etag)
 except Exception as exc:
  if getattr(exc,'response',{}).get('ResponseMetadata',{}).get('HTTPStatusCode')!=412:raise
 else:raise AssertionError('Conditional stale write was accepted; DO NOT ACTIVATE')
 assert pointer(store)[0]==second
 assert load_files(store,load_manifest(store,first['manifest']))==files
 # Recover by explicitly changing only the version pointer, preserving timestamps.
 current,etag=pointer(store);store.compare_set('current.json',encoded({'schema':1,'manifest':first['manifest'],'previous':current['manifest']}),etag)
 with TemporaryDirectory() as directory:
  _,_,restored=restore(store,Path(directory));assert restored==files
 print('PASS: synthetic upload/readback, conditional rejection, retained history, pointer recovery, exact restore; no real email, D1 or production calls')
if __name__=='__main__':main()
