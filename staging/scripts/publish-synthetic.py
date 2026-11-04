"""Explicitly approved staging-only R2 update. No resource creation or collector network calls."""
import json
import os
import subprocess
import sys
from pathlib import Path
from synthetic_intelligence import synthetic_files, f
ROOT=Path(__file__).resolve().parents[2]

def publish(store):
    prior,etag=f.pointer(store)
    previous=prior['manifest'] if prior else None
    files=synthetic_files()
    if previous:
        old=f.load_files(store,f.load_manifest(store,previous))
        # Keep accumulated synthetic history across application updates/rehearsals.
        for name in ['data/threat-ip-history.json','data/ip-geolocation-cache.json']:
            files[name]=old[name]
    for group in f.GROUPS:f.validate_group(group,files)
    return f.publish(store,files,etag,previous,{'staging':{'status':'synthetic-only'}})

def main():
    manifest=json.loads((ROOT/'staging/resources.v1.json').read_text())
    sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    if os.environ.get('CF_STAGING_APPROVED_COMMIT')!=sha or os.environ.get('CF_STAGING_PROVISION_ACTION')!='publish-synthetic':raise ValueError('Reviewed staging publication required')
    if os.environ.get('CF_STAGING_ACCOUNT_ID')!=manifest['account_id']:raise ValueError('Staging account mismatch')
    # Only distinct staging secrets are mapped into the existing publisher.
    os.environ['FEED_R2_ACCOUNT_ID']=manifest['account_id']
    os.environ['FEED_R2_BUCKET']=manifest['intelligence_bucket']
    os.environ['FEED_R2_ACCESS_KEY_ID']=os.environ['CF_STAGING_R2_ACCESS_KEY_ID']
    os.environ['FEED_R2_SECRET_ACCESS_KEY']=os.environ['CF_STAGING_R2_SECRET_ACCESS_KEY']
    result=publish(f.S3Store())
    out=ROOT/'staging/artifacts';out.mkdir(exist_ok=True)
    (out/'publication.json').write_text(json.dumps({'synthetic_only':True,'source_sha':sha,'current':result},indent=2)+'\n')
    print('Synthetic staging snapshot published and verified; native schedules remain disabled.')
if __name__=='__main__':
    try:main()
    except Exception:
        print('Staging publication stopped. Review configured target and approved source; no automatic recovery attempted.',file=sys.stderr)
        raise SystemExit(1)
