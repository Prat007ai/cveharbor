"""OFFLINE ONLY: decrypt a downloaded recovery package and sign its real restore result.

No Cloudflare/GitHub credentials or network code. Keep the private key on the
owner's encrypted device. OpenSSL prompts locally for an encrypted key password.
"""
import argparse, base64, getpass, hashlib, importlib.util, json, os, subprocess, tempfile
from pathlib import Path
from datetime import datetime, timezone
ROOT=Path(__file__).resolve().parents[2]

def run(args, passphrase=None):
    if passphrase is not None: args=args+['-passin','stdin']
    result=subprocess.run(args,input=(passphrase+'\n').encode() if passphrase is not None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    if result.returncode: raise ValueError('offline_crypto_failed')
    return result.stdout

def restore(package,cert,key,work,receipt,signature,passphrase=None):
    if receipt.exists() or signature.exists() or receipt.resolve().is_relative_to(ROOT) or signature.resolve().is_relative_to(ROOT):raise ValueError('private_output_required')
    if package.stat().st_size>150000000: raise ValueError('package_size')
    with tempfile.TemporaryDirectory(prefix='recovery-offline-',dir=work) as temp:
        folder=Path(temp);folder.chmod(0o700);os.environ['TMPDIR']=str(folder);tempfile.tempdir=str(folder)
        plain=folder/'package.json'
        run(['openssl','cms','-decrypt','-binary','-inform','DER','-in',str(package),'-recip',str(cert),'-inkey',str(key),'-out',str(plain)],passphrase)
        if plain.stat().st_size>150000000: raise ValueError('plaintext_size')
        payload=json.loads(plain.read_text());meta=payload['metadata']
        if meta['account']!='9706b4d98ad72884e67fd1eb875c8a61' or meta['database_id']!='fac61562-fc31-426d-8032-550aba63b7f6' or meta['checkpoint']!=29:raise ValueError('target_mismatch')
        sql=base64.b64decode(payload['sql_base64'],validate=True)
        if hashlib.sha256(sql).hexdigest()!=meta['export_sha256']:raise ValueError('export_checksum')
        source=folder/'restore.sql';source.write_bytes(sql);source.chmod(0o600)
        spec=importlib.util.spec_from_file_location('export_validator',ROOT/'staging/scripts/verify-recovery-export.py');validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
        result=validator.validate_export(source,29)
        if result['status']!='passed':raise ValueError('restore_failed')
        proof={**{k:meta[k] for k in ['account','database_id','source_sha','capture_run_id','capture_attempt','captured_at','snapshot_sha256','export_sha256','recipient_fingerprint','bookmark_sha256']},'format':1,'kind':'offline-recovery-restore','status':'passed','checkpoint':29,'decrypted':True,'restore_integrity':True,'ciphertext_sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'verified_at':datetime.now(timezone.utc).isoformat()}
        encoded=json.dumps(proof,sort_keys=True,separators=(',',':')).encode()
        unsigned=folder/'receipt.json';unsigned.write_bytes(encoded)
        sign_args=['openssl','dgst','-sha256','-sign',str(key)]+(['-passin','stdin'] if passphrase is not None else [])+[str(unsigned)]
        signed=subprocess.run(sign_args,input=(passphrase+'\n').encode() if passphrase is not None else None,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
        if signed.returncode: raise ValueError('offline_signing_failed')
        signed=signed.stdout
        for destination,content in [(receipt,encoded),(signature,base64.b64encode(signed))]:
            with destination.open('xb') as out:out.write(content)
            destination.chmod(0o600)
        return proof

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for option in ['package','cert','key','work','receipt','signature']:parser.add_argument('--'+option,type=Path,required=True)
    parser.add_argument('--encrypted-storage-confirmed',action='store_true',required=True)
    args=parser.parse_args();os.umask(0o077)
    try:
        encrypted=b'ENCRYPTED PRIVATE KEY' in args.key.read_bytes()[:100]
        passphrase=getpass.getpass('Offline recovery key passphrase: ') if encrypted else None
        restore(args.package,args.cert,args.key,args.work,args.receipt,args.signature,passphrase)
    except Exception:raise SystemExit('STOP: offline decryption/restore/signing failed. No package contents logged.')
    print('PASS: downloaded ciphertext decrypted, checkpoint-29 restored and checked, receipt signed. No network access.')
if __name__=='__main__':main()
