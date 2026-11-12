"""Package only explicit public application files; deterministic ZIP metadata."""
from pathlib import Path
import hashlib
import json
import subprocess
import zipfile

root=Path(__file__).resolve().parent
dist=root/'dist'
out=root/'package'
out.mkdir(exist_ok=True)
names=['CVEHarbor-Collector.exe','CVEHarbor-Collector.exe.config','README.txt']
assert (dist/names[0]).read_bytes().startswith(b'MZ'), 'Expected Windows executable'
checks=''.join(hashlib.sha256((dist/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names)
(dist/'SHA256SUMS.txt').write_text(checks,encoding='ascii')
names.append('SHA256SUMS.txt')
with zipfile.ZipFile(out/'CVEHarbor-Collector.zip','w',compression=zipfile.ZIP_DEFLATED) as archive:
    for name in names:
        info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
        archive.writestr(info,(dist/name).read_bytes())
(out/'README.txt').write_bytes((root/'README.txt').read_bytes())
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
receipt={'commit':sha,'files':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.name in ('CVEHarbor-Collector.zip','README.txt')}}
(out/'build-receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
print('Packaged Windows collector for '+sha)
