"""Read immutable source from an ancestor of main, with no credentials or deployment."""
import os,re,subprocess,tarfile,io
from pathlib import Path
sha=os.environ.get('BASELINE_SOURCE_SHA','')
if not re.fullmatch('[a-f0-9]{40}',sha):raise SystemExit('Use a full immutable production source SHA')
subprocess.run(['git','fetch','--no-tags','origin','main'],check=True)
subprocess.run(['git','merge-base','--is-ancestor',sha,'origin/main'],check=True)
out=Path('release/.build/production-source');out.mkdir(parents=True,exist_ok=False)
archive=subprocess.check_output(['git','archive',sha])
with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(out,filter='data')
print('Immutable production candidate source prepared; live version must still match.')
