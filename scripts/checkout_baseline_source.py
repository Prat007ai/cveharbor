"""Read immutable source from an ancestor of main, with no credentials or deployment."""
import os,re,subprocess,tarfile,io,json
from pathlib import Path
profile=json.loads(Path('release/baseline.json').read_text())
sha=os.environ.get('BASELINE_SOURCE_SHA') or profile['backend']['source_sha']
if sha!=profile['backend']['source_sha']:raise SystemExit('Use the reviewed production backend source SHA from release/baseline.json')
if not re.fullmatch('[a-f0-9]{40}',sha):raise SystemExit('Use a full immutable production source SHA')
subprocess.run(['git','fetch','--no-tags','origin','main'],check=True)
subprocess.run(['git','merge-base','--is-ancestor',sha,'origin/main'],check=True)
out=Path('release/.build/production-source');out.mkdir(parents=True,exist_ok=False)
archive=subprocess.check_output(['git','archive',sha])
with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(out,filter='data')
frontend=profile['frontend']['source_sha']
subprocess.run(['git','merge-base','--is-ancestor',frontend,'origin/main'],check=True)
front=Path('release/.build/production-frontend');front.mkdir(parents=True,exist_ok=False)
archive=subprocess.check_output(['git','archive',frontend])
with tarfile.open(fileobj=io.BytesIO(archive)) as t:t.extractall(front,filter='data')
Path('release/.build/source-pins.json').write_text(json.dumps({'backend':sha,'frontend':frontend}))
print('Immutable backend and frontend sources prepared; live versions must still match.')
