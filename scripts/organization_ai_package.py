"""Add the reviewed backup AI owner to the serving PR341 package."""
from pathlib import Path
import subprocess
import tempfile
import sys
import os
import catalogue_package as pkg
import team_release as team

BASE = '17cdd73a653de97cbb6155db63f405a6cddf6b79'
PREDECESSOR = 'b27e7dfae44a4de59daf6e9e903a74a3bf34132be06bb8de622746d1b1cc625a'

def build(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    with tempfile.TemporaryDirectory() as temporary:
        checkout = Path(temporary) / 'base'
        pkg.git('-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(checkout), BASE)
        try:
            env = dict(os.environ)
            env.pop('GITHUB_ACTIONS', None)
            subprocess.run([sys.executable, 'scripts/organization_ai_package.py', str(out)], cwd=checkout, env=env, check=True)
        finally:
            pkg.git('worktree', 'remove', '--force', str(checkout))
    pkg.require(team.identity(out) == PREDECESSOR, 'Serving predecessor changed')
    source = out / 'account-backend/src'
    before = {p.name:p.read_bytes() for p in source.iterdir() if p.is_file()}
    (source/'ai-admin.js').write_bytes(Path('account-backend/src/ai-admin.js').read_bytes())
    config=out/'account-backend/wrangler.toml'
    text=config.read_text(encoding='utf-8')
    pkg.require(text.count('[vars]\n')==1 and 'CVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL' not in text, 'Unexpected AI configuration')
    config.write_text(text.replace('[vars]\n','[vars]\nCVEHARBOR_AI_PLATFORM_BACKUP_OWNER_EMAIL = "prat.mahen@gmail.com"\n'),encoding='utf-8',newline='\n')
    after={p.name:p.read_bytes() for p in source.iterdir() if p.is_file()}
    pkg.require(set(after)==set(before),'Unexpected source inventory')
    pkg.require({n for n in before if before[n]!=after[n]}=={'ai-admin.js'},'Unrelated source changed')
    actual=team.identity(out)
    if check:pkg.require(actual==Path('release/organization-ai-backend.txt').read_text().strip(),'AI package differs from reviewed identity')
    print(actual,flush=True)
    return actual

if __name__=='__main__':build(Path(sys.argv[1]).resolve(), '--record' not in sys.argv)
