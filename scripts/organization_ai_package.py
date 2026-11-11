"""Reconstruct serving PR337; organization activation remains opt-in after release."""
from pathlib import Path
import subprocess
import tempfile
import sys
import os
import catalogue_package as pkg
import team_release as team

BASE = '2f72ac9f3fb2d3d8e708ca4bc6e6f2f343584884'
PREDECESSOR = '8fd3af1d291a2861411ba109256d8fad103ccde550003d5dca7b35c4aa9f2487'
MODULES = {'ai-pricing.js', 'ai-allowance.js', 'ai-admin.js', 'ai-routes.js'}

def build(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    with tempfile.TemporaryDirectory() as temporary:
        checkout = Path(temporary) / 'base'
        pkg.git('-c', 'core.autocrlf=false', 'worktree', 'add', '--detach', str(checkout), BASE)
        try:
            env = dict(os.environ)
            env.pop('GITHUB_ACTIONS', None)
            subprocess.run([sys.executable, 'scripts/workspace_history_package.py', str(out)], cwd=checkout, env=env, check=True)
        finally:
            pkg.git('worktree', 'remove', '--force', str(checkout))
    pkg.require(team.identity(out) == PREDECESSOR, 'Serving predecessor changed')
    source = out / 'account-backend/src'
    before = {p.name:p.read_bytes() for p in source.iterdir() if p.is_file()}
    for name in MODULES:
        pkg.require(not (source/name).exists(), 'Unexpected AI predecessor')
        (source/name).write_bytes(Path('account-backend/src', name).read_bytes())
    index = source/'index.js'
    text = index.read_text(encoding='utf-8')
    needle = "  if(!user)return response({error:'Sign in required'},401);"
    pkg.require(text.count(needle) == 1 and 'aiRoute' not in text, 'Unexpected authentication router')
    text = "import {aiRoute} from './ai-routes.js';\n" + text.replace(needle, needle+"\n  if(path.startsWith('/v1/ai/'))return await aiRoute(req,env,user,path,{response,body,limit},ctx);")
    index.write_text(text, encoding='utf-8', newline='\n')
    config=out/'account-backend/wrangler.toml'
    text=config.read_text(encoding='utf-8')
    pkg.require(text.count('[vars]\n')==1 and 'CVEHARBOR_AI_' not in text, 'Unexpected AI configuration')
    config.write_text(text.replace('[vars]\n','[vars]\nCVEHARBOR_AI_ACCOUNTING_ENABLED = "true"\nCVEHARBOR_AI_ENABLED = "true"\nCVEHARBOR_AI_PLATFORM_OWNER_EMAIL = "prat@mahendran.tech"\n'),encoding='utf-8',newline='\n')
    after={p.name:p.read_bytes() for p in source.iterdir() if p.is_file()}
    pkg.require(set(after)-set(before)==MODULES,'Unexpected added modules')
    pkg.require({n for n in before if before[n]!=after[n]}=={'index.js'},'Unrelated source changed')
    actual=team.identity(out)
    if check:pkg.require(actual==Path('release/organization-ai-backend.txt').read_text().strip(),'AI package differs from reviewed identity')
    print(actual,flush=True)
    return actual

if __name__=='__main__':build(Path(sys.argv[1]).resolve(), '--record' not in sys.argv)
