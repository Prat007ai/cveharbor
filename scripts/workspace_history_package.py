"""Build the daily-history overlay over the verified serving backend, without publishing."""
from pathlib import Path
import sys
import team_release as team
import catalogue_package as pkg

BASE = 'b7b8d85775f11261629843f838d55d1ce67f019e'
PREDECESSOR = 'd075a90fa2afd00deb5d500e0beb7129daf343d2deed0127bc94fa4f4f4b9f6e'

def build(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    team.previous(BASE, 'team_release.py', 'cvie-refresh', out)
    pkg.require(team.identity(out) == PREDECESSOR, 'Serving predecessor mismatch')
    source = out / 'account-backend/src'
    before = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    (source / 'workspace-history.js').write_bytes(Path('account-backend/src/workspace-history.js').read_bytes())
    summary = source / 'workspace-summary.js'
    text = summary.read_text(encoding='utf-8')
    needle = ' const url=new URL(req.url);'
    pkg.require(text.count(needle) == 1 and 'readWorkspaceHistory' not in text, 'Unexpected summary layout')
    text = "import {readWorkspaceHistory} from './workspace-history.js';\n" + text
    text = text.replace(needle, needle + "\n if(url.pathname==='/v1/workspace/trend')return json(await readWorkspaceHistory(env,user.id));")
    summary.write_text(text, encoding='utf-8', newline='\n')
    index = source / 'index.js'
    text = index.read_text(encoding='utf-8')
    needle = ' async scheduled(_event,env,ctx) {'
    pkg.require(text.count(needle) == 1 and 'captureWorkspaceHistory' not in text, 'Unexpected scheduler layout')
    text = "import {captureWorkspaceHistory} from './workspace-history.js';\n" + text
    text = text.replace(needle, needle + "\n  if(_event?.cron==='5 * * * *')ctx.waitUntil(captureWorkspaceHistory(env));")
    index.write_text(text, encoding='utf-8', newline='\n')
    config = out / 'account-backend/wrangler.toml'
    text = config.read_text(encoding='utf-8')
    pkg.require(text.count('[vars]\n') == 1 and 'WORKSPACE_HISTORY_ENABLED' not in text, 'Unexpected history settings')
    pkg.require('"5 * * * *"' in text, 'Existing hourly trigger missing')
    config.write_text(text.replace('[vars]\n', '[vars]\nWORKSPACE_HISTORY_ENABLED = "true"\n'), encoding='utf-8', newline='\n')
    after = {p.name: p.read_bytes() for p in source.iterdir() if p.is_file()}
    pkg.require(set(after) - set(before) == {'workspace-history.js'}, 'Unexpected added backend files')
    pkg.require({p for p in before if before[p] != after[p]} == {'index.js', 'workspace-summary.js'}, 'Unexpected backend edits')
    identity = team.identity(out)
    if check:
        pkg.require(identity == Path('release/workspace-history-backend.txt').read_text(encoding='utf-8').strip(), 'History package differs from reviewed identity')
    print(identity, flush=True)
    return identity

if __name__ == '__main__':
    build(Path(sys.argv[1]).resolve())
