"""Overlay only the Azure connection on the verified serving CVIE/Team backend."""
from pathlib import Path
import sys
import team_release as team
import catalogue_package as pkg

BASE = 'b7b8d85775f11261629843f838d55d1ce67f019e'
PREDECESSOR = 'd075a90fa2afd00deb5d500e0beb7129daf343d2deed0127bc94fa4f4f4b9f6e'
CONFIG = {
    'CVEHARBOR_AZURE_OPENAI_ENDPOINT': 'https://cvie-prod.openai.azure.com/',
    'CVEHARBOR_AZURE_OPENAI_DEPLOYMENT': 'gpt-5.4-mini',
    'CVEHARBOR_AZURE_OPENAI_TENANT_ID': 'f95d3766-898f-4e4d-a0ad-9b5efa394592',
    'CVEHARBOR_AZURE_OPENAI_CLIENT_ID': 'dec0de99-1e60-461f-bfb2-aa518b40036a',
}

def build(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    team.previous(BASE, 'team_release.py', 'cvie-refresh', out)
    pkg.require(team.identity(out) == PREDECESSOR, 'Serving predecessor mismatch')
    for name in ('azure-client.js', 'azure-connection.js'):
        dest = out/'account-backend/src'/name
        pkg.require(not dest.exists(), 'Unexpected existing Azure module')
        dest.write_bytes((Path('account-backend/src')/name).read_bytes())
    index = out/'account-backend/src/index.js'
    source = index.read_text()
    needle = "  if(path==='/v1/health'"
    pkg.require(source.count(needle) == 1 and 'azureConnectionProbe' not in source, 'Unexpected route layout')
    source = "import {azureConnectionProbe, probePath} from './azure-connection.js';\nimport {releaseIdentity} from './release-build.js';\n" + source
    source = source.replace(needle, '  if(path===probePath)return azureConnectionProbe(req,env,releaseIdentity);\n'+needle)
    index.write_text(source, encoding='utf-8', newline='\n')
    config = out/'account-backend/wrangler.toml'
    source = config.read_text()
    pkg.require(source.count('[vars]\n') == 1 and 'CVEHARBOR_AZURE_' not in source, 'Unexpected Azure settings')
    additions = ''.join(f'{name} = "{value}"\n' for name,value in CONFIG.items())
    config.write_text(source.replace('[vars]\n', '[vars]\n'+additions), encoding='utf-8', newline='\n')
    actual = team.identity(out)
    if check:
        pkg.require(actual == Path('release/azure-worker-backend.txt').read_text().strip(), 'Azure package differs from reviewed identity')
    print(actual, flush=True)
    return actual

if __name__ == '__main__':
    build(Path(sys.argv[1]).resolve())
