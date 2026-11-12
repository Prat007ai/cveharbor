"""Mapping-only overlay on the verified, serving PR343 backend."""
from pathlib import Path
import sys
import tempfile
import catalogue_package as pkg
import team_release as team

BASE = '86bc0c8f61cb0b4b042b48bef4c8685ac2e738ec'
PREDECESSOR = '0caf38d9c1ea4ed9bbc8c91f71cd8074b69559ae66cb33919d74d607b7519927'
CHANGED = {'account-backend/src/product-identity.js', 'account-backend/src/cvie.js'}


def build(out, check=True):
    pkg.require(not out.exists(), 'Use a new package output directory')
    team.previous(BASE, 'windows_inventory_release.py', 'backend', out)
    pkg.require(team.identity(out) == PREDECESSOR, 'Serving PR343 predecessor mismatch')
    before = {str(p.relative_to(out)).replace('\\', '/'): p.read_bytes() for p in out.rglob('*') if p.is_file()}
    with tempfile.TemporaryDirectory() as temporary:
        for name in sorted(CHANGED):
            old, new = Path(temporary)/'old', Path(temporary)/'new'
            old.write_bytes(pkg.git('show', BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
            (out/name).write_bytes(pkg.git('merge-file', '-p', str(out/name), str(old), str(new)))
    after = {str(p.relative_to(out)).replace('\\', '/'): p.read_bytes() for p in out.rglob('*') if p.is_file()}
    pkg.require(before.keys() == after.keys(), 'Unexpected package additions or deletions')
    pkg.require({n for n in before if before[n] != after[n]} == CHANGED, 'Unexpected release changes')
    value = team.identity(out)
    if check:
        pkg.require(value == Path('release/dotnet-mapping-backend.txt').read_text().strip(), 'Unreviewed mapping package')
    print(value, flush=True)
    return value


if __name__ == '__main__':
    pkg.require(sys.argv[1] in ('build', 'record'), 'Invalid operation')
    value = build(Path(sys.argv[2]).resolve(), sys.argv[1] != 'record')
    if sys.argv[1] == 'record':
        Path('release/dotnet-mapping-backend.txt').write_text(value+'\n')
