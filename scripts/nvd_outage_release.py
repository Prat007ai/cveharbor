"""One-file outage resilience delta on the verified capacity backend."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import catalogue_package as pkg
import team_release as team

BASE = '04ada0f76a35e61c01fdce198b1df0fd6c7edfd9'
PREDECESSOR = 'f941196f5e69b909bc6697a4b9d195eb9767f56a3761a1c8dfe239e6b65dadd2'
MODULE = 'account-backend/src/cvie.js'


def backend(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    cached = os.environ.get('NVD_BACKEND_BASELINE')
    if cached:
        pkg.require(not os.environ.get('GITHUB_ACTIONS'), 'CI must reproduce the reviewed baseline')
        pkg.require(team.identity(Path(cached)) == PREDECESSOR, 'Unexpected local baseline')
        shutil.copytree(cached, out)
    else:
        team.previous(BASE, 'inventory_capacity_release.py', 'backend', out)
    pkg.require(team.identity(out) == PREDECESSOR, 'Unexpected serving backend')
    before = {name: (out/name).read_bytes() for name in pkg.files(out)}
    with tempfile.TemporaryDirectory() as temp:
        old, new = Path(temp)/'old', Path(temp)/'new'
        old.write_bytes(pkg.git('show', BASE+':'+MODULE))
        new.write_bytes(Path(MODULE).read_bytes().replace(b'\r\n', b'\n'))
        (out/MODULE).write_bytes(pkg.git('merge-file', '-p', str(out/MODULE), str(old), str(new)))
    pkg.require(pkg.files(out) == before.keys(), 'Backend inventory changed')
    pkg.require({name for name in before if before[name] != (out/name).read_bytes()} == {MODULE}, 'Unexpected backend delta')
    value = team.identity(out)
    receipt = Path('release/nvd-outage-backend.txt')
    if check:
        pkg.require(value == receipt.read_text().strip(), 'Unreviewed backend identity')
    else:
        receipt.write_bytes((value+'\n').encode())
    print(value)


if __name__ == '__main__':
    pkg.require(sys.argv[1] in ('backend', 'record'), 'Unknown operation')
    backend(Path(sys.argv[2]).resolve(), sys.argv[1] != 'record')
