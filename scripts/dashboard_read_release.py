"""Read-capacity delta on the verified NVD outage backend; no schema changes."""
import os
from pathlib import Path
import shutil
import sys
import tempfile
import catalogue_package as pkg
import team_release as team

BASE = '43fce637edfc8d1a557a7b4a93153fcb5f8070e3'
LIVE_BASE = 'f00b4c4939ddf3d304fe525738d6fdbfedb57956'
PREDECESSOR = '1d687be8ff23a3785b466f41151a065f5dc4aa34aabaafb0b50b832b7021d50f'
CHANGED = {'account-backend/src/recovery-control.js', 'account-backend/src/inventory-pages.js', 'account-backend/src/public-source-status-cache.js', 'account-backend/src/inventory-read-db.js'}
ADDED = {'account-backend/src/dashboard-read-db.js', 'account-backend/src/versioned-read-cache.js'}


def backend(out, check=True):
    pkg.require(not out.exists(), 'Use a new package directory')
    cached = os.environ.get('DASHBOARD_READ_BASELINE')
    if cached:
        pkg.require(not os.environ.get('GITHUB_ACTIONS'), 'CI must reproduce the reviewed baseline')
        pkg.require(team.identity(Path(cached)) == PREDECESSOR, 'Unexpected local baseline')
        shutil.copytree(cached, out)
    else:
        team.previous(LIVE_BASE, 'windows_agent_release.py', 'backend', out)
    pkg.require(team.identity(out) == PREDECESSOR, 'Unexpected serving backend')
    before = {name: (out/name).read_bytes() for name in pkg.files(out)}
    with tempfile.TemporaryDirectory() as temp:
        old, new = Path(temp)/'old', Path(temp)/'new'
        for name in sorted(CHANGED):
            if name == 'account-backend/src/inventory-pages.js':
                # This module has only the serving agent integration and the
                # reviewed capacity changes. Preserve its complete agent shape.
                (out/name).write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
                continue
            old.write_bytes(pkg.git('show', BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
            (out/name).write_bytes(pkg.git('merge-file', '-p', str(out/name), str(old), str(new)))
    for name in ADDED:
        pkg.require(not (out/name).exists(), 'Module collision')
        (out/name).write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
    pkg.require(pkg.files(out)-before.keys() == ADDED, 'Unexpected backend additions')
    pkg.require({name for name in before if before[name] != (out/name).read_bytes()} == CHANGED, 'Unexpected backend delta')
    value = team.identity(out)
    receipt = Path('release/dashboard-read-capacity-backend.txt')
    if check:
        pkg.require(value == receipt.read_text().strip(), 'Unreviewed backend identity')
    else:
        receipt.write_bytes((value+'\n').encode())
    print(value)


if __name__ == '__main__':
    pkg.require(sys.argv[1] in ('backend', 'record'), 'Unknown operation')
    backend(Path(sys.argv[2]).resolve(), sys.argv[1] != 'record')
