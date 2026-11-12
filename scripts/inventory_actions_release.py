"""Change inventory controls only; preserve the exact published PR348 collector."""
import os
from pathlib import Path
import shutil
import tempfile
import catalogue_package as pkg
import catalogue_promotion as prod
import production_release_checks as checks
import team_release as team
import version_picker_release as publisher
import windows_collector_app_release as collector

BASE = '3165deb3bbcfb49985d212f8d553b99dc5f41287'
CHANGED = {'inventory.js'}
COLLECTOR_FILES = {
    'CVEHarbor-Collector.zip': '14a02392492d5fb8ea06e347c064d7685fb84d6c734f67e092de8b245a3708a8',
    'README.txt': '5dc63cc804aac5b4c6d67f7e7584ac86c62fbc241dcf5ccd2548b72754d03c79',
}


def prepare(out):
    # Reconstruct the already deployed package with the artifact from run
    # 43264633230, not a newly compiled executable or unrelated main changes.
    for name in ('asset-import.js', 'scripts/windows_collector_app_release.py'):
        pkg.require(Path(name).read_bytes().replace(b'\r\n', b'\n') == pkg.git('show', BASE+':'+name),
                    'Published collector source changed: '+name)
    for name, digest in COLLECTOR_FILES.items():
        pkg.require(pkg.digest((Path('collector-app/package')/name).read_bytes()) == digest,
                    'Published collector artifact differs: '+name)
    commit = os.environ.get('GITHUB_SHA')
    try:
        os.environ['GITHUB_SHA'] = BASE
        collector.prepare(out)
    finally:
        if commit is None:
            os.environ.pop('GITHUB_SHA', None)
        else:
            os.environ['GITHUB_SHA'] = commit
    shutil.rmtree(out/'before')
    shutil.copytree(out/'after', out/'before')
    with tempfile.TemporaryDirectory() as temp:
        for name in CHANGED:
            old, new = Path(temp)/'old', Path(temp)/'new'
            old.write_bytes(pkg.git('show', BASE+':'+name))
            new.write_bytes(Path(name).read_bytes().replace(b'\r\n', b'\n'))
            target = out/'after'/name
            target.write_bytes(pkg.git('merge-file', '-p', str(target), str(old), str(new)))
    pkg.require(pkg.files(out/'before') == pkg.files(out/'after'), 'Asset inventory changed')
    delta = {n for n in pkg.files(out/'before') if (out/'before'/n).read_bytes() != (out/'after'/n).read_bytes()}
    pkg.require(delta == CHANGED, 'Unexpected production delta: '+str(delta))


def ready():
    collector.ready()


def run(action, out):
    if action == 'prepare':
        return prepare(out)
    pr = team.reviewed('fix/inventory-action-response')
    pkg.require(checks.check_commit(os.environ['GITHUB_SHA']), 'Required application/security CI incomplete')
    if action == 'preflight':
        prod.policy(publisher.ENV)
        ready()
    elif action == 'publish':
        publisher.publish(out, changed=CHANGED, added=set(), reviewed_pr=pr, ready=ready,
                          previous_version='ce792e97-478f-452b-ad3f-ee1367226854',
                          previous_deployment='35237c71-bc0d-47d1-8634-12cd8673b44d',
                          served_copy=out/'verified-origin')
    else:
        raise ValueError(action)


if __name__ == '__main__':
    import sys
    run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
