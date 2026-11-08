"""Initialize only an empty production feed from the verified November 4 baseline."""
import gzip
import json
from pathlib import Path
import subprocess

from feed_snapshot import FILES, S3Store, decode, digest, encoded, pointer, project, publish

BASE = 'f4d3ef9ba79294b5ccd19cf23b8cc92717357741'
DIRECTORY = Path(__file__).resolve().parents[1] / 'release/intelligence-baseline'


def baseline():
    expected = json.loads((DIRECTORY / 'files.json').read_bytes())
    if set(expected) != FILES:
        raise ValueError('Incomplete production baseline')
    files = {}
    for name in sorted(FILES - {'workspace-intelligence.json'}):
        if name in ('lifecycle.js', 'patch-notes.js'):
            raw = gzip.decompress((DIRECTORY / (name + '.gz')).read_bytes())
        else:
            raw = subprocess.check_output(['git', 'show', BASE + ':' + name])
        files[name] = decode(name, raw)
    files['workspace-intelligence.json'] = encoded(project(json.loads(files['data/advisories.json'])))
    if {name: digest(body) for name, body in files.items()} != expected:
        raise ValueError('Production baseline differs from the reviewed files')
    return files


if __name__ == '__main__':
    files = baseline()
    store = S3Store()
    if store.bucket != 'cveharbor-intelligence' or pointer(store)[0] is not None:
        raise ValueError('Initialization requires the empty production feed')
    print(publish(store, files, None, report={'baseline_only': True}))
