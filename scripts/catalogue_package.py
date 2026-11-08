"""Build the catalogue navigation fix on the recorded production frontend."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASE = "64b715e46819d68be389bd894558ca29afe5ac52"
PREVIOUS_FIX = "49a7e29fc06cfe82f933004bd9432516e6ab722c"
CANDIDATE = "e4ffd7fdde0d09d873c6d47d0cf2ba97d7fb915a"
CHANGED = {"app.js", "accounts.js"}
# These two feeds were generated immediately before the original upload.
LIVE_ONLY = {"lifecycle.js", "patch-notes.js"}
# Publication 41882606976, job 126758693492: 14 uploaded + 60 reused.
INVENTORY = "e02c676741f7405cc568fb3be9d643d7b71b73472118bd01011f374144028352"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def files(root):
    return {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args])


def prepare(out):
    for source in CHANGED:
        require(git("show", "HEAD:" + source) == git("show", CANDIDATE + ":" + source), "Unreviewed " + source)
    patch = git("diff", CANDIDATE + "^", CANDIDATE, "--", *sorted(CHANGED))
    out.mkdir()
    tree = out / "source"
    git("-c", "core.autocrlf=false", "worktree", "add", "--detach", str(tree), BASE)
    prior_patch = git("diff", PREVIOUS_FIX + "^", PREVIOUS_FIX, "--", "app.js")
    subprocess.run(["git", "apply", "-"], cwd=tree, input=prior_patch, check=True)
    for name in ("before", "after"):
        if name == "after":
            subprocess.run(["git", "apply", "-"], cwd=tree, input=patch, check=True)
        subprocess.run([sys.executable, "scripts/build_site.py"], cwd=tree, check=True,
                       env={**os.environ, "PYTHONUTF8": "1"})
        shutil.move(tree / "public", out / name)
    before, after = out / "before", out / "after"
    paths = files(before)
    require(paths == files(after), "Catalogue changed asset inventory")
    require(digest(("\n".join(sorted(paths | LIVE_ONLY)) + "\n").encode()) == INVENTORY,
            "Production inventory differs from the original 74 assets")
    changed = {p for p in paths if (before / p).read_bytes() != (after / p).read_bytes()}
    require(changed == CHANGED, "Unexpected built catalogue delta: " + str(changed))
    print("Verified only app.js and accounts.js change across the 74 production paths.")


if __name__ == "__main__":
    prepare(Path(sys.argv[1]).resolve())
