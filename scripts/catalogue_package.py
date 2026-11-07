"""Rebuild the twelve catalogue outputs on the recorded production frontend."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys

BASE = "019efc6ca029f4113ce71c6ebfad3680fa66ba68"
CANDIDATE = "64b715e46819d68be389bd894558ca29afe5ac52"
SOURCES = {"app.js", "styles.css", "index.html"}
SECTIONS = ("intelligence", "vulnerabilities", "alerts", "threats", "malware",
            "lifecycle", "environments", "admin-tools", "remediation")
CHANGED = SOURCES | {name + "/index.html" for name in SECTIONS}
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
    require(git("rev-parse", CANDIDATE + "^").decode().strip() == BASE, "Wrong candidate parent")
    require(set(git("diff", "--name-only", BASE, CANDIDATE).decode().splitlines()) == SOURCES,
            "Unexpected catalogue source changes")
    out.mkdir()
    tree = out / "source"
    git("-c", "core.autocrlf=false", "worktree", "add", "--detach", str(tree), BASE)
    for name in ("before", "after"):
        if name == "after":
            for source in SOURCES:
                (tree / source).write_bytes(git("show", CANDIDATE + ":" + source))
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
    print("Verified 3 source files, 12 changed site assets and 74 production paths.")


if __name__ == "__main__":
    prepare(Path(sys.argv[1]).resolve())
