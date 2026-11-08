"""Build and publish the reviewed session navigation fix on the verified #283 production site."""
import os
import shutil
import tempfile
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError

import catalogue_package as package
import catalogue_promotion as promotion

BASE = "3406a3cf9bcaf554624040cff83b2a6874c47a01"
CANDIDATE = "24ebc2d1d7dded28288d0f5c9ae9c2b77380d213"
AVAILABILITY_PR = 286
LIVE_SOURCE = "de0980596e2dd0e5f0bd4546b8fedd2fa0fee25e"
AVAILABILITY_FIX = "cabddea0b40b77c02d63c1de8b4eeddfd194bbd9"
AVAILABILITY_FILES = {"cvie.js", "app.js", "account-page.js"}
ENVIRONMENT = "cloudflare-site-production"
MODULES = {"app.js", "header-auth.js", "account-page.js", "account-security.js", "accounts.js", "command-center.js"}
SOURCE = MODULES | {"index.html", "workspace/index.html", "account/index.html"}
SECTIONS = {"intelligence", "vulnerabilities", "alerts", "threats", "malware", "lifecycle", "environments", "admin-tools", "remediation"}
CHANGED = SOURCE | {section + "/index.html" for section in SECTIONS}


def prepare_previous_site(out):
    for name in SOURCE:
        package.require(package.git("show", LIVE_SOURCE + ":" + name) == package.git("show", CANDIDATE + ":" + name),
                        "Unreviewed session source: " + name)
    package.prepare(out, review_ref=BASE)
    previous = out / "after"
    previous.rename(out / "deployed")
    tree = out / "source"
    patch = package.git("diff", "--unified=1", BASE, CANDIDATE, "--", *sorted(SOURCE))
    subprocess.run(["git", "apply", "-"], cwd=tree, input=patch, check=True)
    subprocess.run([sys.executable, "scripts/build_site.py"], cwd=tree, check=True,
                   env={**os.environ, "PYTHONUTF8": "1"})
    shutil.move(tree / "public", previous)
    # The earlier check built the predecessor as well. Publish against the exact live #283 bytes.
    (out / "before").rename(out / "predecessor")
    (out / "deployed").rename(out / "before")
    before = out / "before"
    paths = package.files(before)
    package.require(paths == package.files(previous), "Unexpected production asset inventory")
    delta = {p for p in paths if (before / p).read_bytes() != (previous / p).read_bytes()}
    package.require(delta == CHANGED, "Unexpected session navigation changes: " + str(delta ^ CHANGED))


def prepare(out):
    prepare_previous_site(out)
    # These three JavaScript files are copied unchanged by build_site.py. Apply only
    # the reviewed edits to the live copies, preserving older production CVIE code.
    (out / "before").rename(out / "before_session_fix")
    (out / "after").rename(out / "before")
    shutil.copytree(out / "before", out / "after")
    with tempfile.TemporaryDirectory(dir=out) as temp:
        base = Path(temp) / "base"
        candidate = Path(temp) / "candidate"
        for name in sorted(AVAILABILITY_FILES):
            base.write_bytes(package.git("show", LIVE_SOURCE + ":" + name))
            candidate.write_bytes(package.git("show", AVAILABILITY_FIX + ":" + name))
            package.require(candidate.read_bytes() == package.git("show", "HEAD:" + name),
                            "Unexpected reviewed source: " + name)
            result = package.git("merge-file", "-p", str(out / "before" / name), str(base), str(candidate))
            (out / "after" / name).write_bytes(result)
    paths = package.files(out / "after")
    package.require(paths == package.files(out / "before"), "Production asset inventory changed")
    delta = {name for name in paths if (out / "after" / name).read_bytes() != (out / "before" / name).read_bytes()}
    package.require(delta == AVAILABILITY_FILES, "Unexpected availability package changes")


def verify_release():
    promotion.evidence(AVAILABILITY_PR)
    commit = promotion.github("/git/commits/" + os.environ["GITHUB_SHA"])
    package.require(commit["parents"][0]["sha"] == LIVE_SOURCE,
                    "The availability fix must follow the verified production release")


def readiness():
    # A transient failure may clear. Every successful check must satisfy the original gate.
    for attempt in range(3):
        try:
            return promotion.ready()
        except HTTPError as exc:
            if exc.code not in (502, 503, 504) or attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))


if __name__ == "__main__":
    if sys.argv[1:2] == ["prepare"]:
        prepare(Path(sys.argv[2]).resolve())
    elif sys.argv[1:] == ["preflight"]:
        verify_release()
        promotion.policy(ENVIRONMENT)
        readiness()
    elif sys.argv[1:2] == ["publish"]:
        verify_release()
        promotion.publish(Path(sys.argv[2]).resolve(), site_env=ENVIRONMENT,
                          pr_number=AVAILABILITY_PR, previous_version="6a1ca1f8-1206-4f87-ae29-c89c3853d302",
                          previous_deployment="c2d9f9c1-1680-4e2f-a766-cda5a6bdee8f", changed=AVAILABILITY_FILES,
                          readiness=readiness)
    else:
        sys.exit("Expected prepare, preflight or publish")
