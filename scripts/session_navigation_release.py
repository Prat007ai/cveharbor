"""Build and publish the reviewed session navigation fix on the verified #283 production site."""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError

import catalogue_package as package
import catalogue_promotion as promotion

BASE = "3406a3cf9bcaf554624040cff83b2a6874c47a01"
CANDIDATE = "24ebc2d1d7dded28288d0f5c9ae9c2b77380d213"
ENVIRONMENT = "cloudflare-site-production"
MODULES = {"app.js", "header-auth.js", "account-page.js", "account-security.js", "accounts.js", "command-center.js"}
SOURCE = MODULES | {"index.html", "workspace/index.html", "account/index.html"}
SECTIONS = {"intelligence", "vulnerabilities", "alerts", "threats", "malware", "lifecycle", "environments", "admin-tools", "remediation"}
CHANGED = SOURCE | {section + "/index.html" for section in SECTIONS}


def prepare(out):
    for name in SOURCE:
        package.require(package.git("show", "HEAD:" + name) == package.git("show", CANDIDATE + ":" + name),
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
        promotion.evidence(284)
        promotion.policy(ENVIRONMENT, independent=True)
        readiness()
    elif sys.argv[1:2] == ["publish"]:
        promotion.publish(Path(sys.argv[2]).resolve(), site_env=ENVIRONMENT, independent=True,
                          pr_number=284, previous_version="172de42d-2dc6-4eb4-866f-e995854f653d",
                          previous_deployment="df5851e1-84f5-4320-86e4-377d799c0d2f", changed=CHANGED,
                          readiness=readiness)
    else:
        sys.exit("Expected prepare, preflight or publish")
