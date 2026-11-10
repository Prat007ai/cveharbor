"""Publish the reviewed sign-in fix on the verified production site."""
from difflib import SequenceMatcher
from hashlib import sha256
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
TOPICS_PR = 289
TOPICS_BASE = "6f6004a69b0de766caf7ab6d526e1414aa18536f"
TOPICS_SOURCE = "9f2f8a891b02898b3a02722c78c83d36d045fc03"
TOPICS_FILES = {"app.js", "cvie.js"}
SIGNIN_BASE = "4db5c5ae88e2994cbf1637a4777b803ffd28fdd7"
SIGNIN_SOURCE = "b509a67f7d4fe469f351da49f4e7224c925c0953"
SIGNIN_FILES = {"account-page.js", "account-security.js", "app.js"}
SIGNIN_BACKEND = "738b07a3eee67dc5a3d872dfb4ccbbe5ba2aab628b8c964e820b7b69aea63ce8"
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


def prepare_availability(out):
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
            package.require(candidate.read_bytes() == package.git("show", SIGNIN_BASE + ":" + name),
                            "Unexpected reviewed source: " + name)
            result = package.git("merge-file", "-p", str(out / "before" / name), str(base), str(candidate))
            (out / "after" / name).write_bytes(result)
    paths = package.files(out / "after")
    package.require(paths == package.files(out / "before"), "Production asset inventory changed")
    delta = {name for name in paths if (out / "after" / name).read_bytes() != (out / "before" / name).read_bytes()}
    package.require(delta == AVAILABILITY_FILES, "Unexpected availability package changes")


def prepare_signin(out):
    prepare_availability(out)
    (out / "before").rename(out / "before_availability_fix")
    (out / "after").rename(out / "before")
    shutil.copytree(out / "before", out / "after")
    with tempfile.TemporaryDirectory(dir=out) as temp:
        base, candidate = Path(temp) / "base", Path(temp) / "candidate"
        for name in sorted(SIGNIN_FILES):
            base.write_bytes(package.git("show", SIGNIN_BASE + ":" + name))
            candidate.write_bytes(package.git("show", SIGNIN_SOURCE + ":" + name))
            package.require(candidate.read_bytes() == package.git("show", TOPICS_BASE + ":" + name),
                            "Unexpected account recovery source: " + name)
            updated = package.git("merge-file", "-p", str(out / "before" / name), str(base), str(candidate))
            package.require(updated != (out / "before" / name).read_bytes(), "Missing recovery change: " + name)
            (out / "after" / name).write_bytes(updated)


def apply_topic_changes(live, base, candidate):
    # Main also contains an inactive product registry. Only transplant exact, unique
    # source edits, preserving the production version of every unrelated line.
    before, after = base.splitlines(True), candidate.splitlines(True)
    for mode, start, end, new_start, new_end in SequenceMatcher(None, before, after, autojunk=False).get_opcodes():
        if mode == "equal":
            continue
        for left, right in ((0, 0), (2, 0), (0, 2), (1, 1)):
            prefix = before[max(0, start-left):start]
            suffix = before[end:end+right]
            old = b"".join(prefix + before[start:end] + suffix)
            if old and live.count(old) == 1:
                live = live.replace(old, b"".join(prefix + after[new_start:new_end] + suffix))
                break
        else:
            raise ValueError("Cannot isolate reviewed CVIE change")
    package.require(sha256(live).hexdigest() == "e00d0ad3e6c598dfbc63c76dae9f64325d504fb4a8b171256cd8b6e6d4ed79f1",
                    "Unexpected production CVIE script")
    return live


def prepare(out, reviewed_ref="HEAD"):
    prepare_signin(out)
    (out / "before").rename(out / "before_signin")
    (out / "after").rename(out / "before")
    shutil.copytree(out / "before", out / "after")
    with tempfile.TemporaryDirectory(dir=out) as temp:
        base, candidate = Path(temp) / "base", Path(temp) / "candidate"
        for name in sorted(TOPICS_FILES):
            base.write_bytes(package.git("show", TOPICS_BASE + ":" + name))
            candidate.write_bytes(package.git("show", TOPICS_SOURCE + ":" + name))
            package.require(candidate.read_bytes() == package.git("show", reviewed_ref + ":" + name),
                            "Unexpected topic source: " + name)
            prior = out / "before" / name
            merged = (apply_topic_changes(prior.read_bytes(), base.read_bytes(), candidate.read_bytes())
                      if name == "cvie.js" else package.git("merge-file", "-p", str(prior), str(base), str(candidate)))
            (out / "after" / name).write_bytes(merged)


def verify_release():
    promotion.evidence(TOPICS_PR)
    commit = promotion.github("/git/commits/" + os.environ["GITHUB_SHA"])
    package.require(commit["parents"][0]["sha"] == TOPICS_BASE,
                    "The sign-in fix must follow the verified production release")


def readiness():
    # A transient failure may clear. Every successful check must satisfy the original gate.
    for attempt in range(3):
        try:
            return promotion.ready(SIGNIN_BACKEND)
        except HTTPError as exc:
            if exc.code not in (502, 503, 504) or attempt == 2:
                raise
            time.sleep(5 * (attempt + 1))


if __name__ == "__main__":
    if os.environ.get('CVEHARBOR_SITE_RELEASE')=='team-access':
        import team_release
        team_release.site(sys.argv[1],Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "installed-releases":
        import installed_release
        installed_release.run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "firewall-digest":
        import firewall_release
        firewall_release.site(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "version-picker":
        import version_picker_release
        version_picker_release.run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "intelligence":
        import intelligence_release
        intelligence_release.run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv)>2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "manual-customer":
        import manual_customer_release
        manual_customer_release.run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "customer-investigation":
        import customer_investigation_release
        customer_investigation_release.run(sys.argv[1], Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
        sys.exit(0)
    if os.environ.get("CVEHARBOR_SITE_RELEASE") == "assignment-291":
        import assignment_release
        assignment_release.run(sys.argv[1].replace("prepare", "site"),
                               Path(sys.argv[2]).resolve() if len(sys.argv) > 2 else None)
        sys.exit(0)
    if sys.argv[1:2] == ["prepare"]:
        prepare(Path(sys.argv[2]).resolve())
    elif sys.argv[1:] == ["preflight"]:
        verify_release()
        promotion.policy(ENVIRONMENT)
        readiness()
    elif sys.argv[1:2] == ["publish"]:
        verify_release()
        promotion.publish(Path(sys.argv[2]).resolve(), site_env=ENVIRONMENT,
                          pr_number=TOPICS_PR, previous_version="1984c456-71f1-477a-abb4-84fe849e46dd",
                          previous_deployment="632c8c7c-4443-4e46-9db4-9357c14308b8", changed=TOPICS_FILES,
                          readiness=readiness)
    else:
        sys.exit("Expected prepare, preflight or publish")
