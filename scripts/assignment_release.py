"""Assemble the approved investigation changes on the verified production releases."""
from pathlib import Path
import io
import json
import tarfile
import os
import shutil
import subprocess
import sys
import tempfile

import catalogue_package as package
import catalogue_promotion as promotion
import session_navigation_release as predecessor

MAIN_BASE = "c5ff5ca432f2b0c07743743da42af3ad5778d861"
SITE_BASE = "d7577daa"
API_BASE = "4db5c5ae88e2994cbf1637a4777b803ffd28fdd7"
BACKEND = {
    "assignment-acknowledgement.js", "assignment-progress.js", "assignment-progress-common.js",
    "assignment-progress-mail.js", "assignment-progress-page.js", "assignment-template.js",
}
SITE_FILES = {"operations.js", "app.js", "styles.css", "remediation.css"}
ROUTES = {"index.html"} | {section + "/index.html" for section in predecessor.SECTIONS}
CHANGED = SITE_FILES | ROUTES


def backend(out):
    paths = ["account-backend/src", "account-backend/migrations", "account-backend/wrangler.toml", "release/migrations"]
    archive = package.git("archive", "--format=tar", API_BASE, "account-backend", "release/migrations")
    with tarfile.open(fileobj=io.BytesIO(archive)) as tree:
        for member in tree:
            name = member.name
            if not member.isfile() or not (any(name == prefix or name.startswith(prefix + "/") for prefix in paths)
                    or (name.startswith("account-backend/") and name.count("/") == 1 and name.endswith(".sql"))):
                continue
            content = tree.extractfile(member).read()
            if name.startswith("account-backend/src/") and Path(name).name in BACKEND:
                package.require(package.git("show", MAIN_BASE + ":" + name) == content,
                                "Assignment source diverged from production: " + name)
                content = package.git("show", "HEAD:" + name)
            f = out / name
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(content)
    return out


def site(out):
    predecessor.prepare(out, reviewed_ref=SITE_BASE)
    (out / "before").rename(out / "before_topics")
    (out / "after").rename(out / "before")
    shutil.copytree(out / "before", out / "after")
    with tempfile.TemporaryDirectory(dir=out) as temp:
        original, edited = Path(temp) / "original", Path(temp) / "edited"
        for name in sorted(CHANGED):
            source = "index.html" if name in ROUTES else name
            original.write_bytes(package.git("show", MAIN_BASE + ":" + source))
            edited.write_bytes(package.git("show", "HEAD:" + source))
            live = out / "before" / name
            assembled = package.git("merge-file", "-p", str(live), str(original), str(edited))
            (out / "after" / name).write_bytes(assembled)
    package.require({n for n in package.files(out / "after") if (out / "before" / n).read_bytes() != (out / "after" / n).read_bytes()} == CHANGED,
                    "Unexpected files in the production website package")


if __name__ == "__main__":
    action, directory = sys.argv[1:]
    out = Path(directory).resolve()
    if action == "backend":
        backend(out)
    elif action == "site":
        site(out)
    elif action == "preflight":
        promotion.evidence(291)
        promotion.policy(predecessor.ENVIRONMENT)
        promotion.ready(json.loads(Path("release/assignment-291.json").read_text())["backend_identity"])
    elif action == "publish":
        promotion.publish(out, site_env=predecessor.ENVIRONMENT, pr_number=291,
                          previous_version="18d40f45-8250-43ee-9a31-24516fa369bd",
                          previous_deployment="dd6f4134-369c-4293-a721-b49e0365f48b",
                          changed=CHANGED, readiness=lambda: promotion.ready(json.loads(Path("release/assignment-291.json").read_text())["backend_identity"]))
    else:
        sys.exit("Expected backend, site or publish")
