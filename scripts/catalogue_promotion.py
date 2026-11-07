"""One production frontend promotion tied to staging run 42411365289."""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from catalogue_package import CHANGED, LIVE_ONLY, digest, files, require

REPO = "https://api.github.com/repos/Prat007ai/cveharbor"
STAGE = "366a44bcf5dc2c877f59a3a800e08acead7d0871"
STAGE_RUN = 42411365289
SITE_ENV = "cloudflare-site-production"
OLD_VERSION = "e22850fa-851d-453f-8336-5e78d96babdd"
OLD_DEPLOYMENT = "ec3d1d8c-dae1-4745-b866-ce0eed620db6"
BACKEND = "80b709c7559a4277d3c791fc0a853aa874104f180ac26c9e5754379f9087f05f"
ORIGIN = "https://cveharbor.com/"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def request(url, headers=None, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"User-Agent": "CVEHarbor-catalogue-release", "Cache-Control": "no-cache",
               "Content-Type": "application/json", **(headers or {})}
    return build_opener(NoRedirect).open(Request(url, data=data, headers=headers), timeout=45)


def github(path):
    with request(REPO + path, {"Authorization": "Bearer " + os.environ["GH_TOKEN"]}) as r:
        return json.load(r)


def evidence():
    run = github(f"/actions/runs/{STAGE_RUN}")
    require((run["conclusion"], run["head_branch"], run["head_sha"], run["run_attempt"], run["path"]) ==
            ("success", "main", STAGE, 1, ".github/workflows/cvie-staging.yml"), "Wrong staging deployment")
    artifact = github("/actions/artifacts/13589008759")
    require(artifact["workflow_run"]["id"] == STAGE_RUN and artifact["name"] == "customer-candidate-execution"
            and artifact["digest"] == "sha256:e65b13cf96d1022790c3301bdf0bb1df0b9390c3952686dfbb9870964ecf4956",
            "Staging execution receipt differs")
    comment = github("/issues/comments/6712763544")
    require(comment["issue_url"] == REPO + "/issues/278" and comment["user"]["id"] == 349078288
            and comment["updated_at"] == "2026-11-07T20:42:08Z"
            and "Signed-in live acceptance passed" in comment["body"], "Staging acceptance differs")
    print("Verified staging deployment 42411365289 and signed-in acceptance on PR 278.")


def policy():
    env = github("/environments/" + SITE_ENV)
    reviewers = [r for r in env["protection_rules"] if r["type"] == "required_reviewers"
                 and r.get("prevent_self_review") and r.get("reviewers")]
    require(reviewers and env.get("can_admins_bypass") is False,
            "Configure an independent required reviewer, prevent self-review and disable administrator bypass.")
    require((env.get("deployment_branch_policy") or {}).get("custom_branch_policies"),
            "Configure the production environment for the main branch only.")
    branches = github(f"/environments/{SITE_ENV}/deployment-branch-policies?per_page=100")
    require(branches["total_count"] == 1 and
            [(b["type"], b["name"]) for b in branches["branch_policies"]] == [("branch", "main")],
            "Production environment must accept only the main branch.")
    require(github("/git/ref/heads/main")["object"]["sha"] == os.environ["GITHUB_SHA"],
            "Main changed since this release was requested.")


def approval():
    approvals = github("/actions/runs/" + os.environ["GITHUB_RUN_ID"] + "/approvals")
    require(any(a["state"] == "approved" and a["user"]["login"].lower() != os.environ["GITHUB_ACTOR"].lower()
                and any(e["name"] == SITE_ENV for e in a["environments"]) for a in approvals),
            "Independent GitHub approval for this production deployment is missing.")


def provider(path, body=None):
    account = os.environ["CLOUDFLARE_ACCOUNT_ID"]
    require(re.fullmatch("[a-f0-9]{32}", account), "Invalid production account")
    url = "https://api.cloudflare.com/client/v4/accounts/" + account + "/workers/scripts/cveharbor-site"
    with request(url + path, {"Authorization": "Bearer " + os.environ["CLOUDFLARE_API_TOKEN"]}, body) as r:
        result = json.load(r)
    require(result["success"], "Provider rejected site operation")
    return result["result"]


def active(version, deployment=None):
    current = provider("/deployments")["deployments"][0]
    traffic = [(v["version_id"], v["percentage"]) for v in current["versions"]]
    require(traffic == [(version, 100)] and (not deployment or current["id"] == deployment),
            "Production site traffic differs from the expected deployment")
    return current["id"]


def ready():
    with request("https://api.cveharbor.com/v1/release-readiness?catalogue=" + str(time.time_ns())) as r:
        state = json.load(r)
    require(state.get("ready") is True and state.get("schema") == "phase1-integrity-recovery-v1"
            and state.get("release") == BACKEND, "Backend readiness or release identity changed")


def route(path):
    return path.removesuffix("index.html") if path == "index.html" or path.endswith("/index.html") else path


def protected_asset(path, auth):
    with request(ORIGIN + route(path) + "?catalogue=" + str(time.time_ns()), {"Authorization": auth}) as r:
        require(r.status == 200 and "no-store" in r.headers.get("Cache-Control", ""), "Unexpected site response: " + path)
        return r.read()


def check_gate():
    for path in ("", "vulnerabilities/", "app.js", "styles.css", "threat-data.js"):
        try:
            with request(ORIGIN + path):
                raise RuntimeError("Anonymous access to " + path)
        except HTTPError as exc:
            require(exc.code == 401 and 'realm="CVEHarbor development"' in exc.headers.get("WWW-Authenticate", "")
                    and "no-store" in exc.headers.get("Cache-Control", ""), "Unexpected anonymous gate: " + path)


def await_read(check, timeout=100):
    deadline = time.monotonic() + timeout
    while True:
        try:
            return check()
        except (RuntimeError, URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(4)


def verify_asset(path, auth, expected):
    require(digest(protected_asset(path, auth)) == expected, "Post-deployment bytes differ: " + path)


def publish(out):
    policy()
    approval()
    evidence()
    ready()
    active(OLD_VERSION, OLD_DEPLOYMENT)
    check_gate()
    password = os.environ["SITE_GATE_PASSWORD"]
    require(len(password) >= 16, "Missing production site gate credential")
    auth = "Basic " + base64.b64encode(("cveharbor:" + password).encode()).decode()
    before, after = out / "before", out / "after"
    paths = sorted(files(before) | LIVE_ONLY)
    hashes = {}
    for path in paths:
        live = protected_asset(path, auth)
        if path in CHANGED:
            require(live == (before / path).read_bytes(), "Live catalogue baseline differs: " + path)
        else:
            (after / path).write_bytes(live)
        hashes[path] = digest((after / path).read_bytes())
    # Use the historical gate, bindings and asset routing. Version upload cannot update DNS or routes.
    config = out / "source/site-gate/wrangler.json"
    settings = json.loads(config.read_text())
    settings.pop("routes")
    settings["assets"]["directory"] = str(after)
    config.write_text(json.dumps(settings))
    tag = "catalogue-" + os.environ["GITHUB_RUN_ID"]
    active(OLD_VERSION, OLD_DEPLOYMENT)
    require(provider("/versions?per_page=1")["items"][0]["id"] == OLD_VERSION,
            "A newer unpublished version exists. Review before upload.")
    child = {k: os.environ[k] for k in ("PATH", "HOME", "CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN")}
    receipt = out / "upload.ndjson"
    subprocess.run([os.environ["WRANGLER"], "versions", "upload", "--config", str(config), "--tag", tag],
                   check=True, env={**child, "CI": "true", "WRANGLER_SEND_METRICS": "false",
                                    "WRANGLER_OUTPUT_FILE_PATH": str(receipt)})
    rows = [json.loads(line) for line in receipt.read_text().splitlines()]
    versions = [row["version_id"] for row in rows if row["type"] == "version-upload"
                and row["worker_name"] == "cveharbor-site" and row["version"] == 1]
    require(len(versions) == 1 and re.fullmatch(r"[0-9a-f-]{36}", versions[0])
            and versions[0] != OLD_VERSION and versions[0] == provider("/versions?per_page=1")["items"][0]["id"],
            "Uploaded version could not be identified")
    policy()
    approval()
    ready()
    active(OLD_VERSION, OLD_DEPLOYMENT)
    version = versions[0]
    print("Activating catalogue site version", version, flush=True)
    provider("/deployments", {"strategy": "percentage", "versions": [{"version_id": version, "percentage": 100}]})
    deployment = await_read(lambda: active(version))
    for path in paths:
        await_read(lambda: verify_asset(path, auth, hashes[path]))
    check_gate()
    ready()
    active(version, deployment)
    print(f"Verified site deployment {deployment}, version {version}, 100% traffic and all {len(paths)} assets.")


if __name__ == "__main__":
    if sys.argv[1:] == ["evidence"]:
        evidence()
    elif sys.argv[1:] == ["preflight"]:
        evidence()
        policy()
        ready()
    elif len(sys.argv) == 3 and sys.argv[1] == "publish":
        publish(Path(sys.argv[2]).resolve())
    else:
        sys.exit("Expected evidence, preflight or publish DIRECTORY")
