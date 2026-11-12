"""Reuse GitHub's application and security CI for the exact production revision."""
import json
import os
import re
import time
from pathlib import Path
from urllib.request import Request, urlopen

REPOSITORY = "Prat007ai/cveharbor"
WORKFLOW = ".github/workflows/security-ci.yml"
REQUIRED_JOBS = {"Security / workflow policy", "CI / application regression"}


def github(path):
    request = Request(f"https://api.github.com/repos/{REPOSITORY}{path}", headers={
        "Authorization": "Bearer " + os.environ["GH_TOKEN"],
        "User-Agent": "CVEHarbor-production-release",
    })
    with urlopen(request, timeout=20) as response:
        return json.load(response)


def check_commit(sha, get=github):
    if not re.fullmatch("[0-9a-f]{40}", sha) or get("/git/ref/heads/main")["object"]["sha"] != sha:
        raise ValueError("The reviewed commit must still be the tip of main.")
    runs = get("/actions/workflows/security-ci.yml/runs?branch=main&event=push&head_sha="
               + sha + "&per_page=1")["workflow_runs"]
    if not runs:
        return False
    run = runs[0]
    if (run["path"], run["head_sha"], run["head_branch"], run["event"], run["repository"]["full_name"]) != (
            WORKFLOW, sha, "main", "push", REPOSITORY):
        raise ValueError("CI provenance does not match this production release.")
    if run["status"] != "completed":
        return False
    if run["conclusion"] != "success":
        raise ValueError("Application or security CI failed. See " + run["html_url"])
    jobs = get(f"/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")["jobs"]
    passed = {job["name"] for job in jobs if job["status"] == "completed" and job["conclusion"] == "success"}
    if not REQUIRED_JOBS <= passed:
        raise ValueError("Both required jobs must pass for this commit.")
    return True


def check_ai_commit(sha, get=github):
    """Require native accounting checks for the exact AI release, not a prior run."""
    workflow = '.github/workflows/organization-ai-checks.yml'
    runs = get('/actions/workflows/organization-ai-checks.yml/runs?branch=main&event=push&head_sha='
               + sha + '&per_page=1')['workflow_runs']
    if not runs:
        return False
    run = runs[0]
    if (run['path'], run['head_sha'], run['head_branch'], run['event'], run['repository']['full_name']) != (
            workflow, sha, 'main', 'push', REPOSITORY):
        raise ValueError('AI accounting CI provenance mismatch.')
    if run['status'] != 'completed':
        return False
    if run['conclusion'] != 'success':
        raise ValueError('AI accounting CI failed: ' + run['html_url'])
    jobs = get(f"/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")['jobs']
    return any(j['name'] == 'accounting' and j['status'] == 'completed' and j['conclusion'] == 'success' for j in jobs)


def check_inventory_commit(sha, get=github, required_jobs=('collector','workflow')):
    workflow = '.github/workflows/windows-inventory-checks.yml'
    runs = get('/actions/workflows/windows-inventory-checks.yml/runs?branch=main&event=push&head_sha='+sha+'&per_page=1')['workflow_runs']
    if not runs:
        return False
    run = runs[0]
    if (run['path'], run['head_sha'], run['head_branch'], run['event'], run['repository']['full_name']) != (workflow, sha, 'main', 'push', REPOSITORY):
        raise ValueError('Inventory CI provenance mismatch.')
    if run['status'] != 'completed':
        return False
    if run['conclusion'] != 'success':
        raise ValueError('Inventory workflow checks failed: '+run['html_url'])
    jobs = get(f"/actions/runs/{run['id']}/jobs?filter=latest&per_page=100")['jobs']
    return set(required_jobs) <= {j['name'] for j in jobs if j['status']=='completed' and j['conclusion']=='success'}


def main():
    if os.environ["GITHUB_REPOSITORY"] != REPOSITORY or os.environ["GITHUB_REF"] != "refs/heads/main":
        raise ValueError("Production releases must run from the repository's main branch.")
    sha = os.environ["GITHUB_SHA"]
    inputs = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()).get("inputs") or {}
    for flag, commit in {
            "query_fix_287": "4db5c5ae88e2994cbf1637a4777b803ffd28fdd7",
            "assignment_release": "131951c029504940959f79374856c5a2c0d0a30b"}.items():
        if str(inputs.get(flag)).lower() == "true" and (sha != commit or inputs.get("release_mode") != "code-only"):
            raise ValueError("This historical scoped package is restricted to its original code-only release.")
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        ai_release = any(inputs.get(key) == 'organization-ai' for key in ('team_release', 'site_release', 'schema'))
        inventory_release = any(inputs.get(key) in ('windows-inventory','dotnet-mapping','server-security') for key in ('team_release', 'site_release'))
        inventory_jobs = ('collector','workflow','mapping') if inputs.get('team_release') == 'dotnet-mapping' else ('collector','workflow')
        if check_commit(sha) and (not ai_release or check_ai_commit(sha)) and (not inventory_release or check_inventory_commit(sha, required_jobs=inventory_jobs)):
            print(f"Verified production CI for {sha}.")
            return
        time.sleep(10)
    raise TimeoutError("GitHub has not completed the required CI for this commit.")


if __name__ == "__main__":
    main()
