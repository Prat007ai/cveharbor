"""Read GitHub release evidence. No workflow dispatch, Cloudflare access or writes."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

REPO = 'Prat007ai/cveharbor'
CANDIDATE = 'customer-candidate-review'
OUT = Path('staging/.build/customer-remediation-candidate')
REQUIRED = {'security-ci.yml': {'Security / workflow policy', 'CI / application regression'},
            'cvie-staging.yml': {'prepare'}}
# Conservative starting scope. An independent reviewer must also check behavior,
# cost and acceptance criteria: a path alone cannot prove any of those.
APP = {'app.js', 'styles.css', 'index.html', 'customer-remediation-ui.js',
       'account-backend/src/catalogue-selection.js', 'account-backend/src/cve-lookup.js'}
SUPPORT = {'deployment/proposals/customer-remediation/candidate-profile.json',
           'scripts/catalogue_scope_browser_smoke.mjs', 'scripts/browser_smoke.mjs',
           'scripts/cvie_browser_smoke.mjs'}

def need(condition, message):
    if not condition:
        raise ValueError(message)

def git(*args):
    return subprocess.check_output(['git', *args]).decode().rstrip('\n')

def api(route):
    return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPO}/{route}']))

def pages(route):
    return [r for page in json.loads(subprocess.check_output(
        ['gh', 'api', '--paginate', '--slurp', f'repos/{REPO}/{route}'])) for r in page]

def check_review(pr, reviews, sha):
    need(pr['merged'] and pr['base']['ref'] == 'main' and pr['merge_commit_sha'] == sha
         and pr['base']['repo']['full_name'] == REPO, 'PR is not the exact merged main release')
    latest = {}
    for r in sorted(reviews, key=lambda r: r['id']):
        if r['state'] in {'APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'}:
            latest[r['user']['id']] = r
    need(not any(r['state'] == 'CHANGES_REQUESTED' for r in latest.values()), 'Outstanding changes requested')
    for r in latest.values():
        if (r['state'] == 'APPROVED' and r['commit_id'] == pr['head']['sha']
            and r['user']['id'] != pr['user']['id'] and r['user']['type'] == 'User'
            and r['author_association'] in {'OWNER', 'MEMBER', 'COLLABORATOR'}
            and r['submitted_at'] <= pr['merged_at'] and 'Routine staging: approved' in r['body'].splitlines()):
            return r['id']
    raise ValueError('No independent routine approval on the merged PR head before merge')

def scope(files):
    need(bool(APP.intersection(files)), 'No supported routine application change')
    for f in files:
        need(f in APP | SUPPORT or re.fullmatch(r'account-backend/tests/[\w-]+\.test\.mjs', f)
             or re.fullmatch(r'docs/reviews/[\w./-]+\.(?:md|png)', f),
             'Separate review required for path: ' + f)

def one_run(workflow, sha):
    data = api(f'actions/workflows/{workflow}/runs?event=push&branch=main&head_sha={sha}&per_page=2')
    need(data['total_count'] == 1, 'Missing or ambiguous main build: ' + workflow)
    run, = data['workflow_runs']
    need(run['head_sha'] == sha and run['head_branch'] == 'main' and run['event'] == 'push'
         and run['path'] == '.github/workflows/' + workflow and run['head_repository']['full_name'] == REPO
         and run['conclusion'] == 'success' and run['run_attempt'] == 1, 'Main build not successful on first attempt: ' + workflow)
    jobs = api(f"actions/runs/{run['id']}/attempts/1/jobs?per_page=100")
    need(jobs['total_count'] == len(jobs['jobs']), 'Incomplete check inventory')
    for name in REQUIRED[workflow]:
        need([j['conclusion'] for j in jobs['jobs'] if j['name'] == name] == ['success'], 'Required check did not pass: ' + name)
    return run['id']

def review():
    env = os.environ
    need(env.get('ROUTINE_STAGING_DELIVERY_ENABLED') == 'true' and env['GITHUB_REPOSITORY'] == REPO
         and env['GITHUB_REF'] == 'refs/heads/main' and env['GITHUB_EVENT_NAME'] == 'workflow_dispatch'
         and env['GITHUB_RUN_ATTEMPT'] == '1' and env.get('CF_STAGING_CANDIDATE_ENABLED') == 'true'
         and env.get('SIMPLE_STAGING_ENABLED') == 'false', 'Routine delivery disabled or invalid dispatch')
    n, sha = env['ROUTINE_PR'], env['GITHUB_SHA']
    need(re.fullmatch(r'[1-9][0-9]{0,8}', n) and re.fullmatch(r'[a-f0-9]{40}', sha), 'Invalid task reference')
    need(api('commits/main')['sha'] == git('rev-parse', 'HEAD') == sha, 'main moved; review the new release')
    pr = api('pulls/' + n)
    rid = check_review(pr, pages(f'pulls/{n}/reviews?per_page=100'), sha)
    parents = git('show', '-s', '--format=%P', sha).split()
    need(len(parents) == 2 and parents[1] == pr['head']['sha'] and
         git('rev-parse', sha+'^{tree}') == git('rev-parse', parents[1]+'^{tree}'), 'Merge tree differs from reviewed head')
    scope(git('diff', '--no-renames', '--name-only', '-z', parents[0], sha).rstrip('\0').split('\0'))
    one_run('security-ci.yml', sha)
    run = one_run('cvie-staging.yml', sha)
    items = api(f'actions/runs/{run}/artifacts?name={CANDIDATE}&per_page=2')
    need(items['total_count'] == 1, 'Missing or ambiguous candidate artifact')
    item, = items['artifacts']
    need(item['name'] == CANDIDATE and not item['expired'] and item['workflow_run']['id'] == run
         and item['workflow_run']['head_sha'] == sha and re.fullmatch(r'sha256:[0-9a-f]{64}', item['digest']),
         'Candidate artifact provenance or expiry mismatch')
    return {'parent': parents[0], 'review': str(rid), 'run': str(run), 'artifact': str(item['id']), 'digest': item['digest']}

def unpack(archive, digest, dest):
    archive.seek(0)
    need('sha256:' + hashlib.file_digest(archive, 'sha256').hexdigest() == digest, 'Candidate archive checksum mismatch')
    with zipfile.ZipFile(archive) as z:
        names = z.namelist()
        need(not dest.exists() and len(names) == len(set(names)) and
             {'api.mjs','site.mjs','manifest.json','seal.json','public/.nojekyll'} <= set(names), 'Incomplete candidate package')
        for name in names:
            parts = name.rstrip('/').split('/')
            need(all(p not in {'','.','..'} for p in parts) and '\\' not in name and ':' not in name and
                 (name in {'api.mjs','site.mjs','manifest.json','seal.json'} or parts[0] == 'public'), 'Unexpected package path')
        z.extractall(dest)

if __name__ == '__main__':
    result = review()
    if os.environ.get('ROUTINE_DOWNLOAD') == 'true':
        need(result == json.loads(os.environ['EXPECTED_REVIEW']), 'Release evidence changed while awaiting approval')
        with tempfile.TemporaryFile() as f:
            subprocess.run(['gh','api',f"repos/{REPO}/actions/artifacts/{result['artifact']}/zip"], stdout=f, check=True)
            unpack(f, result['digest'], OUT)
    else:
        with open(os.environ['GITHUB_OUTPUT'], 'a') as f:
            print('routine_review=' + json.dumps(result, separators=(',', ':')), file=f)
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a') as f:
        print(f"Routine PR #{os.environ['ROUTINE_PR']}: [independent review](https://github.com/{REPO}/pull/{os.environ['ROUTINE_PR']}#pullrequestreview-{result['review']}), "
              f"[verified main build](https://github.com/{REPO}/actions/runs/{result['run']}), artifact {result['artifact']}, {result['digest']}.", file=f)
