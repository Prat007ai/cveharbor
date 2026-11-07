"""Offline handoff, GitHub evidence and archive tests. No credentials or provider."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from staging.scripts import routine_review as rr

SHA = 'a'*40
HEAD = 'b'*40
BASE = 'c'*40
PR = dict(merged=True, merge_commit_sha=SHA, base={'ref':'main','repo':{'full_name':rr.REPO}},
          user={'id':1}, commits=1, head={'sha':HEAD,'ref':'fix/catalogue','repo':{'full_name':rr.REPO}}, merged_at='2026-11-07T12:00:00Z')
REVIEW = dict(id=12, state='APPROVED', commit_id=HEAD, user={'id':2,'type':'User'},
              author_association='COLLABORATOR', submitted_at='2026-11-07T11:00:00Z', body='Routine staging: approved')
COMMITS = [dict(sha=HEAD, author={'id':3}, committer={'id':4})]
PUSH = dict(ref='refs/heads/fix/catalogue', after=HEAD, activity_type='push',
            timestamp='2026-11-07T10:00:00Z', actor={'id':5})
ENV = dict(GITHUB_SHA=SHA,GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch',
           GITHUB_REF='refs/heads/main',GITHUB_REPOSITORY=rr.REPO,ROUTINE_PR='123',
           CF_STAGING_CANDIDATE_ENABLED='true',SIMPLE_STAGING_ENABLED='false',ROUTINE_STAGING_DELIVERY_ENABLED='true')

class RoutineTests(unittest.TestCase):
    def test_only_current_independent_premerge_approval(self):
        evidence = rr.review_participants(PR, COMMITS, [PUSH])
        self.assertEqual(rr.check_review(PR,[REVIEW],SHA,*evidence),12)
        for identity in (1, 3, 4, 5):
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                rr.check_review(PR,[dict(REVIEW,user={'id':identity,'type':'User'})],SHA,*evidence)
        for activity in ([], [PUSH,PUSH], [dict(PUSH,actor=None)], [dict(PUSH,after=BASE)]):
            with self.assertRaises(ValueError):
                rr.review_participants(PR, COMMITS, activity)
        for commits in ([], [dict(COMMITS[0],author=None)]):
            with self.assertRaises(ValueError):
                rr.review_participants(PR, commits, [PUSH])
        for change in [dict(state='DISMISSED'),dict(commit_id=BASE),dict(user={'id':1,'type':'User'}),
                       dict(author_association='NONE'),dict(submitted_at='2026-11-07T12:01:00Z'),dict(body='LGTM'),dict(submitted_at='2026-11-07T09:59:59Z')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                rr.check_review(PR,[dict(REVIEW,**change)],SHA,*evidence)
        with self.assertRaises(ValueError):
            rr.check_review(PR,[REVIEW,dict(REVIEW,id=13,state='CHANGES_REQUESTED')],SHA,*evidence)

    def test_scope_and_archive(self):
        rr.scope(['app.js','deployment/proposals/customer-remediation/candidate-profile.json'])
        for f in ['account-backend/migrations/a.sql','.github/workflows/cvie-staging.yml','AGENTS.md','account-backend/src/index.js']:
            with self.assertRaises(ValueError): rr.scope(['app.js',f])
        with tempfile.TemporaryDirectory() as d:
            dest=Path(d)/'candidate'
            def pack(extra=None):
                f=io.BytesIO()
                with zipfile.ZipFile(f,'w') as z:
                    for n in ['api.mjs','site.mjs','manifest.json','seal.json','public/.nojekyll']+([extra] if extra else []):
                        z.writestr(n,b'')
                return f,'sha256:'+hashlib.sha256(f.getvalue()).hexdigest()
            f,digest=pack()
            with self.assertRaises(ValueError): rr.unpack(f,'sha256:'+'0'*64,dest)
            with self.assertRaises(ValueError): rr.unpack(*pack('public/../foreign'),dest)
            rr.unpack(f,digest,dest)
            self.assertTrue((dest/'public/.nojekyll').exists())

    def test_end_to_end_resolver_no_dispatch(self):
        def api(p):
            if p=='commits/main': return {'sha':SHA}
            if p=='pulls/123': return PR
            if p.startswith('actions/workflows/'):
                wf=p.split('/')[2]
                return {'total_count':1,'workflow_runs':[dict(id=1 if wf=='security-ci.yml' else 2,
                    head_sha=SHA,head_branch='main',event='push',path='.github/workflows/'+wf,
                    head_repository={'full_name':rr.REPO},conclusion='success',run_attempt=1)]}
            if '/jobs?' in p:
                jobs=[dict(name=n,conclusion='success') for n in rr.REQUIRED['security-ci.yml' if '/1/attempts' in p else 'cvie-staging.yml']]
                return {'total_count':len(jobs),'jobs':jobs}
            if '/artifacts?' in p:
                return {'total_count':1,'artifacts':[dict(id=32,name=rr.CANDIDATE,expired=False,
                        workflow_run={'id':2,'head_sha':SHA},digest='sha256:'+'0'*64)]}
            self.fail(p)
        def git(*args):
            if args[0]=='show':return BASE+' '+HEAD
            if args[0]=='diff':return 'styles.css\0'
            return SHA
        def pages(route):
            return {'pulls/123/reviews?per_page=100':[REVIEW], 'pulls/123/commits?per_page=100':COMMITS,
                    'activity?ref=refs%2Fheads%2Ffix%2Fcatalogue&per_page=100':[PUSH]}[route]
        with patch.dict('os.environ',ENV,clear=True), patch.object(rr,'git',git),patch.object(rr,'pages',pages):
            with patch.object(rr,'api',api): self.assertEqual(rr.review()['artifact'],'32')
            for fragment,mutate in [
                ('commits/main',lambda d:d.update(sha=BASE)),
                ('workflow_runs',lambda d:d['workflow_runs'][0].update(event='pull_request')),
                ('workflow_runs',lambda d:d['workflow_runs'][0].update(run_attempt=2)),
                ('jobs',lambda d:d['jobs'][0].update(conclusion='skipped')),
                ('artifacts',lambda d:d['artifacts'][0].update(expired=True))]:
                def changed(p):
                    d=api(p)
                    if fragment==p or fragment in d:mutate(d)
                    return d
                with self.subTest(fragment=fragment),patch.object(rr,'api',changed),self.assertRaises(ValueError):rr.review()
            with patch.dict('os.environ',ROUTINE_STAGING_DELIVERY_ENABLED='false'),patch.object(rr,'api',side_effect=AssertionError),self.assertRaises(ValueError):rr.review()
