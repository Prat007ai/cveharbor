"""Offline handoff, GitHub evidence and archive tests. No credentials or provider."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import yaml
from staging.scripts import routine_review as rr

SHA = 'a'*40
HEAD = 'b'*40
BASE = 'c'*40
PR = dict(merged=True, merge_commit_sha=SHA, base={'ref':'main','repo':{'full_name':rr.REPO}},
          user={'id':1}, head={'sha':HEAD}, merged_at='2026-11-07T12:00:00Z')
REVIEW = dict(id=12, state='APPROVED', commit_id=HEAD, user={'id':2,'type':'User'},
              author_association='COLLABORATOR', submitted_at='2026-11-07T11:00:00Z', body='Routine staging: approved')
ENV = dict(GITHUB_SHA=SHA,GITHUB_RUN_ATTEMPT='1',GITHUB_EVENT_NAME='workflow_dispatch',
           GITHUB_REF='refs/heads/main',GITHUB_REPOSITORY=rr.REPO,ROUTINE_PR='123',
           CF_STAGING_CANDIDATE_ENABLED='true',SIMPLE_STAGING_ENABLED='false',ROUTINE_STAGING_DELIVERY_ENABLED='true')

class RoutineTests(unittest.TestCase):
    def test_only_current_independent_premerge_approval(self):
        self.assertEqual(rr.check_review(PR,[REVIEW],SHA),12)
        for change in [dict(state='DISMISSED'),dict(commit_id=BASE),dict(user={'id':1,'type':'User'}),
                       dict(author_association='NONE'),dict(submitted_at='2026-11-07T12:01:00Z'),dict(body='LGTM')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                rr.check_review(PR,[dict(REVIEW,**change)],SHA)
        with self.assertRaises(ValueError):
            rr.check_review(PR,[REVIEW,dict(REVIEW,id=13,state='CHANGES_REQUESTED')],SHA)

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
        with patch.dict('os.environ',ENV,clear=True), patch.object(rr,'git',git),patch.object(rr,'pages',return_value=[REVIEW]):
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

    def test_workflow_uses_main_package_without_build_or_cloud_in_review(self):
        doc=yaml.safe_load(Path('.github/workflows/cvie-staging.yml').read_text())
        prep=doc['jobs']['prepare']; job=doc['jobs']['customer-candidate']
        self.assertNotIn('environment',prep)
        self.assertEqual(job['needs'],'prepare')
        self.assertEqual(job['environment'],'cloudflare-cvie-staging')
        steps=prep['steps']+job['steps']
        for s in steps:
            if 'build.mjs' in s.get('run',''):self.assertIn("!= 'routine-deploy'",s['if'])
        checks=[s for s in steps if s.get('run')=='python staging/scripts/routine_review.py']
        self.assertEqual(len(checks),2)
        self.assertTrue(all('secrets.' not in json.dumps(s) for s in checks))
        self.assertEqual(checks[-1]['env']['EXPECTED_REVIEW'],'${{ needs.prepare.outputs.routine_review }}')
