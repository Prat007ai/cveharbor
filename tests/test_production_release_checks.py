import unittest
from unittest.mock import patch
from scripts import production_release_checks as release


class ProductionChecksTest(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        self.run = dict(id=123, head_sha=self.sha, head_branch="main", event="push",
                        path=release.WORKFLOW, repository={"full_name": release.REPOSITORY},
                        status="completed", conclusion="success", html_url="https://github.com/")
        self.jobs = [dict(name=n, status="completed", conclusion="success") for n in release.REQUIRED_JOBS]
        self.main = self.sha

    def api(self, path):
        if path == "/git/ref/heads/main":
            return {"object": {"sha": self.main}}
        if path.startswith("/actions/workflows/security-ci.yml/runs?"):
            return {"workflow_runs": [self.run]}
        self.assertEqual(path, "/actions/runs/123/jobs?filter=latest&per_page=100")
        return {"jobs": self.jobs}

    def test_reuses_ci_on_current_main(self):
        self.assertTrue(release.check_commit(self.sha, self.api))

    def test_dashboard_capacity_release_cannot_skip_cloud_failure(self):
        env = {'GITHUB_REPOSITORY': release.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
               'GITHUB_SHA': self.sha, 'GITHUB_EVENT_PATH': 'fictional-event.json'}
        with patch.dict(release.os.environ, env), patch.object(release.Path, 'read_text', return_value='{"inputs":{"team_release":"dashboard-read-capacity"}}'), \
             patch.object(release, 'check_commit', return_value=True), patch.object(release, 'check_capacity_commit', return_value=True), \
             patch.object(release, 'check_inventory_commit', return_value=True), \
             patch.object(release, 'check_capacity_cloud_commit', side_effect=ValueError('Cloud outage rehearsal failed')) as cloud:
            with self.assertRaisesRegex(ValueError, 'Cloud outage rehearsal failed'):
                release.main()
            cloud.assert_called_once_with(self.sha)

    def test_in_progress_waits_and_failure_stops(self):
        self.run["status"] = "in_progress"
        self.assertFalse(release.check_commit(self.sha, self.api))
        self.run.update(status="completed", conclusion="failure")
        with self.assertRaises(ValueError):
            release.check_commit(self.sha, self.api)

    def test_rejects_stale_main_and_untrusted_event(self):
        self.main = "b" * 40
        with self.assertRaises(ValueError):
            release.check_commit(self.sha, self.api)
        self.main = self.sha
        self.run["event"] = "pull_request"
        with self.assertRaises(ValueError):
            release.check_commit(self.sha, self.api)

    def test_skipped_security_or_regression_job_cannot_release(self):
        self.jobs[0]["conclusion"] = "skipped"
        with self.assertRaises(ValueError):
            release.check_commit(self.sha, self.api)

    def test_ai_release_requires_its_exact_native_accounting_run(self):
        self.run['path'] = '.github/workflows/organization-ai-checks.yml'
        self.jobs = [dict(name='accounting', status='completed', conclusion='success')]
        def get(path):
            return {'workflow_runs': [self.run]} if '/workflows/' in path else {'jobs': self.jobs}
        self.assertTrue(release.check_ai_commit(self.sha, get))
        self.jobs[0]['conclusion'] = 'skipped'
        self.assertFalse(release.check_ai_commit(self.sha, get))
        self.run['head_sha'] = 'b' * 40
        with self.assertRaises(ValueError):
            release.check_ai_commit(self.sha, get)

    def test_capacity_requires_both_jobs_on_exact_main(self):
        self.run['path'] = '.github/workflows/inventory-capacity.yml'
        self.jobs = [dict(name=name,status='completed',conclusion='success') for name in
                     ['Paginated inventory and 50-session local rehearsal','Reviewed production baseline with capacity delta']]
        def get(path):
            return {'workflow_runs':[self.run]} if '/workflows/' in path else {'jobs':self.jobs}
        self.assertTrue(release.check_capacity_commit(self.sha,get))
        self.jobs[1]['conclusion']='skipped'
        self.assertFalse(release.check_capacity_commit(self.sha,get))
        self.run['event']='pull_request'
        with self.assertRaises(ValueError):
            release.check_capacity_commit(self.sha,get)

    def test_cloud_capacity_rejects_cancelled_stale_or_unrecorded_measurement(self):
        self.run.update(path='.github/workflows/inventory-capacity-cloud.yml',event='workflow_dispatch',run_attempt=1)
        self.jobs=[dict(name=name,status='completed',conclusion='success') for name in ('prepare','cloud-load')]
        artifacts=[dict(name=name,expired=False,size_in_bytes=100,digest='sha256:'+'c'*64,workflow_run={'head_sha':self.sha}) for name in ('capacity-backend','capacity-cloud-result')]
        def get(path):
            if '/workflows/' in path:return {'workflow_runs':[self.run]}
            return {'artifacts':artifacts} if '/artifacts?' in path else {'jobs':self.jobs}
        self.assertTrue(release.check_capacity_cloud_commit(self.sha,get))
        artifacts[1]['name']='capacity-coordinator-result'
        self.assertFalse(release.check_capacity_cloud_commit(self.sha,get), 'An experimental coordinator result cannot qualify the unmodified production package')
        artifacts[1]['name']='capacity-cloud-result'
        self.run['conclusion']='cancelled'
        with self.assertRaises(ValueError):release.check_capacity_cloud_commit(self.sha,get)
        self.run['conclusion']='success'
        artifacts[1]['expired']=True
        self.assertFalse(release.check_capacity_cloud_commit(self.sha,get))
        artifacts[1]['expired']=False
        artifacts[1]['workflow_run']['head_sha']='b'*40
        with self.assertRaises(ValueError):release.check_capacity_cloud_commit(self.sha,get)
        artifacts[1]['workflow_run']['head_sha']=self.sha
        self.run['run_attempt']=2
        with self.assertRaises(ValueError):release.check_capacity_cloud_commit(self.sha,get)
