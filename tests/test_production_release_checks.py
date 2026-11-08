import unittest
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
