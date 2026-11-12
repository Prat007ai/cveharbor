import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from production_release_checks import check_inventory_commit


class InventoryReleaseChecks(unittest.TestCase):
    def test_exact_workflow_and_both_required_jobs(self):
        sha = 'a' * 40
        run = dict(id=123, path='.github/workflows/windows-inventory-checks.yml', head_sha=sha,
                   head_branch='main', event='push', repository={'full_name':'Prat007ai/cveharbor'},
                   status='completed', conclusion='success', html_url='https://example.test/run')
        jobs = [dict(name=name, status='completed', conclusion='success') for name in ('collector','workflow')]
        def get(path):
            return {'jobs':jobs} if '/jobs?' in path else {'workflow_runs':[run]}
        self.assertTrue(check_inventory_commit(sha, get))
        jobs[0]['conclusion']='failure'
        self.assertFalse(check_inventory_commit(sha, get))
        jobs[0]['conclusion']='success'
        for field, value in [('head_sha','b'*40),('event','pull_request'),('head_branch','feature/test'),('path','.github/workflows/other.yml')]:
            old=run[field]
            with self.subTest(field=field):
                run[field]=value
                with self.assertRaises(ValueError):check_inventory_commit(sha,get)
            run[field]=old
        run['status']='in_progress'
        self.assertFalse(check_inventory_commit(sha,get))
        run.update(status='completed',conclusion='failure')
        with self.assertRaises(ValueError):check_inventory_commit(sha,get)


if __name__ == '__main__':unittest.main()
