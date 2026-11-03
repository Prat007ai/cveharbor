import importlib.util
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:
    raise unittest.SkipTest("Workflow policy is enforced by security-ci with pinned PyYAML")

spec=importlib.util.spec_from_file_location('workflow_security',Path(__file__).resolve().parents[1]/'scripts/check_workflow_security.py')
policy=importlib.util.module_from_spec(spec);spec.loader.exec_module(policy)
ROOT=policy.ROOT

class WorkflowSecurityTests(unittest.TestCase):
    def audit(self):return policy.load_workflow((ROOT/'.github/workflows/security-phase1-audit.yml').read_text())
    def reject(self, mutate):
        doc=self.audit();mutate(doc);self.assertTrue(policy.validate(doc,'security-phase1-audit.yml'))
    def test_all_current_workflows(self):
        for p in (ROOT/'.github/workflows').glob('*.yml'):
            with self.subTest(path=p.name):self.assertEqual(policy.validate(policy.load_workflow(p.read_text()),p.name),[])
    def test_duplicate_yaml_is_rejected(self):
        with self.assertRaises(ValueError):policy.load_workflow('jobs:\n  audit:\n    if: guarded\n    if: true\n')
    def test_no_environment(self):self.reject(lambda d:d['jobs']['audit'].pop('environment'))
    def test_wrong_branch(self):self.reject(lambda d:d['jobs']['audit'].update({'if':policy.MANUAL.replace('refs/heads/main','refs/heads/feature')}))
    def test_or_bypass(self):self.reject(lambda d:d['jobs']['audit'].update({'if':policy.MANUAL+' || true'}))
    def test_write_token(self):self.reject(lambda d:d.update(permissions={'contents':'write'}))
    def test_write_job_token(self):self.reject(lambda d:d['jobs']['audit'].update(permissions={'actions':'write'}))
    def test_unpinned_action(self):self.reject(lambda d:d['jobs']['audit']['steps'][0].update(uses='actions/checkout@v4'))
    def test_arbitrary_ref(self):self.reject(lambda d:d['jobs']['audit']['steps'][0]['with'].update(ref='${{ inputs.ref }}'))
    def test_persisted_token(self):self.reject(lambda d:d['jobs']['audit']['steps'][0]['with'].update({'persist-credentials':True}))
    def test_production_migration(self):self.reject(lambda d:d['jobs']['audit']['steps'].append({'run':'wrangler d1 execute accounts --remote --file=migration.sql'}))
    def test_audit_cannot_use_deployment_token(self):self.reject(lambda d:d['jobs']['audit']['steps'][-1]['env'].update(CLOUDFLARE_API_TOKEN='${{ secrets.CVEHARBOR_PROD_WORKER_TOKEN }}'))
    def test_direct_push(self):self.reject(lambda d:d['jobs']['audit']['steps'].append({'run':'git push origin HEAD:main'}))
    def test_malformed_heredoc(self):self.reject(lambda d:d['jobs']['audit']['steps'].append({'run':"python - <<'PY'\nprint('test')\n"}))
    def test_mixed_run_and_action(self):self.reject(lambda d:d['jobs']['audit']['steps'][0].update(run='true'))
    def test_staging_cannot_use_production_secret(self):
        d=policy.load_workflow((ROOT/'.github/workflows/security-phase1-staging.yml').read_text())
        d['jobs']['staging']['steps'][-1]['env']['CLOUDFLARE_API_TOKEN']='${{ secrets.CLOUDFLARE_API_TOKEN }}'
        self.assertTrue(policy.validate(d,'security-phase1-staging.yml'))
    def test_hourly_feed_is_independent_and_data_only(self):
        d=policy.load_workflow((ROOT/'.github/workflows/publish-intelligence.yml').read_text())
        job=d['jobs']['collect']
        self.assertNotIn('PRODUCTION_DEPLOYMENTS_ENABLED',job['if']);self.assertNotIn('needs',job)
        self.assertEqual(job['environment'],'cloudflare-intelligence-data')
        self.assertEqual(d['permissions'],{'contents':'read'})
        app=policy.load_workflow((ROOT/'.github/workflows/bootstrap.yml').read_text())
        self.assertNotIn('schedule',app['on'])
        self.assertFalse(any('update.py' in x.get('run','') for x in app['jobs']['sync']['steps']))
    def test_data_job_rejects_deployment_credentials(self):
        d=policy.load_workflow((ROOT/'.github/workflows/publish-intelligence.yml').read_text())
        d['jobs']['collect']['steps'][-1]['env']['CLOUDFLARE_API_TOKEN']='${{ secrets.CVEHARBOR_PROD_WORKER_TOKEN }}'
        self.assertTrue(policy.validate(d,'publish-intelligence.yml'))
    def test_restoration_only_prepares_reviewable_artifact(self):
        d=policy.load_workflow((ROOT/'.github/workflows/bootstrap.yml').read_text())
        job=d['jobs']['restore'];self.assertNotIn('environment',job)
        self.assertFalse(any('git push' in s.get('run','') for s in job['steps']))
        self.assertTrue(any(s.get('uses','').startswith('actions/upload-artifact@') for s in job['steps']))

if __name__=='__main__':unittest.main()
