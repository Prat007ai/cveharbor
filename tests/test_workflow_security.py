import copy
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
        for p in (ROOT / '.github/workflows').iterdir():
            if p.suffix not in {'.yaml', '.yml'}:
                continue
            with self.subTest(path=p.name):self.assertEqual(policy.validate(policy.load_workflow(p.read_text()),p.name),[])
    def test_capacity_caller_is_exact_scoped_and_protected(self):
        source=policy.load_workflow((ROOT/'.github/workflows/inventory-capacity-cloud.yml').read_text())
        mutations=[lambda j:j.update({'if':'true'}),lambda j:j.update({'if':policy.MANUAL}),lambda j:j.update(environment='cloudflare-worker-production'),lambda j:j.update(needs=[]),lambda j:j.update({'timeout-minutes':90}),lambda j:j.update(env={'TOKEN':'${{ secrets.CF_STAGING_API_TOKEN }}'}),lambda j:j['steps'][3]['env'].update(CLOUDFLARE_ACCOUNT_ID='aa99b9b15e0492302e4f6484b8d27bc2'),lambda j:j['steps'][3]['env'].update(EXTRA='${{ secrets.CVEHARBOR_PROD_WORKER_TOKEN }}'),lambda j:j['steps'][3].update(run='node other.mjs')]
        for mutate in mutations:
            changed=copy.deepcopy(source);mutate(changed['jobs']['cloud-load']);self.assertTrue(policy.validate(changed,'inventory-capacity-cloud.yml'))
        self.assertTrue(policy.validate(source,'unapproved-caller.yml'))
    def test_duplicate_yaml_is_rejected(self):
        with self.assertRaises(ValueError):policy.load_workflow('jobs:\n  audit:\n    if: guarded\n    if: true\n')
    def test_native_collector_cannot_receive_credentials_or_write_access(self):
        source=policy.load_workflow((ROOT/'.github/workflows/session-navigation.yml').read_text())
        for change in ({'environment':'cloudflare-site-production'}, {'permissions':{'contents':'write'}},
                       {'env':{'TOKEN':'${{ secrets.EXAMPLE_TOKEN }}'}}, {'runs-on':'self-hosted'}):
            altered=copy.deepcopy(source);altered['jobs']['collector-build'].update(change)
            self.assertTrue(policy.validate(altered,'session-navigation.yml'))
    def test_site_publisher_requires_success_even_with_skipped_optional_collector(self):
        source=policy.load_workflow((ROOT/'.github/workflows/session-navigation.yml').read_text())
        condition=source['jobs']['publish']['if']
        self.assertTrue(condition.startswith("always() && !cancelled() && needs.check.result == 'success' && "))
        for guard in ("always() && ", "!cancelled() && ", "needs.check.result == 'success' && "):
            altered=copy.deepcopy(source)
            altered['jobs']['publish']['if']=condition.replace(guard,'',1)
            self.assertTrue(policy.validate(altered,'session-navigation.yml'))
    def test_azure_verification_rejects_wrong_scope_and_extra_credentials(self):
        source = policy.load_workflow((ROOT / '.github/workflows/verify-azure-ai.yml').read_text())
        mutations = [
            lambda job: job.update(environment='cloudflare-production-audit'),
            lambda job: job.update(needs=[]),
            lambda job: job.update({'if': policy.MANUAL}),
            lambda job: job.update({'if': 'true'}),
            lambda job: job.update({'timeout-minutes': 30}),
            lambda job: job.update(env={'TOKEN': '${{ secrets.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET }}'}),
            lambda job: job['steps'][2]['env'].update(TOKEN='${{ secrets.CVEHARBOR_PROD_WORKER_TOKEN }}'),
            lambda job: job['steps'][2].update(run='echo copied-credential'),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(source)
            mutate(changed['jobs']['verify'])
            self.assertTrue(policy.validate(changed, 'verify-azure-ai.yml'))

    def test_azure_credential_cannot_be_reused_by_other_workflows(self):
        doc = self.audit()
        doc['jobs']['audit']['steps'][-1]['env']['AZURE_SECRET'] = '${{ secrets.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET }}'
        self.assertTrue(policy.validate(doc, 'security-phase1-audit.yml'))
        source = policy.load_workflow((ROOT / '.github/workflows/verify-azure-ai.yml').read_text())
        self.assertTrue(policy.validate(source, 'renamed-azure-workflow.yml'))

    def test_azure_inference_cannot_become_the_default(self):
        doc = policy.load_workflow((ROOT / '.github/workflows/verify-azure-ai.yml').read_text())
        doc['on']['workflow_dispatch']['inputs']['mode']['default'] = 'inference'
        self.assertTrue(policy.validate(doc, 'verify-azure-ai.yml'))
    def test_azure_runtime_publisher_rejects_unreviewed_execution_and_secret_forwarding(self):
        source = policy.load_workflow((ROOT / '.github/workflows/connect-azure-worker.yml').read_text())
        mutations = [
            lambda job: job.update({'if': policy.MANUAL}),
            lambda job: job.update(environment='cloudflare-production-audit'),
            lambda job: job.update(needs='test'),
            lambda job: job.update(concurrency=None),
            lambda job: job.update({'timeout-minutes': 60}),
            lambda job: job.update(env={'SECRET':'${{ secrets.CVEHARBOR_AZURE_OPENAI_CLIENT_SECRET }}'}),
            lambda job: job['steps'][4].update(run='echo copied-credential'),
            lambda job: job['steps'][4]['env'].update(EXTRA='${{ secrets.CVEHARBOR_PROD_CUSTOMER_SCHEMA_TOKEN }}'),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(source)
            mutate(changed['jobs']['connect'])
            self.assertTrue(policy.validate(changed, 'connect-azure-worker.yml'))
        source['jobs']['release-ready']['steps'][-1]['run'] = 'echo skipped-checks'
        self.assertTrue(policy.validate(source, 'connect-azure-worker.yml'))
    def test_no_environment(self):self.reject(lambda d:d['jobs']['audit'].pop('environment'))
    def test_wrong_branch(self):self.reject(lambda d:d['jobs']['audit'].update({'if':policy.MANUAL.replace('refs/heads/main','refs/heads/feature')}))
    def test_owner_review_environment_is_exclusive_to_the_scoped_release(self):
        doc = policy.load_workflow((ROOT / '.github/workflows/bootstrap.yml').read_text())
        for job, wrong_environment in [('sync', policy.CATALOGUE_ENV),
                                       ('catalogue-publish', 'cloudflare-site-production')]:
            changed = copy.deepcopy(doc)
            changed['jobs'][job]['environment'] = wrong_environment
            with self.subTest(job=job):
                self.assertTrue(any('exclusive to the catalogue publisher' in e
                                    for e in policy.validate(changed, 'bootstrap.yml')))
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
        next(s for s in d['jobs']['collect']['steps'] if s.get('run') == 'python scripts/feed_snapshot.py collect')['env']['CLOUDFLARE_API_TOKEN']='${{ secrets.CVEHARBOR_PROD_WORKER_TOKEN }}'
        self.assertTrue(policy.validate(d,'publish-intelligence.yml'))
    def test_restoration_only_prepares_reviewable_artifact(self):
        d=policy.load_workflow((ROOT/'.github/workflows/bootstrap.yml').read_text())
        job=d['jobs']['restore'];self.assertNotIn('environment',job)
        self.assertFalse(any('git push' in s.get('run','') for s in job['steps']))
        self.assertTrue(any(s.get('uses','').startswith('actions/upload-artifact@') for s in job['steps']))

if __name__=='__main__':unittest.main()

class ProductionRepairSecurityTests(unittest.TestCase):
 def doc(self):return policy.load_workflow((ROOT/'.github/workflows/production-compatibility-repair.yml').read_text())
 def test_repair_keeps_exact_manual_environment_and_concurrency_gates(self):
  self.assertEqual(policy.validate(self.doc(),'production-compatibility-repair.yml'),[])
 def test_repair_environment_flag_is_only_evaluated_after_job_selection(self):
  job=self.doc()['jobs']['change']
  self.assertNotIn('vars.',job['if'])
  self.assertEqual(job['steps'][-1]['env']['PRODUCTION_COMPATIBILITY_REPAIR_ENABLED'],'${{ vars.PRODUCTION_COMPATIBILITY_REPAIR_ENABLED }}')
  for change in [
   lambda j:j.update({'if':policy.REPAIR_WRITE+" && vars.PRODUCTION_COMPATIBILITY_REPAIR_ENABLED == 'true'"}),
   lambda j:j['steps'][-1]['env'].pop('PRODUCTION_COMPATIBILITY_REPAIR_ENABLED'),
   lambda j:j['steps'][-1]['env'].update(PRODUCTION_COMPATIBILITY_REPAIR_ENABLED='true'),
   lambda j:j['steps'][-1].update({'if':"vars.PRODUCTION_COMPATIBILITY_REPAIR_ENABLED == 'true'"}),
  ]:
   doc=self.doc();change(doc['jobs']['change']);self.assertTrue(policy.validate(doc,'production-compatibility-repair.yml'))
 def test_repair_rejects_bypassed_gates_public_artifacts_and_extra_entrypoints(self):
  mutations=[
   lambda d:d['on'].update(push={}),
   lambda d:d['concurrency'].update({'cancel-in-progress':True}),
   lambda d:d['jobs']['change'].update({'if':policy.MANUAL}),
   lambda d:d['jobs']['change'].pop('environment'),
   lambda d:d['jobs']['change'].pop('needs'),
   lambda d:d['jobs']['inspect'].update({'if':policy.MANUAL}),
   lambda d:d['jobs']['change']['steps'].append({'run':'echo unsafe-extra-step'}),
   lambda d:d['jobs']['change']['steps'].append({'uses':'actions/upload-artifact@'+'a'*40}),
   lambda d:d['jobs']['change']['steps'][0]['with'].update({'ref':'unreviewed-branch'}),
   lambda d:d['jobs']['inspect']['steps'][-1]['env'].update({'REPAIR_AUTHORIZATION':'${{ secrets.CVEHARBOR_PROD_REPAIR_AUTHORIZATION }}'}),
  ]
  for mutation in mutations:
   d=self.doc();mutation(d);self.assertTrue(policy.validate(d,'production-compatibility-repair.yml'))

class PermanentStagingSecurityTests(unittest.TestCase):
 def test_adoption_dispatch_and_credentials_are_isolated(self):
  source=ROOT/'.github/workflows/cvie-staging.yml'
  doc=policy.load_workflow(source.read_text());self.assertEqual(policy.validate(doc,'cvie-staging.yml'),[])
  for mode in ['guard','credential','fallback']:
   doc=policy.load_workflow(source.read_text());steps=doc['jobs']['release']['steps']
   adoption=next(s for s in steps if s.get('if')=="env.CF_STAGING_PROVISION_ACTION == 'adopt-schema'")
   if mode=='guard':adoption['if']='true'
   elif mode=='credential':adoption['env']['CF_STAGING_R2_ACCESS_KEY_ID']='${{ secrets.CF_STAGING_R2_ACCESS_KEY_ID }}'
   else:next(s for s in steps if s.get('name')=='Execute only the approved existing-resource operation')['if']="env.CF_STAGING_PROVISION_ACTION != 'diagnose-schema'"
   self.assertTrue(policy.validate(doc,'cvie-staging.yml'))
 def test_migration_dispatch_recovery_and_credentials_are_isolated(self):
  source=ROOT/'.github/workflows/cvie-staging.yml'
  for mode in ['guard','credential','recovery','fallback']:
   doc=policy.load_workflow(source.read_text());steps=doc['jobs']['release']['steps']
   migration=next(s for s in steps if s.get('name')=='Execute only the approved schema migration phase')
   if mode=='guard':migration['if']='true'
   elif mode=='credential':migration['env']['CF_STAGING_R2_ACCESS_KEY_ID']='${{ secrets.CF_STAGING_R2_ACCESS_KEY_ID }}'
   elif mode=='recovery':migration['env'].pop('CF_STAGING_RECOVERY_EVIDENCE')
   else:next(s for s in steps if s.get('name')=='Execute only the approved existing-resource operation')['if']="env.CF_STAGING_PROVISION_ACTION != 'diagnose-schema' && env.CF_STAGING_PROVISION_ACTION != 'adopt-schema'"
   self.assertTrue(policy.validate(doc,'cvie-staging.yml'))
 def test_staging_caller_cannot_weaken_guard_or_request_production_credentials(self):
  source=ROOT/'.github/workflows/cvie-staging.yml'
  for mutate in [lambda j:j.update({'if':'true'}),lambda j:j.update({'if':policy.STAGING_RELEASE+' || true'}),lambda j:j.pop('needs'),lambda j:j['steps'].append({'run':'echo forbidden','env':{'TOKEN':'${{ secrets.CVEHARBOR_PROD_WORKER_TOKEN }}'}})]:
   doc=policy.load_workflow(source.read_text());mutate(doc['jobs']['release']);self.assertTrue(policy.validate(doc,'cvie-staging.yml'))
  doc=policy.load_workflow(source.read_text());self.assertTrue(policy.validate(doc,'another-staging.yml'))

class ProductionProbeIsolationTests(unittest.TestCase):
    def confirmation(self):
        return policy.load_workflow((ROOT/'.github/workflows/activate-confirmation-domain.yml').read_text())
    def probe(self, doc):
        return next(s for s in doc['jobs']['validate']['steps'] if s.get('run') == 'node scripts/verify_confirmation_domain.mjs')
    def test_pr_keeps_local_tests_but_excludes_live_probe(self):
        doc = self.confirmation()
        self.assertIn('pull_request', doc['on'])
        self.assertEqual(self.probe(doc)['if'], policy.MAIN + " && github.event_name == 'push'")
        local = next(s for s in doc['jobs']['validate']['steps'] if s.get('run') == 'node --test scripts/verify_confirmation_domain.test.mjs')
        self.assertNotIn('if', local)
        self.assertEqual(policy.validate(doc, 'activate-confirmation-domain.yml'), [])
    def test_removed_or_weakened_probe_guard_fails_policy(self):
        for guard in [None, 'true', "github.base_ref == 'main'", "github.event_name == 'pull_request'", policy.MAIN + " && github.event_name == 'push' || true"]:
            doc = self.confirmation(); probe = self.probe(doc)
            if guard is None: probe.pop('if')
            else: probe['if'] = guard
            self.assertTrue(any('live production confirmation probes' in e for e in policy.validate(doc, 'activate-confirmation-domain.yml')))
    def test_rule_applies_to_other_pr_workflows_and_runtime_mode(self):
        doc = self.confirmation(); probe = self.probe(doc); probe.pop('if'); probe['run'] += ' --runtime'
        self.assertTrue(any('live production confirmation probes' in e for e in policy.validate(doc, 'another-pr-workflow.yml')))
    def test_existing_production_activation_remains_protected(self):
        job = self.confirmation()['jobs']['activate']
        self.assertEqual(job['environment'], 'cloudflare-worker-production')
        self.assertTrue(job['if'].startswith(policy.RELEASE + ' && '))

class RecoveryIsolationTests(unittest.TestCase):
 def workflow(self):return policy.load_workflow((ROOT/'.github/workflows/cvie-staging.yml').read_text())
 def test_recovery_is_same_environment_but_separate_serialized_job(self):
  doc=self.workflow();job=doc['jobs']['recovery']
  self.assertEqual(job['environment'],'cloudflare-cvie-staging')
  self.assertEqual(job['if'],policy.STAGING_RECOVERY)
  self.assertNotIn('vars.',job['if'])
  self.assertNotIn('vars.',doc['jobs']['release']['if'])
  self.assertEqual(doc['jobs']['release']['if'],policy.STAGING_NORMAL)
  self.assertEqual(job['concurrency'],doc['jobs']['release']['concurrency'])
  self.assertEqual(policy.validate(doc,'cvie-staging.yml'),[])
 def test_recovery_rejects_artifacts_caches_release_and_publisher_credentials(self):
  for addition in [
   {'uses':'actions/upload-artifact@'+'a'*40},
   {'uses':'actions/cache@'+'a'*40},
   {'run':'node staging/scripts/release.mjs'},
   {'run':'echo forbidden','env':{'TOKEN':'${{ secrets.CF_STAGING_R2_SECRET_ACCESS_KEY }}'}},
   {'run':'echo forbidden','env':{'KEY':'${{ secrets.CF_STAGING_RECOVERY_PRIVATE_KEY }}'}}]:
   doc=self.workflow();doc['jobs']['recovery']['steps'].append(addition)
   self.assertTrue(policy.validate(doc,'cvie-staging.yml'))
 def test_recovery_rejects_lost_guard_missing_preparation_or_extended_window(self):
  for change in [{'if':policy.STAGING_RELEASE},{'needs':[]},{'timeout-minutes':60},{'concurrency':{'group':'different'}}]:
   doc=self.workflow();doc['jobs']['recovery'].update(change);self.assertTrue(policy.validate(doc,'cvie-staging.yml'))
 def test_inventory_cannot_receive_recovery_keys_or_run_capture_unconditionally(self):
  for change in ['keys','guard','swap','receipt']:
   doc=self.workflow();steps=doc['jobs']['recovery']['steps']
   if change=='swap':steps[:]=[s for s in steps if 'swapoff' not in s.get('run','')]
   elif change=='receipt':next(s for s in steps if s.get('name')=='Execute approved private recovery operation')['env'].pop('CF_STAGING_RECOVERY_RESTORE_SIGNATURE')
   else:
    step=next(s for s in steps if s.get('name')=='Inspect staging recovery inventory only')
    if change=='keys':step['env']['KEY']='${{ secrets.CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY }}'
    else:step['if']='true'
   self.assertTrue(policy.validate(doc,'cvie-staging.yml'))

 def test_release_cannot_receive_recovery_storage_credentials(self):
  doc=self.workflow();doc['jobs']['release']['steps'].append({'run':'echo forbidden','env':{'KEY':'${{ secrets.CF_STAGING_RECOVERY_R2_SECRET_ACCESS_KEY }}'}})
  self.assertTrue(policy.validate(doc,'cvie-staging.yml'))

class SimplifiedReleaseSecurityTests(unittest.TestCase):
 def test_production_publishers_cannot_skip_exact_commit_ci_gate(self):
  for filename,job in [('bootstrap.yml','sync'),('deploy-worker-code.yml','deploy'),('deploy-account-worker.yml','deploy'),('activate-confirmation-domain.yml','activate')]:
   doc=policy.load_workflow((ROOT/'.github/workflows'/filename).read_text())
   self.assertEqual(policy.validate(doc,filename),[])
   doc['jobs'][job].pop('needs')
   self.assertTrue(policy.validate(doc,filename))
   doc=policy.load_workflow((ROOT/'.github/workflows'/filename).read_text())
   next(s for s in doc['jobs']['release-ready']['steps'] if s.get('run')=='python scripts/production_release_checks.py')['if']='false'
   self.assertTrue(policy.validate(doc,filename))
 def test_each_accounts_upload_requires_live_d1_preflight(self):
  publishers = [('deploy-worker-code.yml', 'deploy'), ('deploy-account-worker.yml', 'deploy'), ('activate-confirmation-domain.yml', 'activate')]
  for filename, job in publishers:
   with self.subTest(filename=filename):
    doc = policy.load_workflow((ROOT/'.github/workflows'/filename).read_text())
    steps = doc['jobs'][job]['steps']
    uploads = [i for i, s in enumerate(steps) if ' deploy' in s.get('run', '') and 'wrangler@' in s['run']]
    self.assertEqual(len(uploads), 1)
    index = uploads[0]
    self.assertGreater(index, 0)
    guard, upload = steps[index-1:index+1]
    self.assertEqual(guard['run'], 'node scripts/production_worker_preflight.mjs')
    self.assertNotIn('if', guard)
    self.assertNotIn('continue-on-error', guard)
    self.assertNotIn('if', upload)
    self.assertIn('--config wrangler.toml', upload['run'])
    self.assertEqual(upload['working-directory'], 'account-backend')
    for key in ['CLOUDFLARE_API_TOKEN', 'CLOUDFLARE_ACCOUNT_ID']:
     self.assertEqual(guard['env'][key], upload['env'][key])

 def test_automatic_staging_cannot_gain_production_or_manual_recovery_credentials(self):
  for secret in ['CVEHARBOR_PROD_WORKER_TOKEN','CF_STAGING_RECOVERY_EVIDENCE','CF_STAGING_APPROVED_COMMIT']:
   doc=policy.load_workflow((ROOT/'.github/workflows/cvie-staging.yml').read_text())
   doc['jobs']['automatic-staging']['steps'].append({'run':'echo unsafe','env':{'TOKEN':'${{ secrets.'+secret+' }}'}})
   self.assertTrue(policy.validate(doc,'cvie-staging.yml'))
 def test_frontend_wait_does_not_hold_the_production_mutation_lock(self):
  for filename,job in [('bootstrap.yml','sync'),('deploy-worker-code.yml','deploy')]:
   doc=policy.load_workflow((ROOT/'.github/workflows'/filename).read_text())
   self.assertNotIn('concurrency',doc)
   self.assertNotIn('concurrency',doc['jobs']['release-ready'])
   self.assertEqual(doc['jobs'][job]['concurrency'],{'group':'cveharbor-production-release','cancel-in-progress':False})
  self.assertTrue(any(s.get('run')=='node scripts/verify_frontend_backend.mjs --wait' for s in policy.load_workflow((ROOT/'.github/workflows/bootstrap.yml').read_text())['jobs']['release-ready']['steps']))

class CustomerCandidateWorkflowTests(unittest.TestCase):
 def test_candidate_requires_manual_main_opt_in_and_baseline_lane_disabled(self):
  doc=policy.load_workflow((policy.ROOT/'.github/workflows/cvie-staging.yml').read_text())
  job=doc['jobs']['customer-candidate']
  self.assertEqual(job['if'],policy.CANDIDATE_STAGING)
  self.assertEqual(doc['on']['workflow_dispatch']['inputs']['candidate_operation']['default'],'none')
  for condition in [job['if'].replace("github.event_name == 'workflow_dispatch'", "github.event_name == 'push'"),job['if'].replace(" && vars.SIMPLE_STAGING_ENABLED == 'false'",'')]:
   changed=copy.deepcopy(doc);changed['jobs']['customer-candidate']['if']=condition
   self.assertTrue(policy.validate(changed,'cvie-staging.yml'))
 def test_candidate_credentials_never_enter_build_and_baseline_is_read_only_dispatch(self):
  doc=policy.load_workflow((policy.ROOT/'.github/workflows/cvie-staging.yml').read_text())
  self.assertNotIn("github.event_name == 'push'",doc['jobs']['automatic-staging']['if'])
  self.assertIn('diagnose',doc['jobs']['automatic-staging']['if'])
  bad=copy.deepcopy(doc);bad['jobs']['customer-candidate']['steps'][0]['env']={'TOKEN':'${{ secrets.CF_STAGING_API_TOKEN }}'}
  self.assertTrue(policy.validate(bad,'cvie-staging.yml'))


class RoutineStagingWorkflowTests(unittest.TestCase):
    def test_workflow_uses_main_package_without_build_or_cloud_in_review(self):
        doc=policy.load_workflow((ROOT/'.github/workflows/cvie-staging.yml').read_text())
        prep=doc['jobs']['prepare']; job=doc['jobs']['customer-candidate']
        self.assertNotIn('environment',prep)
        self.assertEqual(job['needs'],'prepare')
        self.assertEqual(job['environment'],'cloudflare-cvie-staging')
        steps=prep['steps']+job['steps']
        for s in steps:
            if 'build.mjs' in s.get('run',''):self.assertIn("!= 'routine-deploy'",s['if'])
        checks=[s for s in steps if s.get('run')=='python staging/scripts/routine_review.py']
        self.assertEqual(len(checks),2)
        self.assertTrue(all('secrets.' not in str(s) for s in checks))
        self.assertEqual(checks[-1]['env']['EXPECTED_REVIEW'],'${{ needs.prepare.outputs.routine_review }}')
