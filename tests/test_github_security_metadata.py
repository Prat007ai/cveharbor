import importlib.util
import json
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('security_metadata',Path(__file__).resolve().parents[1]/'scripts/audit_github_security_metadata.py')
audit=importlib.util.module_from_spec(spec);spec.loader.exec_module(audit)

class MetadataAuditTests(unittest.TestCase):
    def fake(self, endpoint):
        if endpoint=='user':return [{'plan':{'name':'free'},'email':'not-for-report@example.test'}],None
        if endpoint==audit.BASE:return [{'private':False,'visibility':'public','owner':{'type':'User'}}],None
        if endpoint.endswith('/branches/main'):return [{'protected':False}],None
        if endpoint.endswith('/rulesets'):return [[]],None
        if endpoint.endswith('/environments'):return [{'environments':[{'name':'cloudflare-worker-production'}]}],None
        if endpoint.endswith('/deployment-branch-policies'):return [{'branch_policies':[{'name':'main','type':'branch'}]}],None
        if endpoint.endswith('/secrets'):return [{'secrets':[{'name':'CLOUDFLARE_API_TOKEN','updated_at':'2026-11-03','value':'MUST_NOT_APPEAR'}]}],None
        if '/environments/' in endpoint:return [{'can_admins_bypass':False,'deployment_branch_policy':{'custom_branch_policies':True},'protection_rules':[{'type':'required_reviewers','prevent_self_review':True,'reviewers':[{'type':'User','reviewer':{'login':'reviewer','email':'private@example.test'}}]}]}],None
        return [{}],None
    def test_names_locations_and_plan_without_values(self):
        r=audit.collect(self.fake);out=json.dumps(r)
        self.assertEqual(r['plan_name'],'free');self.assertTrue(r['plan_verified']);self.assertFalse(r['main_protected'])
        self.assertEqual(r['repository_secret_metadata'][0]['name'],'CLOUDFLARE_API_TOKEN')
        self.assertEqual(r['environments'][0]['secret_metadata'][0]['name'],'CLOUDFLARE_API_TOKEN')
        for value in ['MUST_NOT_APPEAR','not-for-report@example.test','private@example.test']:self.assertNotIn(value,out)
    def test_denied_metadata_remains_unknown(self):
        r=audit.collect(lambda path:(None,'Metadata unavailable (HTTP 403)'))
        self.assertIsNone(r['environments']);self.assertIsNone(r['repository_secret_metadata'])
        self.assertIsNone(r['main_protected']);self.assertFalse(r['plan_verified']);self.assertTrue(r['unavailable'])
    def test_missing_plan_is_not_assumed_free(self):
        r=audit.collect(lambda p:([{}],None) if p=='user' else self.fake(p))
        self.assertIsNone(r['plan_name']);self.assertFalse(r['plan_verified'])
    def test_only_get_and_no_token_argument(self):
        with patch.object(audit.subprocess,'run',return_value=subprocess.CompletedProcess([],0,'[{}]','')) as run:
            audit.gh_get(audit.BASE+'/actions/secrets')
        cmd=run.call_args.args[0];self.assertEqual(cmd[:4],['gh','api','--method','GET'])
        self.assertNotIn('--field',cmd);self.assertNotIn('--input',cmd)
    def test_nonmetadata_endpoint_rejected(self):
        for path in [audit.BASE+'/actions/workflows/security-phase1-audit.yml/dispatches',audit.BASE+'/contents/data.js','https://api.cloudflare.com/client/v4/accounts',audit.BASE+'/actions/secrets/CLOUDFLARE_API_TOKEN']:
            with self.subTest(path=path),self.assertRaises(ValueError):audit.gh_get(path)
    def test_cli_error_is_sanitized(self):
        with patch.object(audit.subprocess,'run',return_value=subprocess.CompletedProcess([],1,'','HTTP 403 MUST_NOT_APPEAR')):
            pages,error=audit.gh_get('user')
        self.assertIsNone(pages);self.assertEqual(error,'Metadata unavailable (HTTP 403)')

if __name__=='__main__':unittest.main()
