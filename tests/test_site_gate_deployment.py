import contextlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('site_gate_deployer',ROOT/'scripts/deploy_site_gate.py')
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
PASSWORD='fixture-only-strong-password'


class SiteGateDeploymentTests(unittest.TestCase):
    def test_missing_or_weak_password_blocks_before_any_cloudflare_changes(self):
        for value in ('','short','fixture-password\nwith-newline'):
            with patch.dict(os.environ,{'SITE_GATE_PASSWORD':value,'CLOUDFLARE_ACCOUNT_ID':'fixture-account'}),patch.object(mod,'cloudflare') as api,patch.object(mod,'wrangler') as cli:
                with self.assertRaisesRegex(RuntimeError,'SITE_GATE_PASSWORD'):mod.main()
                api.assert_not_called();cli.assert_not_called()

    def deployment(self,existing=False,staging_fails=False,unexpected_origin=False):
        calls=[]
        def cf(path,method='GET',data=None,allow_not_found=False):
            calls.append(('api',method,path,data))
            if path.startswith('/zones?'):return [{'id':'fixture-zone','name':'cveharbor.com','status':'active','account':{'id':'fixture-account'}}]
            if path.endswith('/workers/routes'):return [{'pattern':'api.cveharbor.com/*','script':'cveharbor-accounts'}]
            if '/dns_records?' in path:
                if 'www.' in path:return [{'id':'www','name':'www.cveharbor.com','type':'CNAME','content':'prat007ai.github.io','proxied':False,'proxiable':True}]
                return [{'id':'apex','name':'cveharbor.com','type':'A','content':'203.0.113.1' if unexpected_origin else '185.199.108.153','proxied':False,'proxiable':True},
                        {'id':'mail','name':'cveharbor.com','type':'MX','content':'mail.example.test'},
                        {'id':'account-api','name':'api.cveharbor.com','type':'A','content':'1.1.1.1'}]
            if path.endswith('/settings'):return {'bindings':[{'name':'SITE_GATE_USERNAME'}]} if existing else None
            if method=='PATCH':return {'success':True}
            raise AssertionError('Unexpected provider request: '+path)
        def cli(arguments,password=None):
            calls.append(('wrangler',arguments,password))
            self.assertNotIn(PASSWORD,' '.join(arguments),'password must only travel on stdin')
            return 'Published https://cveharbor-site.fixture.workers.dev'
        def probe(url,*args):
            calls.append(('probe',url))
            if staging_fails and url.endswith('.workers.dev'):raise RuntimeError('Staging inaccessible')
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'SITE_GATE_PASSWORD':PASSWORD,'CLOUDFLARE_ACCOUNT_ID':'fixture-account','RUNNER_TEMP':folder}),patch.object(mod,'cloudflare',side_effect=cf),patch.object(mod,'wrangler',side_effect=cli),patch.object(mod,'probe',side_effect=probe),patch.object(mod.time,'sleep'):
            if staging_fails or unexpected_origin:
                with self.assertRaises(RuntimeError):mod.main()
            else:mod.main()
        return calls

    def test_initial_deployment_verifies_private_staging_before_frontend_routing(self):
        calls=self.deployment()
        staging=next(i for i,c in enumerate(calls) if c[0]=='probe' and c[1].endswith('.workers.dev'))
        routed=next(i for i,c in enumerate(calls) if c[0]=='wrangler' and c[1]==['deploy','--config',str(mod.CONFIG)])
        patches=[(i,c) for i,c in enumerate(calls) if c[:2]==('api','PATCH')]
        self.assertLess(staging,routed)
        self.assertEqual(len(patches),2)
        self.assertTrue(all(i>routed for i,_ in patches))
        self.assertEqual({c[2].rsplit('/',1)[-1] for _,c in patches},{'apex','www'})
        self.assertTrue(all(c[3]=={'proxied':True,'ttl':1} for _,c in patches))
        self.assertEqual(calls[-1],('probe','https://cveharbor.com'))

    def test_recurring_updates_do_not_remove_routes_or_open_a_staging_hostname(self):
        calls=self.deployment(existing=True)
        deployments=[c for c in calls if c[0]=='wrangler' and c[1][0]=='deploy']
        self.assertEqual([c[1] for c in deployments],[['deploy','--config',str(mod.CONFIG)]])
        self.assertFalse(any(c[0]=='probe' and c[1].endswith('.workers.dev') for c in calls))

    def test_failed_staging_leaves_frontend_dns_and_routes_unchanged(self):
        calls=self.deployment(staging_fails=True)
        self.assertFalse(any(c[:2]==('api','PATCH') for c in calls))
        self.assertFalse(any(c[0]=='wrangler' and c[1]==['deploy','--config',str(mod.CONFIG)] for c in calls))

    def test_unexpected_dns_origin_is_not_replaced_or_proxied(self):
        calls=self.deployment(unexpected_origin=True)
        self.assertFalse(any(c[0]=='wrangler' or c[:2]==('api','PATCH') for c in calls))

    def test_cli_output_never_reveals_password_or_cloudflare_token(self):
        token='fixture-only-api-token'
        result=SimpleNamespace(returncode=1,stdout='Diagnostic '+PASSWORD,stderr='Token '+token)
        capture=io.StringIO()
        with patch.dict(os.environ,{'SITE_GATE_PASSWORD':PASSWORD,'CLOUDFLARE_API_TOKEN':token}),patch.object(mod.subprocess,'run',return_value=result),contextlib.redirect_stdout(capture):
            with self.assertRaises(RuntimeError):mod.wrangler(['deploy'])
        self.assertNotIn(PASSWORD,capture.getvalue());self.assertNotIn(token,capture.getvalue())

    def test_ci_authentication_is_scoped_to_frontend_origins_and_realm(self):
        import sys,urllib.request
        path=str(ROOT/'scripts');sys.path.insert(0,path)
        try:
            import site_gate_client
            with patch.dict(os.environ,{'SITE_GATE_PASSWORD':PASSWORD,'SITE_GATE_USERNAME':'cveharbor'}),patch.object(urllib.request,'install_opener') as install:
                site_gate_client.install_site_auth()
            opener=install.call_args.args[0]
            auth=next(h for h in opener.handlers if isinstance(h,urllib.request.HTTPBasicAuthHandler))
            self.assertEqual(auth.passwd.find_user_password('CVEHarbor development','https://cveharbor.com/account/'),('cveharbor',PASSWORD))
            self.assertEqual(auth.passwd.find_user_password('CVEHarbor development','https://api.cveharbor.com/v1/me'),(None,None))
            self.assertEqual(auth.passwd.find_user_password('CVEHarbor development','https://example.test/'),(None,None))
        finally:sys.path.remove(path)
