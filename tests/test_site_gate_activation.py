import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT/'scripts'))
import complete_site_gate_activation as activation


class GateActivationEvidenceTests(unittest.TestCase):
    def test_failed_deployment_redacts_secrets_and_does_not_disable_origin(self):
        password='fixture-with-quote-"-and-backslash-\\'
        def fail():
            print('Provider diagnostic '+password)
            raise RuntimeError('Failure '+password)
        with tempfile.TemporaryDirectory() as folder,patch.dict(os.environ,{'SITE_GATE_PASSWORD':password}),patch.object(activation.deploy_site_gate,'main',side_effect=fail),patch.object(activation.disable_public_pages_origin,'main') as disable,patch.object(activation.subprocess,'run') as verify:
            previous=Path.cwd()
            try:
                os.chdir(folder);Path('data').mkdir()
                with patch('builtins.print'):activation.main()
                report=json.loads(Path('data/site-gate-activation.json').read_text())
            finally:os.chdir(previous)
        self.assertFalse(report['success'])
        self.assertNotIn(password,report['diagnostic']+report['error'])
        disable.assert_not_called();verify.assert_not_called()

    def test_failed_asset_verification_keeps_previous_origin_available(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(activation.deploy_site_gate,'main'),patch.object(activation.disable_public_pages_origin,'main') as disable,patch.object(activation.subprocess,'run',side_effect=RuntimeError('Asset mismatch')):
            previous=Path.cwd()
            try:
                os.chdir(folder);Path('data').mkdir()
                with patch('builtins.print'):activation.main()
                report=json.loads(Path('data/site-gate-activation.json').read_text())
            finally:os.chdir(previous)
        self.assertFalse(report['success'])
        self.assertTrue(report['steps'][0]['success'])
        self.assertEqual(report['steps'][-1]['name'],'verify_published_assets')
        disable.assert_not_called()
