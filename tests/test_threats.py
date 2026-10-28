import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('threat_updater',root/'scripts/update_threats.py')
mod=importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class ThreatFeedTests(unittest.TestCase):
    def test_only_global_ipv4(self):
        self.assertEqual(mod.public_ipv4('8.8.8.8'),'8.8.8.8')
        for entry in ('127.0.0.1','10.1.1.2','192.168.1.10','::1','not-an-ip','224.0.0.1'):
            self.assertIsNone(mod.public_ipv4(entry))
    def test_public_sources_named_and_separate(self):
        self.assertIn('dshield_scanners',mod.FEEDS)
        self.assertIn('feodo_c2',mod.FEEDS)
        self.assertNotEqual(mod.FEEDS['dshield_scanners'][2],mod.FEEDS['feodo_c2'][2])
    def test_does_not_label_collection_time_as_last_seen(self):
        content=(root/'scripts/update_threats.py').read_text()
        self.assertIn('"observed_at":None',content)
