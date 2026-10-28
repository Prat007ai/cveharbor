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
    def test_firewall_exports_create_objects_without_automatic_deny_rules(self):
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            report={"checked_at":"2026-10-28T12:00:00Z","sources":{
                "dshield_scanners":{"ok":True},"feodo_c2":{"ok":True}},
                "indicators":[
                    {"ip":"8.8.8.8","source_id":"dshield_scanners"},
                    {"ip":"1.1.1.1","source_id":"feodo_c2"},
                    {"ip":"127.0.0.1","source_id":"feodo_c2"}]}
            with patch.object(mod,"ROOT",Path(folder)):
                mod.export_templates(report)
                fortinet=(Path(folder)/"fortigate-threat-ip-objects.txt").read_text()
                sophos=(Path(folder)/"sophos-threat-ip-api.txt").read_text()
            self.assertIn("config firewall address",fortinet)
            self.assertIn("set subnet 8.8.8.8 255.255.255.255",fortinet)
            self.assertIn('append member "CVEH_8_8_8_8"',fortinet)
            self.assertNotIn("config firewall policy",fortinet)
            self.assertIn("<HostType>IPList</HostType>",sophos)
            self.assertIn("<ListOfIPAddresses>8.8.8.8</ListOfIPAddresses>",sophos)
            self.assertNotIn("127.0.0.1",sophos)
            self.assertNotIn("<FirewallRule>",sophos)

    def test_does_not_label_collection_time_as_last_seen(self):
        content=(root/'scripts/update_threats.py').read_text()
        self.assertIn('"observed_at":None',content)
