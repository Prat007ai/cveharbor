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
            with patch.object(mod,"ROOT",Path(folder)), patch.object(mod,"HISTORY",Path(folder)/"data"/"threat-ip-history.json"):
                mod.export_templates(report)
                fortinet=(Path(folder)/"fortigate-threat-ip-objects.txt").read_text()
                sophos=(Path(folder)/"sophos-threat-ip-api.txt").read_text()
            self.assertIn("config firewall address",fortinet)
            self.assertIn("set subnet 8.8.8.8 255.255.255.255",fortinet)
            self.assertIn('append member "CVEH_8_8_8_8"',fortinet)
            self.assertNotIn("config firewall policy",fortinet)
            self.assertIn("<HostType>IP</HostType>",sophos)
            self.assertIn("<IPAddress>8.8.8.8</IPAddress>",sophos)
            self.assertNotIn("127.0.0.1",sophos)
            self.assertNotIn("<FirewallRule>",sophos)

    def test_cumulative_and_incremental_exports(self):
        import tempfile, json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            first={"checked_at":"2026-10-28T10:00:00Z",
                   "sources":{"dshield_scanners":{"ok":True}},
                   "indicators":[{"ip":"8.8.8.8","source_id":"dshield_scanners"}]}
            second={"checked_at":"2026-10-29T10:00:00Z",
                    "sources":{"dshield_scanners":{"ok":True}},
                    "indicators":[{"ip":"1.1.1.1","source_id":"dshield_scanners"}]}
            with patch.object(mod,"ROOT",root),patch.object(mod,"HISTORY",root/"data"/"threat-ip-history.json"):
                mod.export_templates(first)
                mod.export_templates(second)
            history=json.loads((root/"data"/"threat-ip-history.json").read_text())
            self.assertEqual(set(history["addresses"]),{"8.8.8.8","1.1.1.1"})
            full=(root/"fortigate-suspicious-ip-initial.txt").read_text()
            delta=(root/"fortigate-suspicious-ip-incremental.txt").read_text()
            self.assertIn('edit "Suspicious IP Block"',full)
            self.assertIn('CVEH_8_8_8_8',full)
            self.assertIn('CVEH_1_1_1_1',full)
            self.assertIn('CVEH_1_1_1_1',delta)
            self.assertNotIn('CVEH_8_8_8_8',delta)
            sophos=(root/"sophos-suspicious-ip-incremental.txt").read_text()
            self.assertIn("REPLACE the complete HostList",sophos)
            self.assertNotIn("<IPHostGroup>",sophos)

    def test_does_not_label_collection_time_as_last_seen(self):
        content=(root/'scripts/update_threats.py').read_text()
        self.assertIn('"observed_at":None',content)

class ThreatCollectionHealthTests(unittest.TestCase):
    def collect_fixture(self, feeds, previous=None):
        import tempfile,json
        from datetime import datetime,timezone
        from unittest.mock import patch
        class Response:
            headers={'Last-Modified':'Sat, 31 Oct 2026 12:00:00 GMT'}
            def __init__(self,body): self.body=body.encode()
            def __enter__(self): return self
            def __exit__(self,*args): pass
            def read(self,limit): return self.body[:limit]
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);out=folder/'threat-data.js';(folder/'data').mkdir()
            if previous: out.write_text('window.CVEHARBOR_THREATS = '+json.dumps(previous)+';\n')
            cache={ip:{'country':'Test','latitude':1,'longitude':1} for body in feeds.values() if isinstance(body,str) for ip in body.splitlines() if mod.public_ipv4(ip)}
            (folder/'data/ip-geolocation-cache.json').write_text(json.dumps(cache))
            def fetch(request,timeout):
                url=request.full_url
                if 'ipwho.is' in url: raise AssertionError('Unexpected geolocation request')
                key=next(k for k,v in mod.FEEDS.items() if v[0]==url)
                value=feeds[key]
                if isinstance(value,Exception): raise value
                return Response(value)
            with patch.object(mod,'ROOT',folder),patch.object(mod,'OUT',out),patch.object(mod,'HISTORY',folder/'data/history.json'),patch.object(mod.urllib.request,'urlopen',side_effect=fetch),patch.object(mod,'datetime') as clock:
                clock.now.return_value=datetime(2026,10,31,13,tzinfo=timezone.utc)
                code=mod.collect();report=json.loads(out.read_text().split('=',1)[1].strip().removesuffix(';'))
                history=json.loads((folder/'data/history.json').read_text())
            return code,report,history

    def test_unchanged_list_preserves_change_time_but_records_a_fetch(self):
        feeds={'dshield_scanners':'8.8.8.8\n','feodo_c2':'1.1.1.1\n'}
        _,first,_=self.collect_fixture(feeds)
        first['last_changed_at']='2026-10-30T12:00:00Z'
        code,second,_=self.collect_fixture(feeds,first)
        self.assertEqual(code,0);self.assertEqual(second['mode'],'live')
        self.assertEqual(second['last_changed_at'],'2026-10-30T12:00:00Z')
        self.assertEqual((second['added_count'],second['removed_count']),(0,0))
        self.assertEqual(second['sources']['dshield_scanners']['last_success'],second['checked_at'])
        self.assertEqual(len(second['sources']['dshield_scanners']['body_sha256']),64)

    def test_same_count_can_contain_different_ips(self):
        _,first,_=self.collect_fixture({'dshield_scanners':'8.8.8.8\n','feodo_c2':'1.1.1.1\n'})
        code,second,_=self.collect_fixture({'dshield_scanners':'9.9.9.9\n','feodo_c2':'1.1.1.1\n'},first)
        self.assertEqual(code,0);self.assertEqual(first['count'],second['count'])
        self.assertEqual((second['added_count'],second['removed_count']),(1,1))

    def test_partial_failure_retains_failed_source_and_reports_failure(self):
        _,first,_=self.collect_fixture({'dshield_scanners':'8.8.8.8\n','feodo_c2':'1.1.1.1\n'})
        first['sources']['feodo_c2']['last_success']='2026-10-30T11:00:00Z'
        code,second,history=self.collect_fixture({'dshield_scanners':'9.9.9.9\n','feodo_c2':OSError('Source unavailable')},first)
        self.assertEqual(code,1);self.assertEqual(second['mode'],'partial')
        self.assertEqual(second['sources']['feodo_c2']['last_success'],'2026-10-30T11:00:00Z')
        self.assertTrue(next(x for x in second['indicators'] if x['ip']=='1.1.1.1')['stale'])
        self.assertNotIn('1.1.1.1',history['addresses'])
        self.assertIn('9.9.9.9',history['addresses'])

    def test_total_failure_does_not_publish_an_empty_healthy_list(self):
        _,first,_=self.collect_fixture({'dshield_scanners':'8.8.8.8\n','feodo_c2':'1.1.1.1\n'})
        code,second,_=self.collect_fixture({'dshield_scanners':OSError('Blocked'),'feodo_c2':OSError('Blocked')},first)
        self.assertEqual(code,1);self.assertEqual(second['mode'],'failed')
        self.assertEqual(second['count'],2);self.assertEqual(second['stale_count'],2)
        self.assertEqual(second['last_successful_update'],first['last_successful_update'])

    def test_truncation_is_explicit(self):
        code,report,_=self.collect_fixture({'dshield_scanners':'\n'.join('8.8.0.'+str(i) for i in range(1,201)),'feodo_c2':'1.1.1.1\n'})
        self.assertEqual(code,0)
        self.assertEqual(report['sources']['dshield_scanners']['count'],200)
        self.assertEqual(report['sources']['dshield_scanners']['published_count'],150)
        self.assertTrue(report['sources']['dshield_scanners']['truncated'])
