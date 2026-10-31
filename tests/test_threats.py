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
        self.requests=[]
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp);out=folder/'threat-data.js';(folder/'data').mkdir()
            if previous: out.write_text('window.CVEHARBOR_THREATS = '+json.dumps(previous)+';\n')
            cache={ip:{'country':'Test','latitude':1,'longitude':1} for body in feeds.values() if isinstance(body,str) for ip in body.splitlines() if mod.public_ipv4(ip)}
            (folder/'data/ip-geolocation-cache.json').write_text(json.dumps(cache))
            def fetch(request,timeout):
                url=request.full_url
                self.requests.append(request)
                if 'ipwho.is' in url:return Response(json.dumps({'success':True,'country':'Test','latitude':1,'longitude':1}))
                key=next(k for k,v in mod.FEEDS.items() if v[0]==url)
                value=feeds[key]
                if isinstance(value,Exception): raise value
                return Response(value)
            with patch.object(mod,'FEEDS',{k:mod.FEEDS[k] for k in feeds}),patch.object(mod,'ROOT',folder),patch.object(mod,'OUT',out),patch.object(mod,'HISTORY',folder/'data/history.json'),patch.object(mod.urllib.request,'urlopen',side_effect=fetch),patch.object(mod,'datetime') as clock:
                clock.now.return_value=datetime(2026,10,31,13,tzinfo=timezone.utc)
                clock.fromisoformat.side_effect=datetime.fromisoformat
                clock.fromtimestamp.side_effect=datetime.fromtimestamp
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
        code,report,_=self.collect_fixture({'dshield_scanners':'\n'.join('8.8.'+str(i//250)+'.'+str(i%250+1) for i in range(600)),'feodo_c2':'1.1.1.1\n'})
        self.assertEqual(code,0)
        self.assertEqual(report['sources']['dshield_scanners']['count'],600)
        self.assertEqual(report['sources']['dshield_scanners']['published_count'],500)
        self.assertTrue(report['sources']['dshield_scanners']['truncated'])

class ExpandedThreatSourceTests(unittest.TestCase):
    def setUp(self):
        from datetime import datetime,timezone
        self.now=datetime(2026,10,31,13,tzinfo=timezone.utc)

    def test_drop_ranges_remain_ranges_and_preserve_source_evidence(self):
        raw='{"cidr":"8.8.0.0/24","sblid":"SBL12345"}\n{"cidr":"10.0.0.0/8","sblid":"SBL12346"}\n{"type":"metadata","timestamp":1793451600}\n'
        entries=mod.parse_source('spamhaus_drop',raw,self.now)
        self.assertEqual(list(entries),['8.8.0.0/24'])
        self.assertEqual(entries['8.8.0.0/24']['kind'],'network')
        self.assertEqual(entries['8.8.0.0/24']['sbl_id'],'SBL12345')
        self.assertIsNone(mod.public_network('0.0.0.0/0'))
        self.assertIsNone(mod.public_network('8.8.0.1/24'))

    def test_threatfox_preserves_evidence_and_expires_old_iocs(self):
        import json
        rows=[{'id':1,'ioc_type':'ip:port','ioc':'8.8.8.8:443','first_seen':'2026-10-30 10:00:00','last_seen':'2026-10-31 10:00:00','confidence_level':90,'malware_printable':'Test family','threat_type':'botnet_cc'},
              {'id':2,'ioc_type':'ip:port','ioc':'8.8.8.8:8443','first_seen':'2026-10-29 10:00:00','last_seen':None,'confidence_level':80},
              {'id':3,'ioc_type':'ip:port','ioc':'1.1.1.1:443','first_seen':'2026-08-01 10:00:00'},
              {'id':4,'ioc_type':'domain','ioc':'example.test','first_seen':'2026-10-30 10:00:00'},
              {'id':5,'ioc_type':'ip:port','ioc':'10.0.0.1:443','first_seen':'2026-10-30 10:00:00'}]
        entries=mod.parse_source('threatfox',json.dumps({'query_status':'ok','data':rows}),self.now)
        self.assertEqual(list(entries),['8.8.8.8'])
        self.assertEqual(len(entries['8.8.8.8']['evidence']),2)
        self.assertEqual(entries['8.8.8.8']['evidence'][0]['source_confidence'],90)
        self.assertEqual(entries['8.8.8.8']['last_seen'],'2026-10-31T10:00:00+00:00')
        self.assertEqual(entries['8.8.8.8']['expires_at'],'2026-11-30T10:00:00+00:00')
        self.assertEqual(mod.parse_source('threatfox','{"query_status":"no_result"}',self.now),{})
        with self.assertRaises(ValueError):mod.parse_source('threatfox','{"query_status":"wrong_auth_key"}',self.now)

    def test_ranges_never_become_single_host_firewall_exports(self):
        import tempfile,json
        with tempfile.TemporaryDirectory() as tmp:
            folder=Path(tmp)
            report={'checked_at':self.now.isoformat(),'sources':{'spamhaus_drop':{'ok':True}},'indicators':[{'ip':'8.8.0.0/24','network':'8.8.0.0/24','kind':'network','source_id':'spamhaus_drop'}]}
            with patch.object(mod,'ROOT',folder),patch.object(mod,'HISTORY',folder/'history.json'):mod.export_templates(report)
            self.assertEqual(json.loads((folder/'history.json').read_text())['addresses'],{})
            self.assertNotIn('8.8.0.0',(folder/'fortigate-suspicious-ip-initial.txt').read_text())

    def test_threatfox_without_key_is_explicitly_unavailable(self):
        import os
        with patch.dict(os.environ,{},clear=True):
            code,report,_=ThreatCollectionHealthTests().collect_fixture({'threatfox':OSError('must not request without key')})
        self.assertEqual(code,1)
        self.assertIn('THREATFOX_AUTH_KEY',report['sources']['threatfox']['error'])

    def test_threatfox_api_utc_timestamps_produce_ip_evidence(self):
        import json
        diagnostics={}
        payload=json.dumps({'query_status':'ok','data':[{'id':42,'ioc_type':'ip:port','ioc':'8.8.8.8:443','first_seen_utc':'2026-10-30 12:00:00','last_seen_utc':'2026-10-31 10:00:00'}]})
        entries=mod.parse_source('threatfox',payload,self.now,diagnostics)
        self.assertEqual(entries['8.8.8.8']['first_seen'],'2026-10-30T12:00:00+00:00')
        self.assertEqual(entries['8.8.8.8']['last_seen'],'2026-10-31T10:00:00+00:00')
        self.assertEqual(entries['8.8.8.8']['evidence'][0]['ioc_id'],'42')
        self.assertEqual(diagnostics['ip_port_records'],1)
        self.assertEqual(diagnostics['missing_observation'],0)

    def test_threatfox_unix_observations_work_in_the_collector(self):
        import json,os
        payload=json.dumps({'query_status':'ok','data':[{'id':42,'ioc_type':'ip:port','ioc':'8.8.8.8:443','first_seen':int(self.now.timestamp())-86400,'last_seen':int(self.now.timestamp())-3600}]})
        with patch.dict(os.environ,{'THREATFOX_AUTH_KEY':'unit-test-placeholder'}):
            code,report,_=ThreatCollectionHealthTests().collect_fixture({'threatfox':payload})
        self.assertEqual(code,0)
        self.assertEqual(report['sources']['threatfox']['count'],1)
        self.assertEqual(report['indicators'][0]['last_seen'],'2026-10-31T12:00:00+00:00')

    def test_source_dates_support_unix_seconds_milliseconds_and_iso(self):
        epoch=int(self.now.timestamp())
        for value in (epoch,str(epoch),str(epoch*1000),self.now.isoformat(),'2026-10-31 13:00:00 UTC'):
            self.assertEqual(mod.source_time(value),self.now)
        for value in ('invalid',True,float('inf')):self.assertIsNone(mod.source_time(value))

    def test_threatfox_missing_timestamp_schema_does_not_silently_publish_empty_success(self):
        import json
        payload=json.dumps({'query_status':'ok','data':[{'ioc_type':'ip:port','ioc':'8.8.8.8:443'}]})
        with self.assertRaisesRegex(ValueError,'lack usable observation timestamps'):
            mod.parse_source('threatfox',payload,self.now)

    def test_threatfox_uses_authenticated_post_without_publishing_the_key(self):
        import os,json
        fixture=ThreatCollectionHealthTests()
        payload=json.dumps({'query_status':'ok','data':[{'id':1,'ioc_type':'ip:port','ioc':'8.8.8.8:443','first_seen':'2026-10-31 12:00:00'}]})
        with patch.dict(os.environ,{'THREATFOX_AUTH_KEY':'unit-test-placeholder'}):
            code,report,_=fixture.collect_fixture({'threatfox':payload})
        self.assertEqual(code,0)
        request=fixture.requests[0]
        self.assertEqual(request.get_method(),'POST')
        self.assertEqual(json.loads(request.data),{'query':'get_iocs','days':7})
        self.assertTrue(request.get_header('Auth-key'))
        self.assertNotIn('unit-test-placeholder',json.dumps(report))

    def test_failed_source_retention_expires_after_72_hours(self):
        fixture=ThreatCollectionHealthTests()
        _,first,_=fixture.collect_fixture({'dshield_scanners':'8.8.8.8\n'})
        first['sources']['dshield_scanners']['last_success']='2026-10-01T12:00:00Z'
        code,report,_=fixture.collect_fixture({'dshield_scanners':OSError('Unavailable')},first)
        self.assertEqual(code,1)
        self.assertEqual(report['indicators'],[])

    def test_threatfox_accepts_weekly_response_larger_than_four_megabytes(self):
        import os,json
        payload=json.dumps({'query_status':'ok','data':[{'id':1,'ioc_type':'ip:port','ioc':'8.8.8.8:443','first_seen':'2026-10-31 12:00:00'}], 'padding':'x'*4_100_000})
        with patch.dict(os.environ,{'THREATFOX_AUTH_KEY':'unit-test-placeholder'}):
            code,report,_=ThreatCollectionHealthTests().collect_fixture({'threatfox':payload})
        self.assertEqual(code,0)
        self.assertEqual(report['sources']['threatfox']['count'],1)
        self.assertEqual(len(report['indicators']),1)
        self.assertNotIn('padding',json.dumps(report))
