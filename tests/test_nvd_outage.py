"""Outages must retain NVD evidence while healthy sources keep publishing."""
import importlib.util
import io
import json
from contextlib import ExitStack
from datetime import timedelta
from email.message import Message
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('outage_updater', ROOT/'scripts/update.py')
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class NvdOutageTests(unittest.TestCase):
    def test_transient_failures_do_not_sleep_or_burst_retry(self):
        headers = Message(); headers['Retry-After'] = '7200'
        failures = [HTTPError(u.SOURCES['nvd'], 503, 'Unavailable', headers, io.BytesIO()),
                    URLError('connection failed'), TimeoutError('timed out')]
        for error in failures:
            with self.subTest(error=type(error).__name__), patch.object(u.urllib.request, 'urlopen', side_effect=error) as request, patch.object(u.time, 'sleep') as sleep:
                with self.assertRaises(u.NvdUnavailable) as raised:
                    u.get_json(u.SOURCES['nvd'], 'nvd')
                self.assertEqual(request.call_count, 1)
                self.assertEqual(request.call_args.kwargs['timeout'], 22)
                sleep.assert_not_called()
                status = u.nvd_retry_status({}, raised.exception)
                self.assertFalse(u.nvd_retry_due(status))
                if isinstance(error, HTTPError):
                    self.assertGreaterEqual(status['next_retry_at'], (u.NOW+timedelta(hours=2)).isoformat(timespec='seconds').replace('+00:00','Z'))

    def test_retry_after_http_date_and_exponential_pause(self):
        from email.utils import format_datetime
        headers=Message(); headers['Retry-After']=format_datetime(u.NOW+timedelta(hours=3))
        with patch.object(u.urllib.request,'urlopen',side_effect=HTTPError(u.SOURCES['nvd'],429,'Rate limited',headers,None)):
            with self.assertRaises(u.NvdUnavailable) as raised:
                u.get_json(u.SOURCES['nvd'],'nvd')
        self.assertGreater(raised.exception.retry_after, 10790)
        status=u.nvd_retry_status({'consecutive_failures':4},TimeoutError())
        self.assertEqual(status['consecutive_failures'],5)
        self.assertFalse(u.nvd_retry_due(status))
        with patch.object(u,'NOW',u.NOW+timedelta(hours=5)):
            self.assertTrue(u.nvd_retry_due(status))

    def test_healthy_sources_publish_during_outage_and_cooldown_then_nvd_recovers(self):
        old_time=(u.NOW-timedelta(hours=3)).isoformat(timespec='seconds').replace('+00:00','Z')
        def record(number):
            return {'id':'CVE-2026-'+str(number),'categories':['Python / PyPI'],
                    'title':'Python fixture','summary':'Python fixture','affected':'Python',
                    'published':u.NOW.date().isoformat(),'updated':u.NOW.date().isoformat(),
                    'sources':[{'label':'Fixture','url':'https://example.test/advisory'}]}
        prior=u.observe_record(None,record(80001),'nvd')
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            for name,file in [('DATA','advisories.json'),('SCRIPT','data.js'),('HEALTH','feed-health.json')]:
                stack.enter_context(patch.object(u,name,Path(temp)/file))
            u.DATA.write_text(json.dumps({'advisories':[prior],'sources':{'nvd':{'ok':True,'last_success':old_time}},'last_successful_update':old_time}),encoding='utf-8')
            for name in ['php_upstream_items','rss_vendor_items','kubernetes_items','mariadb_items','redhat_items','vendor_baseline_items']:
                stack.enter_context(patch.object(u,name,return_value=[]))
            stack.enter_context(patch.object(u,'kev_items',return_value=[{'cveID':'CVE-2026-80001'}]))
            stack.enter_context(patch.object(u,'from_kev',return_value=None))
            stack.enter_context(patch.object(u,'ghsa_items',return_value=[{}]))
            stack.enter_context(patch.object(u,'from_ghsa',return_value=record(80002)))
            stack.enter_context(patch.object(u,'enrich_epss'))
            with patch.object(u,'nvd_items',side_effect=u.NvdUnavailable('NVD unavailable',7200)) as request:
                self.assertEqual(u.run(),0)
                first=json.loads(u.DATA.read_text(encoding='utf-8'))
                self.assertEqual({r['id'] for r in first['advisories']},{prior['id'],'CVE-2026-80002'})
                self.assertEqual(first['sources']['nvd']['last_success'],old_time)
                self.assertFalse(first['sources']['nvd']['ok'])
                self.assertEqual(first['mode'],'partial')
                self.assertTrue(first['sources']['github']['ok'])
                self.assertEqual(u.run(),0)
                self.assertEqual(request.call_count,1,'cooldown persists across collector runs')
                second=json.loads(u.DATA.read_text(encoding='utf-8'))
                self.assertEqual(second['sources']['nvd'],first['sources']['nvd'])
                health=json.loads(u.HEALTH.read_text(encoding='utf-8'))
                self.assertEqual(health['sources']['nvd']['next_retry_at'],first['sources']['nvd']['next_retry_at'])
            with patch.object(u,'NOW',u.NOW+timedelta(hours=3)), patch.object(u,'nvd_items',return_value=[]):
                self.assertEqual(u.run(),0)
            recovered=json.loads(u.DATA.read_text(encoding='utf-8'))
            self.assertTrue(recovered['sources']['nvd']['ok'])
            self.assertNotIn('next_retry_at',recovered['sources']['nvd'])


if __name__=='__main__': unittest.main()
