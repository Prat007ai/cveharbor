import unittest
from datetime import date
from urllib.parse import parse_qs, urlsplit

from monitor_version_scans import CONFIG, compare, period_start, probe, targets


class DailyScanTests(unittest.TestCase):
    day = date(2026, 11, 9)

    def test_inventory_includes_every_card_product_and_both_windows(self):
        catalogue = dict(CONFIG, releases={k:{'versions':[{'version':'1.2'}]} for k in CONFIG['products']})
        checks = set(targets(catalogue))
        self.assertEqual({k for k,v,m in checks}, set(CONFIG['products']))
        self.assertEqual({(k,m) for k,v,m in checks}, {(k,m) for k in CONFIG['products'] for m in (3,12)})
        self.assertIn(('ubuntu','24.04.5',12),checks)
        with self.assertRaises(ValueError):
            list(targets(dict(catalogue, cards={})))

    def test_pagination_and_components(self):
        calls = []
        pages = [
            dict(rows=[], componentRows=[dict(id='CVE-1',scope='optional')], next='more',nextQuarter=1),
            dict(rows=[],next=None,nextQuarter=1),
            dict(rows=[dict(id='CVE-2')],next=None,nextQuarter=2),
        ]
        def read(path):
            calls.append(parse_qs(urlsplit(path).query))
            return pages.pop(0)
        result = probe(('react','19.2',12),str(self.day),read)
        self.assertEqual(result['empty'],[])
        self.assertEqual([c['quarter'] for c in calls],[['0'],['0'],['1']])
        self.assertEqual(calls[1]['cursor'],['more'])

    def test_component_alone_cannot_hide_direct_zero(self):
        page = dict(rows=[],componentRows=[dict(id='X',scope='bundled')],next=None,nextQuarter=None)
        result = probe(('npm','11.5',3),str(self.day),lambda _:page)
        self.assertEqual(result['empty'],['direct'])

    def test_incomplete_page_never_becomes_zero(self):
        for page in ({'rows':[]},{'rows':[], 'next':'same', 'nextQuarter':None},{'rows':None}):
            result = probe(('php','8.4',3),str(self.day),lambda _:page)
            self.assertIn('error',result)
            self.assertNotIn('empty',result)

    def test_private_source_warning_survives_a_completed_public_page(self):
        pages = iter([dict(rows=[], next='more', nextQuarter=None, coverageGaps=['Private vendor channel']),
                      dict(rows=[], next=None, nextQuarter=None, coverageGaps=[])])
        result = probe(('esxi','12345678',3),str(self.day),lambda _:next(pages))
        self.assertTrue(result['coverage_incomplete'])
        self.assertIn('Coverage incomplete',compare([result],self.day,{},{})[1][0])

    def test_period_boundaries(self):
        self.assertEqual(period_start(self.day,3),'2026-08-10')
        self.assertEqual(period_start(date(2024,5,31),3),'2024-03-01')
        self.assertEqual(period_start(self.day,12),'2025-11-10')

    def test_vendor_evidence_dates_and_missing_source(self):
        def scan(months):
            return dict(key='sql2016',version='13.0', months=months,empty=['direct'])
        ref = ('sql2016','13.0','direct')
        witness = lambda day: dict(id='KB123',published=day,url='https://support.microsoft.com/')
        results = [scan(3),scan(12)]
        failures, checked = compare(results,self.day,{ref:[witness('2026-08-09'),witness('2026-11-10')]},{})
        self.assertEqual(len(failures),1)
        self.assertIn('12 months',failures[0])
        self.assertIn('KB123',failures[0])
        self.assertIn('Coverage incomplete',checked[0])
        incomplete, checked = compare(results,self.day,{},{ref:['Microsoft']})
        self.assertEqual(len(incomplete),2)
        self.assertIn('incomplete',incomplete[0])
        self.assertFalse(checked)
