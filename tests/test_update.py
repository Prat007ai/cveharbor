import importlib.util
import unittest
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('updater',root/'scripts/update.py')
u=importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

class FeedTests(unittest.TestCase):
    def test_all_requested_categories(self):
        self.assertEqual(15,len(u.CATEGORIES))
    def test_pip_classification(self):
        self.assertIn('Python / PyPI',u.classify(product='hydra-core',ecosystem='pip'))
        self.assertIn('Application dependencies',u.classify(product='hydra-core',ecosystem='pip'))
    def test_microsoft_azure(self):
        self.assertIn('Azure',u.classify(product='Microsoft Azure App Service'))
    def test_no_generic_false_positive(self):
        self.assertEqual([],u.classify(product='an unrelated printer',text='Node 5 in a building has a window'))
    def test_ghsa_versions(self):
        fake={'ghsa_id':'GHSA-abcd-1234-efgh','cve_id':'CVE-2026-12345','severity':'high','summary':'Remote code execution in Example Package',
              'description':'A crafted input can reach an unsafe parser',
              'published_at':'2026-10-26T10:00:00Z','updated_at':'2026-10-27T12:00:00Z',
              'vulnerabilities':[{'package':{'ecosystem':'pip','name':'example-lib'},'vulnerable_version_range':'< 2.0',
                                  'first_patched_version':{'identifier':'2.0'}}],
              'references':[], 'cvss':{'score':8.8}}
        a=u.from_ghsa(fake)
        self.assertEqual(a['id'],'CVE-2026-12345')
        self.assertIn('Python / PyPI',a['categories'])
        self.assertIn('2.0',a['remediation'])
        self.assertFalse(a['known_exploited'])
    def test_cisa_flag_merges(self):
        old={'id':'CVE-2026-99999','categories':['PHP'],'first_seen_at':'2026-10-26T01:00:00Z',
             'source_type':'github','known_exploited':False,'summary':'vendor report',
             'sources':[{'label':'Original','url':'https://github.com/advisories/GHSA-aaaa-bbbb-cccc'}],
             'updated':'2026-10-26'}
        new={'id':'CVE-2026-99999','categories':['PHP'],'first_seen_at':'2026-10-27T01:00:00Z',
             'source_type':'cisa_kev','known_exploited':True, 'summary':'listed',
             'sources':[{'label':'CISA','url':'https://www.cisa.gov/known-exploited-vulnerabilities-catalog'}],
             'updated':'2026-10-27'}
        merged=u.merge_record(old,new)
        self.assertTrue(merged['known_exploited'])
        self.assertEqual(merged['first_seen_at'],old['first_seen_at'])
        self.assertEqual(merged['summary'],'vendor report')
    def test_url_rejection(self):
        self.assertFalse(u.clean_url('javascript:alert(1)'))
        self.assertFalse(u.clean_url('http://example.org'))
        self.assertEqual(u.clean_url('https://nvd.nist.gov/'),'https://nvd.nist.gov/')

if __name__=='__main__':unittest.main()
