import importlib.util
import unittest
import json
import subprocess
import sys
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('updater',root/'scripts/update.py')
u=importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

class FeedTests(unittest.TestCase):
    def test_all_requested_categories(self):
        self.assertEqual(25,len(u.CATEGORIES))
        self.assertEqual([c['name'] for c in u.CATEGORIES[:21]], ["Windows Server OS","Windows 11 OS",".NET / ASP.NET",".NET Core","WordPress / Plugins","Linux","PHP","Python / PyPI","Azure","Microsoft 365","Exchange SE","SQL Server","MySQL / MariaDB","Fortinet","Sophos Firewall","VMware","Veeam Backup & Replication","HyperV","Docker / Kubernetes","Progress Telerik","Sitefinity"])
        self.assertIn('HyperV',[c['name'] for c in u.CATEGORIES])
        self.assertIn('.NET Core',[c['name'] for c in u.CATEGORIES])
        self.assertIn('Windows Server OS',[c['name'] for c in u.CATEGORIES])
        self.assertIn('Windows',[c['name'] for c in u.CATEGORIES])
        self.assertIn('Linux',[c['name'] for c in u.CATEGORIES])
        self.assertNotIn('Windows / Linux',[c['name'] for c in u.CATEGORIES])
    def test_windows_only(self):
        labels = u.classify(product="Microsoft Windows Server 2025", text="Windows Server operating system security update")
        self.assertIn('Windows Server OS',labels)
        self.assertNotIn('Windows',labels)
        self.assertNotIn('Linux',labels)
    def test_linux_only(self):
        labels = u.classify(product="Ubuntu Linux kernel", text="Ubuntu kernel privilege escalation")
        self.assertIn('Linux',labels)
        self.assertNotIn('Windows',labels)
    def test_both_operating_systems(self):
        labels = u.classify(product="Windows Server and Ubuntu Linux", text="Shared library affects both systems")
        self.assertIn('Windows Server OS',labels)
        self.assertIn('Linux',labels)
    def test_legacy_category_migration(self):
        migrated = u.migrate_legacy_categories({
            'id':'CVE-2026-80000','categories':['Windows / Linux'],
            'title':'Ubuntu Linux kernel vulnerability','affected':'Ubuntu 24.04',
            'summary':'Linux kernel security vulnerability'})
        self.assertEqual(['Linux'], migrated['categories'])
    def test_no_assumed_linux_for_openssh(self):
        labels = u.classify(product="OpenSSH", text="A remote service vulnerability")
        self.assertNotIn('Linux',labels)
        self.assertNotIn('Windows',labels)
    def test_windows_server_category(self):
        labels = u.classify(product="Microsoft Windows Server 2022", text="Security issue in Windows Server")
        self.assertIn('Windows Server OS', labels)
        self.assertNotIn('Windows', labels)
        self.assertNotIn('Linux', labels)
    def test_client_windows_category(self):
        labels = u.classify(product="Microsoft Windows 11", text="Client security fix")
        self.assertIn('Windows 11 OS', labels)
        self.assertNotIn('Windows Server OS', labels)
        self.assertNotIn('Windows', labels)
    def test_modern_dotnet(self):
        labels = u.classify(product="Microsoft ASP.NET Core 8.0", text="ASP.NET Core runtime security update")
        self.assertIn('.NET Core', labels)
        self.assertNotIn('.NET / ASP.NET', labels)
    def test_legacy_dotnet(self):
        labels = u.classify(product="ASP.NET Framework 4.8", text="Web Forms")
        self.assertIn('.NET / ASP.NET', labels)
        self.assertNotIn('.NET Core', labels)
    def test_hyperv(self):
        labels = u.classify(product="Microsoft Hyper-V", text="VM management service")
        self.assertIn('HyperV', labels)
    def test_new_category_migration(self):
        old = {'categories':['Windows'], 'title':'Microsoft Windows Server 2025',
               'affected':'Windows Server 2025','summary':'Server privilege elevation'}
        migrated = u.recategorize_existing(old)
        self.assertIn('Windows Server OS', migrated['categories'])
        self.assertNotIn('Windows', migrated['categories'])
    def test_progress_telerik_category(self):
        found = u.classify(product='Progress Telerik UI for ASP.NET AJAX',text='RadAsyncUpload vulnerability')
        self.assertIn('Progress Telerik',found)
        self.assertIn('.NET / ASP.NET',found)
    def test_sitefinity_is_separate_from_drupal(self):
        found = u.classify(product='Progress Sitefinity CMS',text='Sitefinity web services authentication')
        self.assertIn('Sitefinity',found)
        self.assertNotIn('Drupal / CMS',found)
    def test_veeam_backup_category(self):
        found = u.classify(product='Veeam Backup & Replication',text='CDP coordinator authorization bypass')
        self.assertIn('Veeam Backup & Replication',found)
    def test_managed_veeam_agent(self):
        found = u.classify(product='Veeam Agent for Linux',text='Managed backup agent privilege escalation')
        self.assertIn('Veeam Backup & Replication',found)
        self.assertIn('Linux',found)
    def test_sophos_firewall_only(self):
        self.assertIn('Sophos Firewall',u.classify(product='Sophos Firewall SFOS 21.5'))
        self.assertNotIn('Sophos Firewall',u.classify(product='Sophos Endpoint'))
    def test_windows11_separate(self):
        found=u.classify(product='Microsoft Windows 11 Version 25H2')
        self.assertIn('Windows 11 OS',found)
        self.assertNotIn('Windows Server OS',found)
        self.assertNotIn('Windows',found)
    def test_exchange_se_separate(self):
        found=u.classify(product='Microsoft Exchange Server Subscription Edition RTM')
        self.assertIn('Exchange SE',found)
    def test_old_sitefinity_migration(self):
        found=u.recategorize_existing({'categories':['Drupal / CMS'], 'title':'Progress Sitefinity', 'affected':'Progress Sitefinity CMS 15.4', 'summary':'Sitefinity security'})
        self.assertIn('Sitefinity',found['categories'])
        self.assertNotIn('Drupal / CMS',found['categories'])
    def test_vendor_baseline_records_have_sources_and_historical_dates(self):
        records=u.vendor_baseline_items()
        self.assertGreaterEqual(len(records),6)
        for item in records:
            self.assertTrue(item['sources'])
            self.assertIn(item['categories'][0],[x['name'] for x in u.CATEGORIES])
            self.assertEqual(item['source_type'],'vendor_baseline')
            self.assertEqual(item['status'],'Vendor-sourced historical baseline; not newly disclosed')
    def test_public_site_build_contains_vendor_catalog(self):
        result = subprocess.run([sys.executable,str(root/'scripts/build_site.py')],cwd=root,
                                capture_output=True,text=True,check=True)
        exported = root/'public'/'catalog.js'
        self.assertTrue(exported.exists(),result.stdout + result.stderr)
        body=exported.read_text(encoding='utf-8')
        self.assertTrue(body.startswith('window.CVEHARBOR_CATALOG = '))
        obj=json.loads(body.partition(' = ')[2].strip().removesuffix(';'))
        self.assertEqual(25,len(obj['categories']))
        for name in ('Progress Telerik','Sitefinity','Veeam Backup & Replication',
                     'Sophos Firewall','Windows 11 OS','Exchange SE'):
            self.assertIn(name,[c['name'] for c in obj['categories']])
        self.assertGreaterEqual(len(obj['advisories']),8)
        self.assertIn('CVE-2026-13185',[x['id'] for x in obj['advisories']])
    def test_site_places_source_health_after_main(self):
        html=(root/'index.html').read_text(encoding='utf-8')
        self.assertGreater(html.index('id="feedHeadline"'),html.index('</main>'))
        self.assertIn('catalog.js?v=',html)
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
