import importlib.util
import unittest
import json
import subprocess
import sys
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse
from pathlib import Path
root=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('updater',root/'scripts/update.py')
u=importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)

class FeedTests(unittest.TestCase):
    def test_all_requested_categories(self):
        self.assertEqual(38,len(u.CATEGORIES))
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
        self.assertIn('.NET / ASP.NET', labels)
    def test_dotnet_umbrella_includes_runtime_packages(self):
        labels = u.classify(product="Microsoft.NETCore.App.Runtime", ecosystem="nuget",text="Modern .NET runtime issue")
        self.assertIn('.NET / ASP.NET', labels)
    def test_recent_official_dotnet_advisories_are_in_catalog(self):
        data=u.vendor_baseline_items()
        by_id={x['id']:x for x in data}
        modern=('CVE-2026-111497','CVE-2026-114148','CVE-2026-70197',
                'CVE-2026-102870','CVE-2026-88092','CVE-2026-70188')
        for cve in modern:
            self.assertIn(cve,by_id)
            self.assertIn('.NET Core',by_id[cve]['categories'])
            self.assertIn('.NET / ASP.NET',by_id[cve]['categories'])
            self.assertTrue(by_id[cve]['sources'])
        self.assertIn('CVE-2026-108398',by_id)
        self.assertTrue(by_id['CVE-2026-111497']['known_exploited'])
        self.assertIn('.NET / ASP.NET',by_id['CVE-2026-108398']['categories'])
        self.assertNotIn('.NET Core',by_id['CVE-2026-108398']['categories'])
    def test_recategorization_keeps_dotnet_overview(self):
        entry = {'categories':['.NET Core'], 'title':'ASP.NET Core 8.0',
                 'affected':'ASP.NET Core runtime', 'summary':'Modern .NET runtime vulnerability'}
        tagged=u.recategorize_existing(entry)
        self.assertIn('.NET / ASP.NET',tagged['categories'])
        self.assertIn('.NET Core',tagged['categories'])
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
        self.assertEqual(38,len(obj['categories']))
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
    def test_github_rest_patched_version_string(self):
        advisory={
            'ghsa_id':'GHSA-abcd-2345-fghi', 'cve_id':'CVE-2026-123456',
            'type':'reviewed', 'severity':'high',
            'summary':'Vulnerable npm package parsing', 'description':'Node.js npm package',
            'published_at':'2026-10-27T00:00:00Z',
            'updated_at':'2026-10-27T01:00:00Z',
            'vulnerabilities':[{
                'package':{'ecosystem':'npm','name':'example-pkg'},
                'first_patched_version':'2.4.1',
                'vulnerable_version_range':'< 2.4.1'
            }],
            'cvss':{'score':7.8},
            'references':['https://github.com/advisories/GHSA-abcd-2345-fghi']
        }
        result=u.from_ghsa(advisory)
        self.assertIsNotNone(result)
        self.assertIn('example-pkg: 2.4.1',result['remediation'])
        self.assertIn('Node.js / npm',result['categories'])
        self.assertEqual(result['cvss'],'7.8')

    def test_github_optional_malformed_fields_do_not_abort_source(self):
        advisory={
            'ghsa_id':'GHSA-bcde-2345-fghi','type':'reviewed',
            'severity':'critical','summary':'Python package dependency',
            'description':'Python PyPI package vulnerability',
            'vulnerabilities':[{'package':{'ecosystem':'pip','name':'my-package'},
                'first_patched_version':None},'bad-field'],
            'cvss':None,'references':[]
        }
        result=u.from_ghsa(advisory)
        self.assertIn('Python / PyPI',result['categories'])
        self.assertEqual(result['severity'],'critical')

    def test_php_critical_october_baseline_is_visible_as_new(self):
        records={record['id']:record for record in u.vendor_baseline_items()}
        for cve in ('CVE-2026-109618','CVE-2026-109619'):
            self.assertIn(cve,records)
            self.assertEqual(records[cve]['severity'],'critical')
            self.assertEqual(records[cve]['published'],'2026-10-21')
            self.assertIn('PHP',records[cve]['categories'])
            self.assertTrue(records[cve]['known_exploited'])
            self.assertTrue(records[cve]['sources'])
        self.assertIn('CVE-2026-115560',records)
        self.assertIn('PHP',records['CVE-2026-115560']['categories'])

    def test_php_upstream_independent_security_feed(self):
        seen=[]
        def feed(url,source):
            self.assertEqual(source,'php_upstream')
            seen.append(parse_qs(urlparse(url).query)['sort'][0])
            return [{'ghsa_id':'GHSA-w8hw-w9fx-j79w',
                     'cve_id':'CVE-2026-109618',
                     'summary':'RCE via OOM corruption',
                     'description':'A PHP request can trigger out of memory corruption',
                     'severity':'critical','type':'reviewed',
                     'published_at':'2026-10-21T13:40:00Z',
                     'updated_at':'2026-10-27T00:00:00Z',
                     'vulnerabilities':[{
                       'package':{'ecosystem':'other','name':'php-src'},
                       'vulnerable_version_range':'< 8.4.27',
                       'first_patched_version':'8.4.27'}],
                     'cvss':{'score':9.2},'references':[]}]
        with patch.object(u,'get_json',side_effect=feed):
            results=u.php_upstream_items()
        self.assertEqual(sorted(seen),['published','updated'])
        self.assertEqual(len(results),1)
        record=u.from_php_upstream(results[0])
        self.assertEqual(record['id'],'CVE-2026-109618')
        self.assertEqual(record['published'],'2026-10-21')
        self.assertIn('PHP',record['categories'])
        self.assertEqual(record['status'],'Published security advisory from PHP upstream')
        self.assertIn('8.4.27',record['remediation'])

    def test_php_source_missing_pubdate_does_not_claim_new_today(self):
        advisory={'ghsa_id':'GHSA-ffff-gggg-aaaa',
          'severity':'high','summary':'PHP session state flaw',
          'vulnerabilities':[]}
        record=u.from_php_upstream(advisory)
        self.assertIsNotNone(record)
        self.assertEqual(record['published'],'')
        self.assertIn('PHP',record['categories'])

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
    def test_new_publications_are_prioritized_above_old_metadata_updates(self):
        today = u.NOW.date().isoformat()
        old = {f'CVE-2026-{n:06d}': {'id':f'CVE-2026-{n:06d}',
               'published':'2026-04-02','updated':today,
               'source_updated_at':today,'categories':['PHP']} for n in range(950)}
        new = {'CVE-2026-999991': {'id':'CVE-2026-999991',
               'published':today,'updated':today,
               'source_updated_at':today,'categories':['PHP']}}
        selected=u.choose_records({**old,**new},set())
        self.assertEqual(900,len(selected))
        self.assertEqual(selected[0]['id'],'CVE-2026-999991')
        self.assertNotEqual(selected[0]['published'],'2026-04-02')

    def test_nvd_fetches_new_publications_separately_from_updates(self):
        seen=[]
        def sample(url,source):
            query=parse_qs(urlparse(url).query)
            seen.append(query)
            return {'vulnerabilities':[], 'totalResults':0}
        with patch.object(u,'get_json',side_effect=sample),patch.object(u.time,'sleep'):
            u.nvd_items()
        self.assertEqual(2,len(seen))
        self.assertIn('pubStartDate',seen[0])
        self.assertIn('lastModStartDate',seen[1])

    def test_ghsa_checks_published_and_modified_advisories(self):
        seen=[]
        def sample(url,source):
            seen.append(parse_qs(urlparse(url).query))
            return []
        with patch.object(u,'get_json',side_effect=sample):
            u.ghsa_items()
        self.assertEqual({'published','updated'},{x['sort'][0] for x in seen})
        self.assertEqual({'reviewed','malware'},{x['type'][0] for x in seen})

    def test_cisa_date_added_is_not_original_published_date(self):
        result=u.from_kev({'cveID':'CVE-2026-91818',
           'vendorProject':'Microsoft','product':'Windows Server',
           'vulnerabilityName':'Windows Server vulnerability',
           'dateAdded':'2026-10-27'})
        self.assertEqual('',result['published'])
        self.assertEqual('2026-10-27',result['updated'])

    def test_redesigned_technology_browser(self):
        html=(root/'index.html').read_text(encoding='utf-8')
        js=(root/'app.js').read_text(encoding='utf-8')
        self.assertIn('id="technologySearch"',html)
        self.assertIn('id="categoryGrid"',html)
        self.assertNotIn('id="additionalTech"',html)
        self.assertNotIn('id="otherCategoryGrid"',html)
        self.assertIn('technology-redesign',html)
        self.assertIn("technologySearch').addEventListener('input',renderCategories)",js)
        self.assertIn("openTechnologyAdvisories(x.name)",js)
        self.assertIn('technology-row',js)
        self.assertIn('advisoryIDs',js)
        groups=json.loads(js.split('const technologyGroups = ',1)[1].split(';',1)[0])
        self.assertEqual(set(groups),{'microsoft','applications','infrastructure','data'})
        names=[n for group in groups.values() for n in group]
        self.assertEqual(len(names),38)
        self.assertEqual(len(set(names)),38)
        self.assertEqual(sorted(names),sorted(c['name'] for c in u.CATEGORIES))

    def test_technology_chart_switches_between_new_and_historical(self):
        html=(root/'index.html').read_text(encoding='utf-8')
        js=(root/'app.js').read_text(encoding='utf-8')
        for element in ('chartShowAll','chartModeDescription','chartNoRecords'):
            self.assertIn('id="'+element+'"',html)
        self.assertIn('data-chart-period="all"',html)
        self.assertIn('data-chart-period="published30"',html)
        self.assertIn('data-chart-period="updated7"',html)
        self.assertIn("let chartPeriod = 'all'",js)
        self.assertIn('chartRecordMatches(x)',js)
        self.assertIn('openTechnologyAdvisories(x.name,false,chartPeriod)',js)
        self.assertIn("chartShowAll').addEventListener('click'",js)
        self.assertIn("state.period=selectedPeriod",js)

    def test_new_advisory_index_has_historical_vendor_examples(self):
        records=u.vendor_baseline_items()
        for category in ('Kendo UI','NoSQL / MongoDB','Progress Telerik','Sitefinity',
                         'Sophos Firewall','VMware'):
            # Some platforms have no corresponding curated baseline record;
            # zero remains legitimate and must not imply verified safety.
            self.assertIn(category,{x['name'] for x in u.CATEGORIES})
        for category in ('Kendo UI','NoSQL / MongoDB','Progress Telerik','Sitefinity','Sophos Firewall'):
            self.assertTrue(any(category in x['categories'] for x in records),category)

    def test_whitecap_public_site_added_technology_categories(self):
        names={c['name'] for c in u.CATEGORIES}
        expected={'Angular','React / Next.js','JavaScript / TypeScript',
                  'jQuery / Bootstrap','Kendo UI','SharePoint / SharePoint Server',
                  'Microsoft Power Platform','Dynamics 365','Microsoft Fabric / Power BI',
                  'Azure AI / AI SDK','NoSQL / MongoDB','AWS','iOS / Android'}
        self.assertTrue(expected.issubset(names))
        self.assertEqual(13,len(expected))
        self.assertEqual(38,len(names))

    def test_new_product_classifier_positive_and_negative_cases(self):
        cases={
            '@angular/common': ('Angular','npm'),
            'react-server-dom-webpack': ('React / Next.js','npm'),
            'TypeScript compiler': ('JavaScript / TypeScript','npm'),
            'jquery': ('jQuery / Bootstrap','npm'),
            'Kendo UI for jQuery': ('Kendo UI',''),
            'Microsoft SharePoint Server Subscription Edition': ('SharePoint / SharePoint Server',''),
            'Microsoft Power Apps': ('Microsoft Power Platform',''),
            'Dynamics 365 CRM': ('Dynamics 365',''),
            'Microsoft Power BI': ('Microsoft Fabric / Power BI',''),
            'Azure OpenAI Service': ('Azure AI / AI SDK',''),
            'MongoDB Server': ('NoSQL / MongoDB',''),
            'AWS SDK for Python': ('AWS',''),
            'Android SDK': ('iOS / Android',''),
        }
        for name,(label,eco) in cases.items():
            with self.subTest(name=name):
                self.assertIn(label,u.classify(product=name,ecosystem=eco))
        self.assertNotIn('SharePoint / SharePoint Server',u.classify(product='Share point of sale display'))
        self.assertNotIn('NoSQL / MongoDB',u.classify(product='An unrelated SQL Server'))

    def test_source_verified_technology_advisories_are_seeded(self):
        found={x['id']:x for x in u.vendor_baseline_items()}
        expected={'CVE-2026-111753','GHSA-xqc2-xf4c-x3h3',
                  'CVE-2025-55182','CVE-2026-70266',
                  'CVE-2026-70259','CVE-2025-6725','CVE-2025-14847'}
        self.assertTrue(expected.issubset(found))
        self.assertEqual('advisory',found['GHSA-xqc2-xf4c-x3h3']['kind'])
        self.assertEqual('critical',found['GHSA-xqc2-xf4c-x3h3']['severity'])
        self.assertEqual('2026-10-14',found['GHSA-xqc2-xf4c-x3h3']['published'])
        self.assertTrue(found['CVE-2025-14847']['known_exploited'])
        for id in expected:
            self.assertGreater(len(found[id]['sources']),0)

    def test_catalog_build_preserves_ghsa_only_records(self):
        import subprocess,sys
        result=subprocess.run([sys.executable,str(root/'scripts/build_site.py')],cwd=root,
                              capture_output=True,text=True,check=True)
        payload=(root/'public'/'catalog.js').read_text(encoding='utf-8')
        data=json.loads(payload.partition(' = ')[2].strip().removesuffix(';'))
        self.assertEqual(38,len(data['categories']))
        react=next(a for a in data['advisories'] if a['id']=='GHSA-xqc2-xf4c-x3h3')
        self.assertEqual('advisory',react['kind'])

    def test_url_rejection(self):
        self.assertFalse(u.clean_url('javascript:alert(1)'))
        self.assertFalse(u.clean_url('http://example.org'))
        self.assertEqual(u.clean_url('https://nvd.nist.gov/'),'https://nvd.nist.gov/')

if __name__=='__main__':unittest.main()
