import unittest
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from build_workspace_intelligence import project
class WorkspaceProjection(unittest.TestCase):
    def test_period_dedup_and_bound(self):
        rows=[{'id':f'CVE-2026-{10000+i}','published':'2026-11-01','sources':[{'url':'https://example.test/reference','label':'Source'}],'categories':['PHP']} for i in range(65)]
        rows += [rows[0],{'id':'CVE-2026-99999','published':'2026-11-02'},{'id':'CVE-2026-99998','published':'2026-10-02'},{'id':'CVE-2026-99997','published':'invalid'}]
        data=project({'snapshotDate':'2026-11-01','advisories':rows,'coverage_limited':True})
        self.assertEqual(data['count'],65);self.assertEqual(len(data['items']),50);self.assertEqual(data['period_start'],'2026-10-03');self.assertTrue(data['coverage_limited']);self.assertEqual(data['scope'],'global')
    def test_empty(self):
        self.assertEqual(project({'snapshotDate':'2026-11-01','advisories':[]})['count'],0)
if __name__=='__main__':unittest.main()
