import unittest
from scripts.collect_sql_updates import parse_microsoft_sql_updates

class SqlServicingTests(unittest.TestCase):
    def test_cu_version_and_kb(self):
        html = ('<h2>SQL Server 2022</h2><table>'
                '<tr><td>16.0.4305.5</td><td>CU27 + GDR</td><td>KB5126934</td></tr>'
                '<tr><td>16.0.1210.3</td><td>GDR</td><td>KB5128493</td></tr></table>')
        records = parse_microsoft_sql_updates(html)
        self.assertTrue(any(x['kb']=='KB5126934' for x in records))
        self.assertTrue(any(x['kb']=='KB5128493' for x in records))

    def test_unknown_versions_are_ignored(self):
        html = '<h2>SQL Server 2022</h2><table><tr><td>99.0.1.1</td><td>CU27</td><td>KB5126934</td></tr></table>'
        self.assertEqual(parse_microsoft_sql_updates(html), [])
