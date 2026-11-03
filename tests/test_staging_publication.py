import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'staging/scripts'))
from synthetic_intelligence import f
from test_feed_snapshot import MemoryStore
spec=importlib.util.spec_from_file_location('staging_publisher',Path(__file__).resolve().parents[1]/'staging/scripts/publish-synthetic.py')
p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class StagingPublicationTests(unittest.TestCase):
 def test_same_atomic_protocol_and_history_survive_republication(self):
  store=MemoryStore();first=p.publish(store);files=f.load_files(store,f.load_manifest(store,first['manifest']))
  second=p.publish(store);self.assertEqual(second['previous'],first['manifest'])
  self.assertEqual(files['data/threat-ip-history.json'],f.load_files(store,f.load_manifest(store,second['manifest']))['data/threat-ip-history.json'])
  self.assertIn('CVE-2099-12345',files['data.js'].decode())
  with tempfile.TemporaryDirectory() as directory:
   result=f.collect(store,Path(directory),lambda script:type('Result',(),{'returncode':0})())
   self.assertFalse(result['degraded'])
 def test_failed_promotion_keeps_previous_version(self):
  store=MemoryStore();first=p.publish(store);store.fail='pointer'
  with self.assertRaises(OSError):p.publish(store)
  self.assertEqual(f.pointer(store)[0],first)
