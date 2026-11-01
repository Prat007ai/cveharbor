import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('monitor_health',Path(__file__).resolve().parents[1]/'scripts/check_product_monitor_health.py')
health=importlib.util.module_from_spec(spec);spec.loader.exec_module(health)
class MonitorHealth(unittest.TestCase):
    def test_stopped_scheduler_is_detected_independently_of_smtp(self):
        self.assertTrue(health.assess({'last_run':1},20_000_000))
    def test_healthy_empty_queue_does_not_alert(self):
        self.assertEqual(health.assess({'last_run':20_000_000},20_000_001),[])
    def test_backlog_source_and_ambiguous_submission_are_actionable(self):
        self.assertEqual(len(health.assess({'last_run':300_000_000,'stale_sources':1,'oldest_pending':1,'unknown_submissions':1},300_000_001)),3)
    def test_failure_rate_needs_a_meaningful_sample(self):
        self.assertEqual(health.assess({'last_run':20,'recent_messages':2,'recent_failures':2},21),[])
        self.assertTrue(health.assess({'last_run':20,'recent_messages':5,'recent_failures':1},21))
