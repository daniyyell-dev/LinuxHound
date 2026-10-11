import unittest

from linuxhound.compare import compare_reports
from linuxhound.synthetic import after_report, before_report, incomplete_after_report


class CompareTests(unittest.TestCase):
    def test_complete_rescan_can_show_removed_rights(self):
        result = compare_reports(before_report(), after_report())
        removed = result["paths"]["removed_under_complete_coverage"]
        self.assertTrue(any(item["pattern"] == "writable-root-job" for item in removed))
        self.assertTrue(any(item["pattern"] == "docker-group" for item in removed))
        self.assertTrue(result["configuration_changes"])
        self.assertEqual(result["paths"]["incomplete_not_a_fix"], [])

    def test_incomplete_rescan_is_not_a_fix(self):
        result = compare_reports(before_report(), incomplete_after_report())
        incomplete = result["paths"]["incomplete_not_a_fix"]
        self.assertTrue(any(item["pattern"] == "writable-root-job" for item in incomplete))
        removed_paths = result["paths"]["removed_under_complete_coverage"]
        self.assertFalse(any(item["pattern"] == "writable-root-job" for item in removed_paths))
        removed_edges = result["edges"]["removed_under_complete_coverage"]
        self.assertTrue(any(item["type"] == "CanWrite" for item in removed_edges))
        self.assertTrue(any(change["domain"] == "systemd" for change in result["coverage_changes"]))


if __name__ == "__main__":
    unittest.main()
