import unittest
from pathlib import Path

from mcp_sentinel.scanner import ConfigError, score_to_grade, scan_file

FIXTURES = Path(__file__).parent / "fixtures"


class TestScanner(unittest.TestCase):
    def test_clean_config_grades_a(self):
        report = scan_file(FIXTURES / "clean.json")
        self.assertEqual(len(report.servers), 1)
        self.assertEqual(report.overall_grade, "A")
        self.assertEqual(report.servers[0].score, 100)

    def test_risky_config_has_low_grade_and_findings(self):
        report = scan_file(FIXTURES / "risky.json")
        self.assertEqual(len(report.servers), 3)
        by_name = {s.name: s for s in report.servers}

        self.assertLess(by_name["shell-wrapper"].score, 50)
        rule_ids = {f.rule_id for f in by_name["shell-wrapper"].findings}
        self.assertIn("SHELL_INDIRECTION", rule_ids)
        self.assertIn("SHELL_METACHARACTERS", rule_ids)
        self.assertIn("INLINE_SECRET", rule_ids)

        sketchy_ids = {f.rule_id for f in by_name["sketchy-fs"].findings}
        self.assertIn("BROAD_FS_SCOPE", sketchy_ids)
        self.assertIn("POSSIBLE_TYPOSQUAT", sketchy_ids)

        floating_ids = {f.rule_id for f in by_name["floating"].findings}
        self.assertIn("LATEST_TAG", floating_ids)

        self.assertLess(report.overall_score, 75)
        self.assertIn(report.overall_grade, {"C", "D", "F"})

    def test_missing_mcp_servers_key_raises(self):
        import json
        import tempfile

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"not_mcp": True}, f)
            path = Path(f.name)
        try:
            with self.assertRaises(ConfigError):
                scan_file(path)
        finally:
            path.unlink()

    def test_score_to_grade_boundaries(self):
        self.assertEqual(score_to_grade(100), "A")
        self.assertEqual(score_to_grade(90), "A")
        self.assertEqual(score_to_grade(89), "B")
        self.assertEqual(score_to_grade(75), "B")
        self.assertEqual(score_to_grade(74), "C")
        self.assertEqual(score_to_grade(60), "C")
        self.assertEqual(score_to_grade(59), "D")
        self.assertEqual(score_to_grade(40), "D")
        self.assertEqual(score_to_grade(39), "F")
        self.assertEqual(score_to_grade(0), "F")
