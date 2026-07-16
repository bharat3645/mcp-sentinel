import contextlib
import io
import unittest
from pathlib import Path

from mcp_sentinel.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


class TestCli(unittest.TestCase):
    def test_scan_clean_exits_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(["scan", str(FIXTURES / "clean.json")])
        self.assertEqual(code, 0)
        self.assertIn("grade A", buf.getvalue())

    def test_scan_fail_under_trips_on_risky_config(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                ["scan", str(FIXTURES / "risky.json"), "--fail-under", "70"]
            )
        self.assertEqual(code, 1)

    def test_scan_missing_file_exits_nonzero(self):
        buf, errbuf = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(errbuf):
            code = main(["scan", str(FIXTURES / "does-not-exist.json")])
        self.assertEqual(code, 2)

    def test_scan_no_paths_and_no_auto_exits_nonzero(self):
        errbuf = io.StringIO()
        with contextlib.redirect_stderr(errbuf):
            code = main(["scan"])
        self.assertEqual(code, 2)
