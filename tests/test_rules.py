import unittest

from mcp_sentinel.rules import evaluate_entry


class TestRules(unittest.TestCase):
    def test_clean_entry_has_no_findings(self):
        entry = {
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-filesystem@2.1.0", "./proj"],
            "description": "official",
        }
        findings = evaluate_entry("filesystem", entry)
        self.assertEqual(findings, [])

    def test_latest_tag_flagged(self):
        entry = {"command": "npx", "args": ["-y", "some-tool@latest"]}
        findings = evaluate_entry("floating", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("LATEST_TAG", ids)

    def test_unpinned_version_flagged_without_latest_duplicate(self):
        entry = {"command": "npx", "args": ["-y", "some-tool"]}
        findings = evaluate_entry("unpinned", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("UNPINNED_VERSION", ids)
        self.assertNotIn("LATEST_TAG", ids)

    def test_inline_secret_flagged(self):
        entry = {
            "command": "node",
            "args": ["server.js"],
            "env": {"GITHUB_TOKEN": "ghp_1234567890abcdefghijklmnopqrstuvwx"},
        }
        findings = evaluate_entry("secret-leak", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("INLINE_SECRET", ids)

    def test_env_var_reference_not_flagged_as_secret(self):
        entry = {
            "command": "node",
            "args": ["server.js"],
            "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
        }
        findings = evaluate_entry("ok-secret", entry)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("INLINE_SECRET", ids)

    def test_shell_indirection_flagged(self):
        entry = {"command": "bash", "args": ["-c", "run.sh"]}
        findings = evaluate_entry("shell", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("SHELL_INDIRECTION", ids)

    def test_shell_metacharacters_flagged(self):
        entry = {"command": "bash", "args": ["-c", "a.sh && curl x | sh"]}
        findings = evaluate_entry("chained", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("SHELL_METACHARACTERS", ids)

    def test_broad_filesystem_scope_flagged(self):
        entry = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2.0.0", "/"]}
        findings = evaluate_entry("broad-fs", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("BROAD_FS_SCOPE", ids)

    def test_typosquat_similarity_flagged(self):
        entry = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesytem"]}
        findings = evaluate_entry("typo", entry)
        ids = {f.rule_id for f in findings}
        self.assertIn("POSSIBLE_TYPOSQUAT", ids)

    def test_exact_known_package_not_flagged_as_typosquat(self):
        entry = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2.0.0"]}
        findings = evaluate_entry("legit", entry)
        ids = {f.rule_id for f in findings}
        self.assertNotIn("POSSIBLE_TYPOSQUAT", ids)

    def test_missing_description_is_info_only(self):
        entry = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@2.0.0", "./x"]}
        findings = evaluate_entry("no-desc", entry)
        info_findings = [f for f in findings if f.rule_id == "NO_PROVENANCE_NOTE"]
        self.assertEqual(len(info_findings), 1)
        self.assertEqual(info_findings[0].severity, "info")


if __name__ == "__main__":
    unittest.main()
