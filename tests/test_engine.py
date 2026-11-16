"""End-to-end scans of the example projects and engine-level robustness."""

import json
import unittest

from ai_threat_model.engine import ScanOptions, build_threat_model
from ai_threat_model.errors import ScanError
from ai_threat_model.models import Severity
from ai_threat_model.reporting import render_json
from tests.helpers import EXAMPLES_DIR, TempDirTestCase, findings_with, rule_ids, write_project

VULNERABLE = EXAMPLES_DIR / "vulnerable_support_agent"
SECURE = EXAMPLES_DIR / "secure_support_agent"


class VulnerableExampleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.model = build_threat_model(VULNERABLE)

    def test_expected_rules_fire(self) -> None:
        expected = {
            "AITM-TOOL-001", "AITM-TOOL-003", "AITM-TOOL-005", "AITM-PI-001", "AITM-PI-003",
            "AITM-OUT-001", "AITM-OUT-002", "AITM-AUTH-001", "AITM-DATA-001", "AITM-DATA-002",
            "AITM-DATA-003", "AITM-DATA-004", "AITM-DATA-005", "AITM-SUP-001",
        }
        self.assertLessEqual(expected, rule_ids(self.model.findings))

    def test_frameworks_and_boundaries(self) -> None:
        self.assertEqual(self.model.frameworks, ["LangChain", "LangGraph"])
        names = {boundary.name for boundary in self.model.trust_boundaries}
        self.assertLessEqual({
            "Users to application", "Application to local model runtime", "External content to model context",
            "Model decisions to tool execution", "Application to observability vendor",
        }, names)
        self.assertNotIn("Application to hosted model provider", names)

    def test_indirect_injection_is_high(self) -> None:
        [finding] = findings_with(self.model.findings, "AITM-PI-003")
        self.assertIs(finding.severity, Severity.HIGH)

    def test_both_http_routes_lack_auth(self) -> None:
        self.assertEqual(len(findings_with(self.model.findings, "AITM-AUTH-001")), 2)

    def test_interprocedural_shell_finding_points_to_helper(self) -> None:
        shell_findings = [
            f for f in findings_with(self.model.findings, "AITM-TOOL-003")
            if any(location.file == "app/system_utils.py" for location in f.related)
        ]
        self.assertEqual(len(shell_findings), 1)
        self.assertEqual(shell_findings[0].location.file, "app/agent.py")

    def test_secrets_never_appear_in_report(self) -> None:
        report = render_json(self.model)
        for secret in ("acme-support-7d41c9e2", "acme-db-pass-2024"):
            self.assertNotIn(secret, report)
        self.assertIn("[REDACTED]", report)

    def test_findings_are_unique_per_rule_and_line(self) -> None:
        keys = [(f.rule_id, f.location.file, f.location.line) for f in self.model.findings]
        self.assertEqual(len(keys), len(set(keys)))


class SecureExampleTests(unittest.TestCase):
    def test_no_medium_or_higher_findings(self) -> None:
        model = build_threat_model(SECURE)
        serious = [f for f in model.findings if f.severity.rank >= Severity.MEDIUM.rank]
        self.assertEqual(serious, [], [f"{f.rule_id} {f.location}" for f in serious])


class RobustnessTests(TempDirTestCase):
    def test_unparseable_file_is_recorded_and_scan_continues(self) -> None:
        write_project(self.tmp, {
            "broken.py": "def oops(:\n",
            "agent.py": "from langchain_community.tools import ShellTool\ntools = [ShellTool()]\n",
        })
        model = build_threat_model(self.tmp)
        self.assertIn("AITM-TOOL-001", rule_ids(model.findings))
        self.assertTrue(any("broken.py" in error for error in model.errors))
        self.assertNotIn("broken.py", model.scanned_files)

    def test_non_directory_root_raises(self) -> None:
        target = self.tmp / "file.py"
        target.write_text("x = 1\n", encoding="utf-8")
        with self.assertRaises(ScanError):
            build_threat_model(target)

    def test_project_without_framework_warns(self) -> None:
        write_project(self.tmp, {"main.py": "print('hello')\n"})
        model = build_threat_model(self.tmp)
        self.assertTrue(any("No LangChain or LangGraph" in error for error in model.errors))
        self.assertEqual(model.findings, [])

    def test_gitignored_env_lowers_severity(self) -> None:
        write_project(self.tmp, {".gitignore": ".env\n", ".env": "DB_PASSWORD=acme-db-pass-2024\n"})
        [finding] = build_threat_model(self.tmp).findings
        self.assertIs(finding.severity, Severity.LOW)

    def test_scan_options_limit_files(self) -> None:
        write_project(self.tmp, {f"m{i}.py": "x = 1\n" for i in range(4)})
        model = build_threat_model(self.tmp, ScanOptions(max_files=2))
        self.assertEqual(len(model.scanned_files), 2)

    def test_json_report_is_valid(self) -> None:
        write_project(self.tmp, {"agent.py": "from langchain_community.tools import ShellTool\nt = ShellTool()\n"})
        data = json.loads(render_json(build_threat_model(self.tmp)))
        self.assertEqual(data["tool"]["name"], "ai-threat-model")
        self.assertEqual(sum(data["severity_counts"].values()), len(data["findings"]))
        self.assertIn(data["findings"][0]["severity"], {s.value for s in Severity})
        self.assertTrue(all("id" in component for component in data["components"]))


if __name__ == "__main__":
    unittest.main()
