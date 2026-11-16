"""Configuration analysis: committed secrets, tracing, LangGraph deployments, dependencies."""

import textwrap
import unittest

from ai_threat_model.config_analyzer import analyze_config
from ai_threat_model.models import ComponentKind, Severity
from tests.helpers import fake_openai_key, findings_with, rule_ids


def analyze(path: str, text: str, *, ignored: bool = False):
    return analyze_config(path, textwrap.dedent(text).lstrip("\n"), env_ignored_by_git=ignored)


class SecretTests(unittest.TestCase):
    def test_token_in_env_file_is_high_and_masked(self) -> None:
        key = fake_openai_key()
        result = analyze(".env", f"OPENAI_API_KEY={key}\n")
        [finding] = findings_with(result.findings, "AITM-DATA-001")
        self.assertIs(finding.severity, Severity.HIGH)
        self.assertNotIn(key, finding.description)
        self.assertNotIn(key, finding.location.snippet)

    def test_key_value_secret_severity_depends_on_gitignore(self) -> None:
        committed = analyze(".env", "DB_PASSWORD=acme-db-pass-2024\n", ignored=False)
        ignored = analyze(".env", "DB_PASSWORD=acme-db-pass-2024\n", ignored=True)
        self.assertIs(findings_with(committed.findings, "AITM-DATA-001")[0].severity, Severity.HIGH)
        self.assertIn(".gitignore", committed.findings[0].description)
        self.assertIs(findings_with(ignored.findings, "AITM-DATA-001")[0].severity, Severity.LOW)

    def test_yaml_secret_is_reported(self) -> None:
        result = analyze("config/settings.yaml", 'database:\n  password: "acme-db-pass-2024"\n')
        self.assertIn("AITM-DATA-001", rule_ids(result.findings))

    def test_example_files_and_placeholders_are_skipped(self) -> None:
        self.assertEqual(analyze(".env.example", "DB_PASSWORD=acme-db-pass-2024\n").findings, [])
        self.assertEqual(analyze(".env", "OPENAI_API_KEY=<your-key-here>\n").findings, [])
        self.assertEqual(analyze(".env", "# OPENAI_API_KEY=acme-db-pass-2024\n").findings, [])

    def test_example_files_still_report_real_token_formats(self) -> None:
        result = analyze(".env.example", f"OPENAI_API_KEY={fake_openai_key()}\n")
        self.assertIn("AITM-DATA-001", rule_ids(result.findings))


class TracingTests(unittest.TestCase):
    def test_enabled_tracing_adds_observability_component(self) -> None:
        result = analyze(".env", "LANGSMITH_TRACING=true\n")
        self.assertIn("AITM-DATA-004", rule_ids(result.findings))
        [component] = result.components
        self.assertIs(component.kind, ComponentKind.OBSERVABILITY)

    def test_disabled_tracing_is_ignored(self) -> None:
        result = analyze(".env", "LANGCHAIN_TRACING_V2=false\n")
        self.assertEqual((result.findings, result.components), ([], []))


class DependencyTests(unittest.TestCase):
    def test_unpinned_requirements(self) -> None:
        result = analyze("requirements.txt", """
            langchain>=0.3
            langgraph
            langchain-ollama==0.3.3
            fastapi
        """)
        [finding] = findings_with(result.findings, "AITM-SUP-001")
        self.assertIn("langchain", finding.description)
        self.assertIn("langgraph", finding.description)
        self.assertNotIn("langchain-ollama", finding.description)
        self.assertNotIn("fastapi", finding.description)
        self.assertEqual(finding.location.line, 1)
        self.assertEqual([location.line for location in finding.related], [2])

    def test_pinned_requirements_are_clean(self) -> None:
        self.assertEqual(analyze("requirements.txt", "langchain==0.3.25\n-r base.txt\n").findings, [])

    def test_pyproject_dependencies(self) -> None:
        result = analyze("pyproject.toml", """
            [project]
            name = "demo"
            dependencies = ["langchain-core>=0.3", "langgraph==0.4.8"]
        """)
        [finding] = findings_with(result.findings, "AITM-SUP-001")
        self.assertIn("langchain-core", finding.description)
        self.assertNotIn("langgraph", finding.description)


class LangGraphConfigTests(unittest.TestCase):
    def test_graphs_become_entry_points(self) -> None:
        result = analyze("langgraph.json", """
            {
              "dependencies": ["."],
              "graphs": {"support": "./app/agent.py:build_agent"}
            }
        """)
        [entry] = result.components
        self.assertIs(entry.kind, ComponentKind.ENTRY_POINT)
        self.assertEqual(entry.name, "LangGraph API graph 'support'")
        self.assertEqual(entry.location.line, 3)
        self.assertEqual(entry.attributes["auth"], "platform default")

    def test_invalid_json_does_not_crash(self) -> None:
        with self.assertLogs("ai_threat_model.config_analyzer", level="WARNING"):
            result = analyze("langgraph.json", "{not json")
        self.assertEqual(result.components, [])


if __name__ == "__main__":
    unittest.main()
