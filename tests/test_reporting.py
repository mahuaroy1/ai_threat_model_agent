"""Report rendering (Markdown, JSON, SARIF) and atomic writing."""

import json
import unittest

from ai_threat_model.errors import ReportError
from ai_threat_model.models import Component, ComponentKind, DataFlow, Location, Severity, ThreatModel, TrustBoundary
from ai_threat_model.reporting import render_json, render_markdown, render_sarif, write_reports
from ai_threat_model.rules import make_finding
from tests.helpers import TempDirTestCase


def sample_model() -> ThreatModel:
    entry = Component(ComponentKind.ENTRY_POINT, "POST /chat", Location("app/main.py", 20), "chat",
                      {"interface": "HTTP", "auth": "not detected"})
    llm = Component(ComponentKind.MODEL, "qwen2.5-coder:7b", Location("app/agent.py", 5), "ChatOllama",
                    {"provider": "ollama", "local": "yes"})
    model = ThreatModel(
        project_root="/work/demo", generated_at="2025-01-01T00:00:00+00:00",
        scanned_files=["app/main.py", "app/agent.py"], frameworks=["LangChain"], components=[entry, llm],
    )
    model.findings = [
        make_finding("AITM-OUT-002", Location("app/main.py", 25, "return HTMLResponse(f'<b>{a}</b>') | x"),
                     "Model output is rendered as <script> HTML.", related=[Location("app/agent.py", 5)]),
        make_finding("AITM-SUP-001", Location("requirements.txt", 1), "Unpinned AI dependencies: langchain."),
        make_finding("AITM-DATA-004", Location(".env", 2), "Tracing enabled.", severity=Severity.INFO),
    ]
    model.trust_boundaries = [TrustBoundary("TB-1", "Users to application", "External users", "Application",
                                            "All content is attacker-controllable.", [entry.id])]
    model.data_flows = [DataFlow(entry.id, llm.id, "user input", "TB-1")]
    return model


class MarkdownTests(unittest.TestCase):
    def test_contains_sections_and_escapes_untrusted_text(self) -> None:
        report = render_markdown(sample_model())
        for heading in ("# AI Threat Model", "## Summary", "## Architecture", "## Trust boundaries"):
            self.assertIn(heading, report)
        self.assertIn("```mermaid", report)
        self.assertIn("-->", report)
        self.assertNotIn("<script>", report)
        self.assertIn("&lt;script&gt;", report)
        self.assertIn("\\|", report)  # pipe in a snippet must not break the table/cell
        self.assertIn("app/main.py:25", report)

    def test_narrative_section_only_when_present(self) -> None:
        model = sample_model()
        self.assertNotIn("AI-assisted analysis", render_markdown(model))
        model.llm_narrative, model.llm_model = "Summary text", "qwen2.5-coder:7b"
        report = render_markdown(model)
        self.assertIn("AI-assisted analysis", report)
        self.assertIn("not a scanner finding or validation", report)
        self.assertIn("Summary text", report)

    def test_mermaid_labels_are_sanitized(self) -> None:
        model = sample_model()
        model.components[0].name = 'evil"]; click N0 "javascript:alert(1)'
        diagram = render_markdown(model).split("```mermaid", 1)[1].split("```", 1)[0]
        self.assertNotIn('evil"]', diagram)
        self.assertNotIn(";", diagram)


class JsonAndSarifTests(unittest.TestCase):
    def test_json_serializes_enums_and_ids(self) -> None:
        data = json.loads(render_json(sample_model()))
        self.assertEqual(data["findings"][0]["severity"], "high")
        self.assertEqual(data["components"][0]["kind"], "entry_point")
        self.assertIn("id", data["components"][0])
        self.assertEqual(data["severity_counts"]["info"], 1)

    def test_sarif_structure_and_levels(self) -> None:
        sarif = json.loads(render_sarif(sample_model()))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
        self.assertEqual(rule_ids, sorted({"AITM-OUT-002", "AITM-SUP-001", "AITM-DATA-004"}))
        levels = {result["ruleId"]: result["level"] for result in run["results"]}
        self.assertEqual(levels, {"AITM-OUT-002": "error", "AITM-SUP-001": "note", "AITM-DATA-004": "note"})
        first = run["results"][0]
        self.assertEqual(first["locations"][0]["physicalLocation"]["region"]["startLine"], 25)
        self.assertEqual(len(first["relatedLocations"]), 1)
        for result in run["results"]:
            self.assertEqual(rule_ids[result["ruleIndex"]], result["ruleId"])


class WriteReportsTests(TempDirTestCase):
    def test_writes_requested_formats_without_temp_files(self) -> None:
        output = self.tmp / "out"
        written = write_reports(sample_model(), output, ["md", "json", "sarif", "md"])
        self.assertEqual([p.name for p in written], ["threat-model.md", "threat-model.json", "threat-model.sarif"])
        self.assertEqual(sorted(p.name for p in output.iterdir()), sorted(p.name for p in written))
        json.loads((output / "threat-model.json").read_text(encoding="utf-8"))

    def test_unknown_format_raises(self) -> None:
        with self.assertRaises(ReportError):
            write_reports(sample_model(), self.tmp, ["pdf"])

    def test_unwritable_output_dir_raises(self) -> None:
        blocker = self.tmp / "file"
        blocker.write_text("x", encoding="utf-8")
        with self.assertRaises(ReportError):
            write_reports(sample_model(), blocker / "sub", ["md"])


if __name__ == "__main__":
    unittest.main()
