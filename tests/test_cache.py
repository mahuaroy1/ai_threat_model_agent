"""Incremental analysis: cached summaries and results are reused only while still valid."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from ai_threat_model.cache import CACHE_SUFFIX, cache_path, load_cache
from ai_threat_model.engine import ScanOptions, scan
from ai_threat_model.models import ThreatModel
from tests.helpers import TempDirTestCase, findings_with, write_project

SAFE_HELPER = """
    def run_command(target):
        return "would ping " + target
"""

SHELL_HELPER = """
    import subprocess

    def run_command(target):
        return subprocess.check_output("ping " + target, shell=True)
"""

TOOLS = '''
    from langchain_core.tools import tool
    from helpers.shell import run_command

    @tool
    def diagnose(host: str) -> str:
        """Diagnose a host."""
        return run_command(host)
'''

UNRELATED = """
    from langchain_ollama import ChatOllama

    llm = ChatOllama(model="qwen2.5-coder:7b")
"""


def fingerprint(model: ThreatModel) -> tuple:
    """Everything a report shows, excluding the timestamp."""
    return (
        sorted((f.rule_id, f.location.file, f.location.line, f.severity.value, f.description,
                tuple(str(r) for r in f.related)) for f in model.findings),
        sorted(c.id for c in model.components),
        sorted((d.source_id, d.target_id, d.label) for d in model.data_flows),
        sorted(model.scanned_files),
        model.frameworks,
    )


class IncrementalScanTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.project = self.tmp / "project"
        self.cache_dir = self.tmp / "cache"
        self.options = ScanOptions(cache_dir=self.cache_dir)
        write_project(self.project, {
            "helpers/__init__.py": "",
            "helpers/shell.py": SAFE_HELPER,
            "tools.py": TOOLS,
            "models.py": UNRELATED,
            "config/settings.yaml": "log_level: info\n",
        })

    def assert_matches_full_scan(self, incremental: ThreatModel) -> None:
        self.assertEqual(fingerprint(incremental), fingerprint(scan(self.project).model))

    def test_first_scan_analyzes_everything_and_saves_cache(self) -> None:
        result = scan(self.project, self.options)
        self.assertFalse(result.stats.cache_loaded)
        self.assertTrue(result.stats.cache_saved)
        self.assertEqual((result.stats.reused, result.stats.analyzed), (0, 5))
        self.assertTrue(cache_path(self.cache_dir, self.project.resolve()).is_file())

    def test_unchanged_project_is_fully_reused_with_identical_results(self) -> None:
        first = scan(self.project, self.options)
        second = scan(self.project, self.options)
        self.assertTrue(second.stats.cache_loaded)
        self.assertEqual((second.stats.reused, second.stats.analyzed), (5, 0))
        self.assertEqual(fingerprint(second.model), fingerprint(first.model))

    def test_changed_callee_reanalyzes_dependents_only(self) -> None:
        scan(self.project, self.options)
        write_project(self.project, {"helpers/shell.py": SHELL_HELPER})

        result = scan(self.project, self.options)

        # shell.py changed and tools.py depends on it; models.py, __init__.py and the YAML are reused.
        self.assertEqual((result.stats.reused, result.stats.analyzed), (3, 2))
        [finding] = findings_with(result.model.findings, "AITM-TOOL-003")
        self.assertEqual(finding.location.file, "tools.py")
        self.assert_matches_full_scan(result.model)

    def test_removed_sink_does_not_leave_stale_findings(self) -> None:
        write_project(self.project, {"helpers/shell.py": SHELL_HELPER})
        self.assertTrue(findings_with(scan(self.project, self.options).model.findings, "AITM-TOOL-003"))

        write_project(self.project, {"helpers/shell.py": SAFE_HELPER})
        result = scan(self.project, self.options)

        self.assertEqual(findings_with(result.model.findings, "AITM-TOOL-003"), [])
        self.assert_matches_full_scan(result.model)

    def test_new_function_rebuilds_all_summaries(self) -> None:
        scan(self.project, self.options)
        write_project(self.project, {"models.py": textwrap.dedent(UNRELATED) + "\ndef extra(value):\n    return value\n"})

        result = scan(self.project, self.options)

        # Import resolution may change, so every Python file is re-analyzed; the YAML is still reused.
        self.assertEqual((result.stats.reused, result.stats.analyzed), (1, 4))
        self.assert_matches_full_scan(result.model)

    def test_deleted_file_is_dropped(self) -> None:
        scan(self.project, self.options)
        (self.project / "models.py").unlink()

        result = scan(self.project, self.options)

        self.assertNotIn("models.py", result.model.scanned_files)
        self.assert_matches_full_scan(result.model)

    def test_gitignore_change_reanalyzes_env_files(self) -> None:
        write_project(self.project, {".env": "DB_PASSWORD=acme-db-pass-2024\n"})
        first = scan(self.project, self.options)
        [secret] = findings_with(first.model.findings, "AITM-DATA-001")
        self.assertEqual(secret.severity.value, "high")

        write_project(self.project, {".gitignore": ".env\n"})
        result = scan(self.project, self.options)

        [secret] = findings_with(result.model.findings, "AITM-DATA-001")
        self.assertEqual(secret.severity.value, "low")
        self.assert_matches_full_scan(result.model)

    def test_rebuild_cache_ignores_existing_cache(self) -> None:
        scan(self.project, self.options)
        result = scan(self.project, ScanOptions(cache_dir=self.cache_dir, rebuild_cache=True))
        self.assertFalse(result.stats.cache_loaded)
        self.assertEqual(result.stats.reused, 0)
        self.assertTrue(result.stats.cache_saved)

    def test_cache_inside_project_is_not_scanned(self) -> None:
        options = ScanOptions(cache_dir=self.project / ".aitm")
        scan(self.project, options)
        result = scan(self.project, options)
        self.assertFalse(any(path.endswith(CACHE_SUFFIX) for path in result.model.scanned_files))
        self.assertEqual(result.stats.analyzed, 0)


class CacheRobustnessTests(TempDirTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.project = write_project(self.tmp / "project", {"tools.py": TOOLS, "helpers/shell.py": SHELL_HELPER})
        self.cache_dir = self.tmp / "cache"
        self.options = ScanOptions(cache_dir=self.cache_dir)
        self.expected = fingerprint(scan(self.project, self.options).model)
        self.file = cache_path(self.cache_dir, self.project.resolve())

    def rescan_after(self, content: str) -> None:
        self.file.write_text(content, encoding="utf-8")
        with self.assertLogs("ai_threat_model", level="INFO"):
            result = scan(self.project, self.options)
        self.assertFalse(result.stats.cache_loaded)
        self.assertEqual(result.stats.reused, 0)
        self.assertEqual(fingerprint(result.model), self.expected)
        self.assertIsNotNone(load_cache(self.file, self.project.resolve()), "a valid cache is rewritten")

    def test_corrupt_json_falls_back_to_full_scan(self) -> None:
        self.rescan_after("{not json")

    def test_wrong_types_fall_back_to_full_scan(self) -> None:
        data = json.loads(self.file.read_text(encoding="utf-8"))
        first = next(iter(data["files"].values()))
        first["findings"] = "not a list"
        self.rescan_after(json.dumps(data))

    def test_invalid_enum_falls_back_to_full_scan(self) -> None:
        data = json.loads(self.file.read_text(encoding="utf-8"))
        for entry in data["files"].values():
            for finding in entry["findings"]:
                finding["severity"] = "catastrophic"
        self.rescan_after(json.dumps(data))

    def test_other_tool_version_is_ignored(self) -> None:
        data = json.loads(self.file.read_text(encoding="utf-8"))
        data["tool_version"] = "0.0.0-other"
        self.rescan_after(json.dumps(data))

    def test_other_project_root_is_ignored(self) -> None:
        data = json.loads(self.file.read_text(encoding="utf-8"))
        data["project_root"] = str(Path(self.tmp, "elsewhere"))
        self.rescan_after(json.dumps(data))

    def test_unwritable_cache_location_does_not_fail_scan(self) -> None:
        blocker = self.tmp / "blocker"
        blocker.write_text("a file, not a directory", encoding="utf-8")
        with self.assertLogs("ai_threat_model", level="WARNING"):
            result = scan(self.project, ScanOptions(cache_dir=blocker / "cache"))
        self.assertFalse(result.stats.cache_saved)
        self.assertEqual(fingerprint(result.model), self.expected)
