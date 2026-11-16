"""Command-line interface: exit codes, report output, and the optional Ollama narrative."""

import contextlib
import io
import unittest
from unittest import mock

from ai_threat_model import ollama_client
from ai_threat_model.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, main
from tests.helpers import EXAMPLES_DIR, StubOllama, TempDirTestCase, unused_local_port
from tests.test_logging_setup import reset_package_logger

VULNERABLE = str(EXAMPLES_DIR / "vulnerable_support_agent")


class CliTests(TempDirTestCase):
    def tearDown(self) -> None:
        reset_package_logger()
        super().tearDown()

    def run_cli(self, *args: str) -> tuple[int, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main([*args, "--log-level", "ERROR"])
        return code, stdout.getvalue() + stderr.getvalue()

    def test_scan_writes_reports(self) -> None:
        out = self.tmp / "report"
        code, output = self.run_cli(VULNERABLE, "-o", str(out), "-f", "md", "json", "sarif")
        self.assertEqual(code, EXIT_OK)
        self.assertTrue((out / "threat-model.md").is_file())
        self.assertTrue((out / "threat-model.json").is_file())
        self.assertTrue((out / "threat-model.sarif").is_file())
        self.assertIn("Findings:", output)

    def test_fail_on_threshold(self) -> None:
        code, _ = self.run_cli(VULNERABLE, "-o", str(self.tmp), "--fail-on", "high")
        self.assertEqual(code, EXIT_FINDINGS)

    def test_cache_dir_reuses_results_on_second_run(self) -> None:
        args = (VULNERABLE, "-o", str(self.tmp / "out"), "--cache-dir", str(self.tmp / "cache"))
        _, first = self.run_cli(*args)
        code, second = self.run_cli(*args)
        self.assertEqual(code, EXIT_OK)
        self.assertIn("Cache: reused 0, analyzed 7; saved", first)
        self.assertIn("Cache: reused 7, analyzed 0; saved", second)

    def test_rebuild_cache_requires_cache_dir(self) -> None:
        code, _ = self.run_cli(VULNERABLE, "-o", str(self.tmp), "--rebuild-cache")
        self.assertEqual(code, EXIT_ERROR)

    def test_missing_path_is_an_error(self) -> None:
        code, _ = self.run_cli(str(self.tmp / "missing"), "-o", str(self.tmp / "out"))
        self.assertEqual(code, EXIT_ERROR)

    def test_remote_llm_url_is_rejected_before_scanning(self) -> None:
        code, _ = self.run_cli(VULNERABLE, "-o", str(self.tmp), "--llm", "--ollama-url", "http://10.1.2.3:11434")
        self.assertEqual(code, EXIT_ERROR)
        self.assertFalse((self.tmp / "threat-model.md").exists())

    def test_narrative_from_stub_ollama_is_embedded(self) -> None:
        with StubOllama([(200, {"response": "Top risk: the ShellTool."})]) as stub:
            code, _ = self.run_cli(VULNERABLE, "-o", str(self.tmp), "--llm", "--ollama-url", stub.url)
        self.assertEqual(code, EXIT_OK)
        report = (self.tmp / "threat-model.md").read_text(encoding="utf-8")
        self.assertIn("AI-assisted analysis", report)
        self.assertIn("Top risk: the ShellTool.", report)
        self.assertEqual(stub.requests[0]["body"]["model"], "qwen2.5-coder:7b")

    @mock.patch.object(ollama_client, "RETRY_BACKOFF_SECONDS", 0)
    def test_unreachable_ollama_degrades_gracefully(self) -> None:
        url = f"http://127.0.0.1:{unused_local_port()}"
        code, _ = self.run_cli(VULNERABLE, "-o", str(self.tmp), "-f", "json", "--llm", "--ollama-url", url,
                               "--ollama-retries", "0", "--ollama-timeout", "2")
        self.assertEqual(code, EXIT_OK)
        report = (self.tmp / "threat-model.json").read_text(encoding="utf-8")
        self.assertIn("AI narrative skipped", report)

    def test_out_of_range_retries_is_a_usage_error(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            main([VULNERABLE, "--ollama-retries", "9"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
