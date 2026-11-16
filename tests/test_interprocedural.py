"""Interprocedural analysis: taint followed through helper functions and across files."""

from ai_threat_model.engine import build_threat_model
from ai_threat_model.models import ComponentKind, Severity
from tests.helpers import TempDirTestCase, findings_with, rule_ids, write_project

# Indented like the code blocks below so the concatenation dedents cleanly.
TOOL_HEADER = """
            import os
            from langchain_core.tools import tool
"""


class CrossFileTests(TempDirTestCase):
    def test_tool_argument_reaches_sink_in_another_module(self) -> None:
        write_project(self.tmp, {
            "helpers/__init__.py": "",
            "helpers/shell.py": """
                import subprocess

                def run_command(target):
                    return subprocess.check_output("ping " + target, shell=True)
            """,
            "tools.py": '''
                from langchain_core.tools import tool
                from helpers.shell import run_command

                @tool
                def diagnose(host: str) -> str:
                    """Diagnose a host."""
                    return run_command(host)
            ''',
        })
        model = build_threat_model(self.tmp)

        [finding] = findings_with(model.findings, "AITM-TOOL-003")
        self.assertEqual(finding.location.file, "tools.py")
        self.assertIs(finding.severity, Severity.CRITICAL)
        self.assertIn("run_command()", finding.description)
        self.assertIn("helpers/shell.py", {location.file for location in finding.related})
        tool = next(c for c in model.components if c.kind is ComponentKind.TOOL)
        self.assertIn("command execution", tool.attributes["capabilities"])

    def test_relative_import_is_resolved(self) -> None:
        write_project(self.tmp, {
            "pkg/__init__.py": "",
            "pkg/ops.py": """
                import os

                def wipe(path):
                    os.remove(path)
            """,
            "pkg/tools.py": '''
                from langchain_core.tools import tool
                from .ops import wipe

                @tool
                def cleanup(path: str) -> str:
                    """Delete a file."""
                    wipe(path)
                    return "ok"
            ''',
        })
        model = build_threat_model(self.tmp)
        self.assertIn("AITM-TOOL-003", rule_ids(model.findings))


class ChainTests(TempDirTestCase):
    def test_two_level_call_chain(self) -> None:
        write_project(self.tmp, {"agent_tools.py": TOOL_HEADER + '''
            def execute(command):
                os.system(command)

            def prepare(value):
                execute("echo " + value)

            @tool
            def echo(text: str) -> str:
                """Echo text."""
                prepare(text)
                return text
        '''})
        model = build_threat_model(self.tmp)
        [finding] = findings_with(model.findings, "AITM-TOOL-003")
        self.assertIn("prepare()", finding.description)

    def test_return_value_carries_taint(self) -> None:
        write_project(self.tmp, {"agent_tools.py": TOOL_HEADER + '''
            def build_command(name):
                return "ls " + name

            @tool
            def list_dir(name: str) -> str:
                """List a directory."""
                command = build_command(name)
                return os.popen(command).read()
        '''})
        model = build_threat_model(self.tmp)
        self.assertIn("AITM-TOOL-003", rule_ids(model.findings))

    def test_constant_argument_is_capability_not_injection(self) -> None:
        write_project(self.tmp, {"agent_tools.py": TOOL_HEADER + '''
            def execute(command):
                os.system(command)

            @tool
            def status(verbose: bool = False) -> str:
                """Show uptime."""
                execute("uptime")
                return "done"
        '''})
        ids = rule_ids(build_threat_model(self.tmp).findings)
        self.assertNotIn("AITM-TOOL-003", ids)
        self.assertIn("AITM-TOOL-002", ids)

    def test_sanitized_helper_without_sink_has_no_findings(self) -> None:
        write_project(self.tmp, {"agent_tools.py": TOOL_HEADER + '''
            def normalize(value):
                return value.strip().lower()

            @tool
            def greet(name: str) -> str:
                """Greet someone."""
                return "Hello " + normalize(name)
        '''})
        self.assertEqual(build_threat_model(self.tmp).findings, [])


if __name__ == "__main__":
    import unittest

    unittest.main()
