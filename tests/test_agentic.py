"""OWASP Top 10 for Agentic Applications (ASI01-ASI10): rules, mapping, controls, and reporting."""

import json
import textwrap
import unittest

from ai_threat_model import agentic
from ai_threat_model.config_analyzer import analyze_config
from ai_threat_model.engine import ScanOptions, build_threat_model
from ai_threat_model.models import ControlStatus, Severity
from ai_threat_model.python_analyzer import analyze_python_source
from ai_threat_model.reporting import render_markdown, render_sarif
from ai_threat_model.rules import OWASP_AGENTIC, RULES, agentic_label
from tests.helpers import TempDirTestCase, findings_with, rule_ids, write_project


def analyze(source: str, path: str = "app.py"):
    return analyze_python_source(path, textwrap.dedent(source).lstrip("\n"))


class MappingTests(unittest.TestCase):
    def test_all_ten_risks_are_defined(self) -> None:
        self.assertEqual(list(OWASP_AGENTIC), [f"ASI{n:02d}" for n in range(1, 11)])

    def test_rule_codes_are_valid(self) -> None:
        for rule in RULES.values():
            for code in rule.owasp_agentic:
                self.assertIn(code, OWASP_AGENTIC, rule.id)

    def test_findings_carry_the_rule_mapping(self) -> None:
        result = analyze("""
            from langchain_core.tools import tool
            import subprocess

            @tool
            def run(cmd: str) -> str:
                \"\"\"Run a command.\"\"\"
                return subprocess.run(cmd, shell=True).stdout
        """)
        finding = findings_with(result.findings, "AITM-TOOL-003")[0]
        self.assertIn("ASI02", finding.owasp_agentic)
        self.assertIn("ASI05", finding.owasp_agentic)

    def test_label(self) -> None:
        self.assertEqual(agentic_label("ASI06"), f"ASI06 {OWASP_AGENTIC['ASI06']}")
        self.assertEqual(agentic_label("XYZ"), "XYZ")


class AgenticHelperTests(unittest.TestCase):
    def test_loopback(self) -> None:
        self.assertTrue(agentic.is_loopback("http://localhost:8000"))
        self.assertTrue(agentic.is_loopback("http://127.0.0.1:8000"))
        self.assertFalse(agentic.is_loopback("http://agents.example.com"))

    def test_channel_issue(self) -> None:
        plaintext = agentic.channel_issue("x", "http://agents.example.com/mcp", has_auth=True)
        self.assertEqual(plaintext.severity, Severity.HIGH)
        anonymous = agentic.channel_issue("x", "https://agents.example.com/mcp", has_auth=False)
        self.assertEqual(anonymous.severity, Severity.MEDIUM)
        self.assertEqual(anonymous.confidence, "low")
        self.assertIsNone(agentic.channel_issue("x", "https://agents.example.com/mcp", has_auth=True))
        self.assertIsNone(agentic.channel_issue("x", "http://localhost:3000/mcp", has_auth=False))
        self.assertIsNone(agentic.channel_issue("x", None, has_auth=False))

    def test_unpinned_package(self) -> None:
        self.assertEqual(agentic.unpinned_package("npx", ["-y", "@acme/mcp-server"]), "@acme/mcp-server")
        self.assertIsNone(agentic.unpinned_package("npx", ["-y", "@acme/mcp-server@1.2.3"]))
        self.assertEqual(agentic.unpinned_package("uvx", ["mcp-server-git"]), "mcp-server-git")
        self.assertIsNone(agentic.unpinned_package("uvx", ["mcp-server-git==0.6.2"]))
        self.assertIsNone(agentic.unpinned_package("python", ["server.py"]))
        self.assertIsNone(agentic.unpinned_package(None, []))

    def test_hub_reference(self) -> None:
        self.assertTrue(agentic.is_pinned_hub_reference("acme/prompt:0123abcd"))
        self.assertFalse(agentic.is_pinned_hub_reference("acme/prompt"))
        self.assertFalse(agentic.is_pinned_hub_reference("acme/prompt:latest"))


class MemoryTests(unittest.TestCase):
    def test_tool_writing_model_text_to_store_is_memory_poisoning(self) -> None:
        result = analyze("""
            from langchain_core.tools import tool
            from langgraph.store.memory import InMemoryStore

            store = InMemoryStore()

            @tool
            def remember(note: str) -> str:
                \"\"\"Save a note for later.\"\"\"
                store.put(("memories",), "latest", {"text": note})
                return "saved"
        """)
        findings = findings_with(result.findings, "AITM-MEM-001")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, Severity.HIGH)
        self.assertIn("ASI06", findings[0].owasp_agentic)
        self.assertIn("memory", {c.kind.value for c in result.components})

    def test_web_content_into_vector_store(self) -> None:
        result = analyze("""
            from langchain_community.document_loaders import WebBaseLoader
            from langchain_chroma import Chroma

            def ingest(url, vectorstore):
                docs = WebBaseLoader(url).load()
                vectorstore.add_documents(docs)
        """)
        self.assertIn("AITM-MEM-001", rule_ids(result.findings))

    def test_constant_writes_are_not_reported(self) -> None:
        result = analyze("""
            def seed(vectorstore):
                vectorstore.add_texts(["Our refund window is 30 days."])
        """)
        self.assertNotIn("AITM-MEM-001", rule_ids(result.findings))

    def test_thread_id_from_request_is_caller_controlled_scope(self) -> None:
        result = analyze("""
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/chat")
            def chat(message: str, thread_id: str):
                return graph.invoke({"messages": [message]}, {"configurable": {"thread_id": thread_id}})
        """)
        findings = findings_with(result.findings, "AITM-MEM-002")
        self.assertEqual(len(findings), 1)
        self.assertIn("ASI06", findings[0].owasp_agentic)

    def test_thread_id_from_authenticated_user_is_fine(self) -> None:
        result = analyze("""
            from fastapi import Depends, FastAPI
            app = FastAPI()

            @app.post("/chat")
            def chat(message: str, current_user=Depends(get_user)):
                return graph.invoke({"messages": [message]}, {"configurable": {"thread_id": current_user.id}})
        """)
        self.assertNotIn("AITM-MEM-002", rule_ids(result.findings))


class IdentityTests(unittest.TestCase):
    def test_model_chosen_identifier_is_confused_deputy(self) -> None:
        result = analyze("""
            from langchain_core.tools import tool

            @tool
            def get_invoices(customer_id: str) -> str:
                \"\"\"Return invoices for a customer.\"\"\"
                return db.fetch(customer_id)
        """)
        findings = findings_with(result.findings, "AITM-ID-001")
        self.assertEqual(len(findings), 1)
        self.assertIn("ASI03", findings[0].owasp_agentic)

    def test_injected_identity_is_not_reported(self) -> None:
        result = analyze("""
            from typing import Annotated
            from langchain_core.tools import InjectedToolArg, tool

            @tool
            def get_invoices(customer_id: Annotated[str, InjectedToolArg]) -> str:
                \"\"\"Return invoices for the caller.\"\"\"
                return db.fetch(customer_id)
        """)
        self.assertNotIn("AITM-ID-001", rule_ids(result.findings))

    def test_tool_with_config_is_not_reported(self) -> None:
        result = analyze("""
            from langchain_core.runnables import RunnableConfig
            from langchain_core.tools import tool

            @tool
            def get_order(order_id: str, config: RunnableConfig) -> str:
                \"\"\"Return one of the caller's orders.\"\"\"
                return lookup(order_id, config["configurable"]["user"])
        """)
        self.assertNotIn("AITM-ID-001", rule_ids(result.findings))


class SupplyChainTests(unittest.TestCase):
    def test_unpinned_hub_prompt(self) -> None:
        result = analyze("""
            from langchain import hub
            prompt = hub.pull("acme/support-agent")
            pinned = hub.pull("acme/support-agent:0a1b2c3d")
        """)
        findings = findings_with(result.findings, "AITM-SUP-002")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].location.line, 2)

    def test_mcp_client_unpinned_npx_and_plaintext_http(self) -> None:
        result = analyze("""
            from langchain_mcp_adapters.client import MultiServerMCPClient

            client = MultiServerMCPClient({
                "files": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"], "transport": "stdio"},
                "pinned": {"command": "npx", "args": ["-y", "@acme/server@1.0.0"], "transport": "stdio"},
                "billing": {"url": "http://billing.internal.example.com/mcp", "transport": "streamable_http"},
                "local": {"url": "http://localhost:3000/mcp", "transport": "streamable_http"},
            })
        """)
        self.assertEqual(len(findings_with(result.findings, "AITM-SUP-002")), 1)
        channel = findings_with(result.findings, "AITM-MA-001")
        self.assertEqual(len(channel), 1)
        self.assertEqual(channel[0].severity, Severity.HIGH)
        mcp_tools = [c for c in result.components if c.attributes.get("source") == "MCP"]
        self.assertEqual(len(mcp_tools), 4)

    def test_remote_graph_over_https_without_auth_is_low_confidence(self) -> None:
        result = analyze("""
            from langgraph.pregel.remote import RemoteGraph
            remote = RemoteGraph("researcher", url="https://agents.example.com")
        """)
        finding = findings_with(result.findings, "AITM-MA-001")[0]
        self.assertEqual(finding.confidence, "low")
        self.assertIn("ASI07", finding.owasp_agentic)


class ExecutionLimitTests(unittest.TestCase):
    def test_huge_recursion_limit(self) -> None:
        result = analyze("""
            def run(graph, text):
                return graph.invoke({"messages": [text]}, config={"recursion_limit": 5000})
        """)
        self.assertIn("AITM-TOOL-006", rule_ids(result.findings))

    def test_small_recursion_limit_is_a_control(self) -> None:
        result = analyze("""
            def run(graph, text):
                return graph.invoke({"messages": [text]}, config={"recursion_limit": 10})
        """)
        self.assertNotIn("AITM-TOOL-006", rule_ids(result.findings))
        self.assertIn("iteration_limit", result.signals)


class McpConfigFileTests(unittest.TestCase):
    def test_mcp_json_servers(self) -> None:
        text = json.dumps({"mcpServers": {
            "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
            "remote": {"url": "http://mcp.example.com/sse"},
            "safe": {"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer ${TOKEN}"}},
        }}, indent=2)
        result = analyze_config(".vscode/mcp.json", text, env_ignored_by_git=True)
        self.assertEqual(len([c for c in result.components if c.attributes.get("source") == "MCP"]), 3)
        self.assertEqual(len(findings_with(result.findings, "AITM-SUP-002")), 1)
        self.assertEqual(len(findings_with(result.findings, "AITM-MA-001")), 1)
        self.assertEqual(findings_with(result.findings, "AITM-SUP-002")[0].location.line, 3)

    def test_invalid_json_is_ignored(self) -> None:
        result = analyze_config("mcp.json", "{not json", env_ignored_by_git=True)
        self.assertEqual(result.components, [])


MULTI_AGENT_APP = """
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent
from langgraph_supervisor import create_supervisor
import subprocess

llm = ChatOllama(model="qwen2.5-coder:7b")

@tool
def deploy(service: str) -> str:
    \"\"\"Deploy a service.\"\"\"
    return subprocess.run(["deploy", service]).stdout

ops = create_react_agent(llm, [deploy], name="ops")
supervisor = create_supervisor([ops], model=llm).compile()
"""


class ProjectTests(TempDirTestCase):
    def controls(self, model) -> dict[str, ControlStatus]:
        return {control.id: control.status for control in model.controls}

    def test_multi_agent_delegation_and_missing_controls(self) -> None:
        write_project(self.tmp, {"app.py": MULTI_AGENT_APP})
        model = build_threat_model(self.tmp)
        self.assertIn("AITM-MA-002", rule_ids(model.findings))
        statuses = self.controls(model)
        self.assertEqual(statuses["CTRL-01"], ControlStatus.MISSING)  # no human approval for deploy
        self.assertEqual(statuses["CTRL-02"], ControlStatus.PARTIAL)  # framework default limits
        self.assertEqual(statuses["CTRL-03"], ControlStatus.NOT_APPLICABLE)  # no HTTP entry points
        self.assertEqual(statuses["CTRL-12"], ControlStatus.NOT_APPLICABLE)  # no memory

    def test_controls_present_when_evidence_found(self) -> None:
        write_project(self.tmp, {"app.py": MULTI_AGENT_APP + textwrap.dedent("""
            from langgraph.types import interrupt
            from langchain_core.rate_limiters import InMemoryRateLimiter

            limiter = InMemoryRateLimiter(requests_per_second=1)
            approval = interrupt({"action": "deploy"})
            result = supervisor.invoke({"messages": []}, config={"recursion_limit": 10})
        """)})
        model = build_threat_model(self.tmp)
        statuses = self.controls(model)
        self.assertEqual(statuses["CTRL-01"], ControlStatus.PRESENT)
        self.assertEqual(statuses["CTRL-02"], ControlStatus.PRESENT)
        ma = findings_with(model.findings, "AITM-MA-002")
        self.assertTrue(all(f.severity is Severity.MEDIUM for f in ma))

    def test_reports_include_owasp_agentic(self) -> None:
        write_project(self.tmp, {"app.py": MULTI_AGENT_APP})
        model = build_threat_model(self.tmp)
        markdown = render_markdown(model)
        self.assertIn("## OWASP Top 10 for Agentic Applications", markdown)
        self.assertIn("## Agent controls checklist", markdown)
        self.assertIn("**OWASP Agentic:**", markdown)
        sarif = json.loads(render_sarif(model))
        tags = {tag for rule in sarif["runs"][0]["tool"]["driver"]["rules"] for tag in rule["properties"]["tags"]}
        self.assertIn("ASI07", tags)

    def test_cache_round_trips_mapping_and_signals(self) -> None:
        write_project(self.tmp, {"app.py": MULTI_AGENT_APP})
        cache_dir = self.tmp / ".cache"
        options = ScanOptions(cache_dir=cache_dir)
        first = build_threat_model(self.tmp, options)
        second = build_threat_model(self.tmp, options)
        self.assertEqual(
            sorted((f.rule_id, tuple(f.owasp_agentic)) for f in first.findings),
            sorted((f.rule_id, tuple(f.owasp_agentic)) for f in second.findings),
        )
        self.assertEqual(self.controls(first), self.controls(second))


if __name__ == "__main__":
    unittest.main()
