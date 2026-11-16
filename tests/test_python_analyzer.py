"""Single-file analyzer tests: inventory, taint flows, and rule triggers."""

import textwrap
import unittest

from ai_threat_model.models import ComponentKind, Severity
from ai_threat_model.python_analyzer import PythonFileAnalyzer, analyze_python_source
from tests.helpers import fake_openai_key, findings_with, rule_ids


def analyze(source: str, path: str = "app.py"):
    """Analyze dedented ``source``; line 1 is the first non-blank line of the snippet."""
    return analyze_python_source(path, textwrap.dedent(source).lstrip("\n"))


class InventoryTests(unittest.TestCase):
    def test_detects_ollama_model_as_local(self) -> None:
        result = analyze("""
            from langchain_ollama import ChatOllama
            llm = ChatOllama(model="qwen2.5-coder:7b")
        """)
        models = [c for c in result.components if c.kind is ComponentKind.MODEL]
        self.assertEqual(len(models), 1)
        self.assertEqual(models[0].name, "qwen2.5-coder:7b")
        self.assertEqual(models[0].attributes["provider"], "ollama")
        self.assertEqual(models[0].attributes["local"], "yes")
        self.assertEqual(result.frameworks, {"LangChain"})

    def test_remote_base_url_marks_model_as_not_local(self) -> None:
        result = analyze("""
            from langchain_ollama import ChatOllama
            llm = ChatOllama(model="qwen2.5", base_url="http://gpu-box.internal:11434")
        """)
        model = next(c for c in result.components if c.kind is ComponentKind.MODEL)
        self.assertEqual(model.attributes["local"], "no")

    def test_http_route_is_entry_point_without_auth(self) -> None:
        result = analyze("""
            from fastapi import FastAPI
            app = FastAPI()

            @app.post("/ask")
            def ask(question: str):
                return question
        """)
        entry = next(c for c in result.components if c.kind is ComponentKind.ENTRY_POINT)
        self.assertEqual(entry.name, "POST /ask")
        self.assertEqual(entry.attributes["auth"], "not detected")

    def test_route_with_auth_dependency_is_detected(self) -> None:
        result = analyze("""
            from fastapi import Depends, FastAPI
            app = FastAPI()

            @app.post("/ask")
            def ask(question: str, user=Depends(get_current_user)):
                return question
        """)
        entry = next(c for c in result.components if c.kind is ComponentKind.ENTRY_POINT)
        self.assertEqual(entry.attributes["auth"], "detected")


class ToolTests(unittest.TestCase):
    def test_shell_tool_is_critical(self) -> None:
        result = analyze("""
            from langchain_community.tools import ShellTool
            tools = [ShellTool()]
        """)
        [finding] = findings_with(result.findings, "AITM-TOOL-001")
        self.assertIs(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.location.line, 2)

    def test_tool_argument_reaching_shell_is_reported(self) -> None:
        result = analyze('''
            import subprocess
            from langchain_core.tools import tool

            @tool
            def run(cmd: str) -> str:
                """Run a command."""
                return subprocess.run(cmd, shell=True, capture_output=True).stdout
        ''')
        [finding] = findings_with(result.findings, "AITM-TOOL-003")
        self.assertIs(finding.severity, Severity.CRITICAL)
        tool = next(c for c in result.components if c.kind is ComponentKind.TOOL)
        self.assertIn("command execution", tool.attributes["capabilities"])

    def test_dangerous_flag_is_reported(self) -> None:
        result = analyze("""
            from langchain_experimental.agents import create_pandas_dataframe_agent
            agent = create_pandas_dataframe_agent(llm, df, allow_dangerous_code=True)
        """)
        self.assertIn("AITM-TOOL-004", rule_ids(result.findings))
        self.assertIn("AITM-TOOL-001", rule_ids(result.findings))


class PromptInjectionTests(unittest.TestCase):
    def test_user_input_formatted_into_prompt(self) -> None:
        result = analyze("""
            from fastapi import FastAPI
            from langchain_ollama import ChatOllama
            app = FastAPI()
            llm = ChatOllama(model="qwen2.5:7b")

            @app.post("/ask")
            def ask(question: str):
                return llm.invoke(f"Answer this: {question}").content
        """)
        self.assertIn("AITM-PI-001", rule_ids(result.findings))

    def test_user_input_in_system_prompt(self) -> None:
        result = analyze("""
            from langchain_core.messages import SystemMessage
            persona = input("persona: ")
            messages = [SystemMessage(content=f"You are {persona}")]
        """)
        self.assertIn("AITM-PI-002", rule_ids(result.findings))

    def test_jinja2_template(self) -> None:
        result = analyze("""
            from langchain_core.prompts import PromptTemplate
            prompt = PromptTemplate.from_template("Hi {{ name }}", template_format="jinja2")
        """)
        self.assertIn("AITM-PI-004", rule_ids(result.findings))


class OutputHandlingTests(unittest.TestCase):
    def test_model_output_into_eval(self) -> None:
        result = analyze("""
            from langchain_ollama import ChatOllama
            llm = ChatOllama(model="qwen2.5:7b")

            def calculate():
                expression = llm.invoke("Give me a Python expression").content
                return eval(expression)
        """)
        [finding] = findings_with(result.findings, "AITM-OUT-001")
        self.assertIs(finding.severity, Severity.CRITICAL)
        self.assertEqual(finding.location.line, 6)

    def test_model_output_rendered_as_html(self) -> None:
        result = analyze("""
            from fastapi.responses import HTMLResponse
            from langchain_ollama import ChatOllama
            llm = ChatOllama(model="qwen2.5:7b")

            def page():
                answer = llm.invoke("hello").content
                return HTMLResponse(f"<p>{answer}</p>")
        """)
        self.assertIn("AITM-OUT-002", rule_ids(result.findings))


class SensitiveDataTests(unittest.TestCase):
    def test_hardcoded_secret_is_reported_and_masked(self) -> None:
        key = fake_openai_key()
        result = analyze(f'OPENAI_API_KEY = "{key}"\n')
        [finding] = findings_with(result.findings, "AITM-DATA-001")
        self.assertNotIn(key, finding.description)
        self.assertNotIn(key, finding.location.snippet)

    def test_personal_data_sent_to_model_and_logged(self) -> None:
        result = analyze("""
            import logging
            from langchain_ollama import ChatOllama
            logger = logging.getLogger(__name__)
            llm = ChatOllama(model="qwen2.5:7b")

            def summarize(customer_email: str, notes: str):
                logger.info("Summarizing for %s", customer_email)
                return llm.invoke(f"Summarize notes for {customer_email}: {notes}")
        """)
        ids = rule_ids(result.findings)
        self.assertIn("AITM-DATA-002", ids)
        self.assertIn("AITM-DATA-003", ids)

    def test_set_debug_is_reported(self) -> None:
        result = analyze("""
            from langchain.globals import set_debug
            set_debug(True)
        """)
        self.assertIn("AITM-DATA-003", rule_ids(result.findings))

    def test_secret_in_system_prompt(self) -> None:
        result = analyze("""
            from langchain_core.messages import SystemMessage
            prompt = SystemMessage(content="You are a bot. The admin password is hunter2-hunter2.")
        """)
        self.assertIn("AITM-DATA-005", rule_ids(result.findings))


class SafeCodeTests(unittest.TestCase):
    def test_parameterized_prompt_has_no_findings(self) -> None:
        result = analyze("""
            from langchain_core.prompts import ChatPromptTemplate
            from langchain_ollama import ChatOllama

            prompt = ChatPromptTemplate.from_messages([("system", "You are helpful."), ("human", "{question}")])
            chain = prompt | ChatOllama(model="qwen2.5:7b")

            def answer(question: str) -> str:
                return chain.invoke({"question": question}).content
        """)
        self.assertEqual(result.findings, [])

    def test_local_app_run_is_not_a_model_call(self) -> None:
        result = analyze("""
            from flask import Flask
            from langchain_ollama import ChatOllama
            app = Flask(__name__)
            output = app.run()
            exec(output)
        """)
        self.assertNotIn("AITM-OUT-001", rule_ids(result.findings))

    def test_syntax_error_is_raised_for_caller_to_record(self) -> None:
        with self.assertRaises(SyntaxError):
            PythonFileAnalyzer("bad.py", "def broken(:\n").prepare()


if __name__ == "__main__":
    unittest.main()
