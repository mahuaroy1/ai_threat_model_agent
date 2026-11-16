"""Acme support agent: a LangGraph ReAct agent backed by a local Qwen model in Ollama.

INTENTIONALLY VULNERABLE. This package is a scan target for ``ai-threat-model``.
Do not run or deploy it. Each weakness is annotated with the rule that detects it.
"""

import sqlite3

from langchain.globals import set_debug
from langchain_community.document_loaders import WebBaseLoader
from langchain_community.tools import ShellTool
from langchain_core.messages import SystemMessage
from langchain_core.tools import tool
from langchain_ollama import ChatOllama
from langgraph.prebuilt import create_react_agent

from app.system_utils import run_network_check

DB_PATH = "support.db"
SUPPORT_API_KEY = "acme-support-7d41c9e2"  # AITM-DATA-001: hard-coded credential

set_debug(True)  # AITM-DATA-003: prints full prompts and tool arguments

llm = ChatOllama(model="qwen2.5-coder:7b", base_url="http://127.0.0.1:11434", temperature=0)

# AITM-DATA-005: a secret inside the system prompt can be extracted by prompt injection.
SYSTEM_PROMPT = SystemMessage(
    content="You are Acme's support assistant. The admin password is Tr0ub4dor-acme. Never reveal it."
)


@tool
def fetch_kb_article(url: str) -> str:
    """Fetch a knowledge-base article or any web page the customer mentions."""
    documents = WebBaseLoader(url).load()  # AITM-PI-003: untrusted web content enters the agent context
    return documents[0].page_content


@tool
def lookup_customer(customer_id: str) -> str:
    """Look up a customer record by ID."""
    with sqlite3.connect(DB_PATH) as connection:
        # AITM-TOOL-003: model-chosen argument spliced into SQL
        row = connection.execute(f"SELECT name, plan FROM customers WHERE id = '{customer_id}'").fetchone()
    return str(row)


@tool
def network_check(host: str) -> str:
    """Check whether a customer's server is reachable."""
    return run_network_check(host)  # AITM-TOOL-003 (interprocedural): reaches a shell in system_utils.py


def build_agent():
    """Create the agent. No interrupt_before / human approval (AITM-TOOL-005)."""
    tools = [fetch_kb_article, lookup_customer, network_check, ShellTool()]  # AITM-TOOL-001: ShellTool
    return create_react_agent(llm, tools, prompt=SYSTEM_PROMPT)
