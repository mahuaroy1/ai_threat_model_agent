"""Catalog of threat rules.

Every finding is created through :func:`make_finding` so titles, categories,
and remediation advice stay consistent.

Each rule maps to two taxonomies:

* ``category`` - the OWASP Top 10 for LLM Applications (2025), and
* ``owasp_agentic`` - the OWASP Top 10 for Agentic Applications (ASI01-ASI10).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .models import Finding, Location, Severity

OWASP_AGENTIC: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: Severity
    recommendation: str
    owasp_agentic: tuple[str, ...] = ()


_RULES: tuple[Rule, ...] = (
    # Prompt injection (LLM01)
    Rule(
        "AITM-PI-001",
        "Untrusted input concatenated into a prompt",
        "LLM01 Prompt Injection",
        Severity.MEDIUM,
        "Pass user input as a separate template variable or human message; never splice it "
        "into instructions. Delimit untrusted text and validate its length and format.",
        ("ASI01",),
    ),
    Rule(
        "AITM-PI-002",
        "Untrusted data controls a system prompt or prompt template",
        "LLM01 Prompt Injection",
        Severity.HIGH,
        "Keep system prompts and templates static. Put untrusted data only in human/user "
        "message slots, and never let callers supply the template itself.",
        ("ASI01",),
    ),
    Rule(
        "AITM-PI-003",
        "Indirect prompt injection: external content reaches an agent with privileged tools",
        "LLM01 Prompt Injection",
        Severity.HIGH,
        "Treat retrieved and fetched content as data: isolate it from tool-calling agents, "
        "restrict tools to least privilege, and require human approval for side effects.",
        ("ASI01", "ASI06"),
    ),
    Rule(
        "AITM-PI-004",
        "Jinja2 prompt template",
        "LLM01 Prompt Injection",
        Severity.MEDIUM,
        "Prefer f-string templates. If Jinja2 is required, use a sandboxed environment and "
        "never render templates sourced from users or model output.",
        ("ASI01", "ASI05"),
    ),
    # Unsafe tool use / excessive agency (LLM06)
    Rule(
        "AITM-TOOL-001",
        "High-risk built-in tool exposed to the model",
        "LLM06 Excessive Agency",
        Severity.CRITICAL,
        "Remove the tool or replace it with a narrowly scoped tool that validates arguments, "
        "runs in a sandbox, and requires human approval.",
        ("ASI02", "ASI05"),
    ),
    Rule(
        "AITM-TOOL-002",
        "Custom tool performs a privileged operation",
        "LLM06 Excessive Agency",
        Severity.MEDIUM,
        "Confirm the capability is required, use allow-lists for arguments, run with least "
        "privilege, and add human approval for irreversible actions.",
        ("ASI02",),
    ),
    Rule(
        "AITM-TOOL-003",
        "Model-controlled tool argument reaches a dangerous sink",
        "LLM06 Excessive Agency",
        Severity.CRITICAL,
        "Validate tool arguments against a strict schema and allow-list. Use parameterized "
        "queries, argument arrays without a shell, and path/URL allow-lists.",
        ("ASI02", "ASI05"),
    ),
    Rule(
        "AITM-TOOL-004",
        "Framework safety guard explicitly disabled",
        "LLM06 Excessive Agency",
        Severity.HIGH,
        "Remove the override, or isolate the component in a sandbox with no secrets, network, "
        "or write access and document the accepted risk.",
        ("ASI02", "ASI05"),
    ),
    Rule(
        "AITM-TOOL-005",
        "No human approval before side-effecting tool calls",
        "LLM06 Excessive Agency",
        Severity.MEDIUM,
        "Use LangGraph interrupts (interrupt_before / interrupt()) or human-in-the-loop "
        "middleware so a person approves destructive or external actions.",
        ("ASI02", "ASI09"),
    ),
    Rule(
        "AITM-TOOL-006",
        "Agent loop is not bounded",
        "LLM10 Unbounded Consumption",
        Severity.LOW,
        "Set max_iterations / max_execution_time on AgentExecutor or a modest recursion_limit on "
        "LangGraph invocations, and enforce per-user quotas.",
        ("ASI08", "ASI10"),
    ),
    # Improper output handling (LLM05)
    Rule(
        "AITM-OUT-001",
        "Model output reaches a dangerous sink",
        "LLM05 Improper Output Handling",
        Severity.CRITICAL,
        "Treat model output as untrusted input. Parse it into a validated structure and "
        "never pass it to eval, shells, raw SQL, file paths, or URLs.",
        ("ASI05", "ASI02"),
    ),
    Rule(
        "AITM-OUT-002",
        "Model output rendered as trusted HTML or template",
        "LLM05 Improper Output Handling",
        Severity.HIGH,
        "HTML-escape model output, render it as text or sanitized Markdown, and never mark "
        "it as safe markup.",
        ("ASI09",),
    ),
    Rule(
        "AITM-INJ-001",
        "User input reaches a dangerous sink",
        "LLM05 Improper Output Handling",
        Severity.HIGH,
        "Validate and allow-list user input before it reaches commands, code evaluation, "
        "queries, files, or outbound requests.",
        ("ASI05",),
    ),
    # Sensitive data exposure (LLM02, LLM07)
    Rule(
        "AITM-DATA-001",
        "Hard-coded secret",
        "LLM02 Sensitive Information Disclosure",
        Severity.HIGH,
        "Revoke and rotate the credential, remove it from source and history, and load it "
        "from a secret manager or untracked environment configuration.",
        ("ASI03",),
    ),
    Rule(
        "AITM-DATA-002",
        "Secret or personal data sent to a model",
        "LLM02 Sensitive Information Disclosure",
        Severity.MEDIUM,
        "Minimize and redact data before prompting. Confirm the provider's retention terms "
        "and keep credentials out of prompts entirely.",
    ),
    Rule(
        "AITM-DATA-003",
        "Sensitive data written to logs or debug output",
        "LLM02 Sensitive Information Disclosure",
        Severity.LOW,
        "Disable verbose/debug modes in production and redact secrets and personal data "
        "before logging prompts, responses, or tool arguments.",
    ),
    Rule(
        "AITM-DATA-004",
        "Prompts and outputs exported to a third-party tracing service",
        "LLM02 Sensitive Information Disclosure",
        Severity.LOW,
        "Confirm tracing is intended for this environment, mask inputs/outputs containing "
        "personal data, and review the vendor's retention policy.",
    ),
    Rule(
        "AITM-DATA-005",
        "Credential embedded in a system prompt",
        "LLM07 System Prompt Leakage",
        Severity.MEDIUM,
        "Assume system prompts can be extracted. Remove credentials and sensitive rules from "
        "prompts and enforce authorization outside the model.",
        ("ASI03",),
    ),
    # Access control and supply chain
    Rule(
        "AITM-AUTH-001",
        "LLM entry point has no detected authentication",
        "LLM10 Unbounded Consumption",
        Severity.MEDIUM,
        "Require authentication and authorization on the endpoint, and add rate limits and "
        "usage quotas to protect model spend and connected tools.",
        ("ASI03",),
    ),
    Rule(
        "AITM-SUP-001",
        "AI framework dependency is not pinned",
        "LLM03 Supply Chain",
        Severity.LOW,
        "Pin exact versions (or use a lock file with hashes) for LangChain, LangGraph, and "
        "model SDK packages, and review updates before upgrading.",
        ("ASI04",),
    ),
    # Agentic risks (OWASP Top 10 for Agentic Applications)
    Rule(
        "AITM-SUP-002",
        "Agent prompt, tool, or MCP server loaded from a remote source without pinning",
        "LLM03 Supply Chain",
        Severity.MEDIUM,
        "Pin prompts to a commit hash (hub.pull('owner/name:<commit>')), pin MCP server packages to "
        "exact versions (npx pkg@1.2.3, uvx pkg==1.2.3), and review tool descriptions before upgrading.",
        ("ASI04",),
    ),
    Rule(
        "AITM-MEM-001",
        "Untrusted data written to persistent agent memory",
        "LLM04 Data and Model Poisoning",
        Severity.MEDIUM,
        "Validate and attribute memory writes, store untrusted content separately from "
        "instructions, scope long-term memory per user/tenant, and expire or review entries.",
        ("ASI06",),
    ),
    Rule(
        "AITM-MEM-002",
        "Memory or conversation scope is chosen by the caller or the model",
        "LLM02 Sensitive Information Disclosure",
        Severity.MEDIUM,
        "Derive thread_id, session_id, and memory namespaces from the authenticated identity on "
        "the server side; never accept them from request bodies or tool arguments.",
        ("ASI06", "ASI03"),
    ),
    Rule(
        "AITM-ID-001",
        "Tool takes an object or identity reference from the model (confused deputy)",
        "LLM06 Excessive Agency",
        Severity.MEDIUM,
        "Inject the caller's identity into the tool (InjectedToolArg, InjectedState, or the "
        "RunnableConfig) and authorize every object access against it; never trust IDs chosen "
        "by the model.",
        ("ASI03", "ASI02"),
    ),
    Rule(
        "AITM-MA-001",
        "Inter-agent or MCP channel lacks transport security or authentication",
        "LLM06 Excessive Agency",
        Severity.MEDIUM,
        "Use HTTPS/mTLS for remote agents and MCP servers, authenticate every connection, "
        "and treat messages from other agents as untrusted input.",
        ("ASI07", "ASI04"),
    ),
    Rule(
        "AITM-MA-002",
        "Multi-agent delegation reaches privileged tools without isolation",
        "LLM06 Excessive Agency",
        Severity.MEDIUM,
        "Give each agent least-privilege tools, validate hand-off messages, and require "
        "approval before a delegated agent performs side effects.",
        ("ASI07", "ASI08", "ASI10"),
    ),
)

RULES: dict[str, Rule] = {rule.id: rule for rule in _RULES}


def agentic_label(code: str) -> str:
    """``ASI06`` -> ``ASI06 Memory and Context Poisoning``."""
    return f"{code} {OWASP_AGENTIC[code]}" if code in OWASP_AGENTIC else code


def make_finding(
    rule_id: str,
    location: Location,
    description: str,
    *,
    severity: Severity | None = None,
    related: Iterable[Location] = (),
    confidence: str = "medium",
) -> Finding:
    """Create a :class:`Finding` from a rule in the catalog.

    Raises:
        KeyError: If ``rule_id`` is not defined; this indicates a programming error.
    """
    rule = RULES[rule_id]
    return Finding(
        rule_id=rule.id,
        title=rule.title,
        severity=severity or rule.severity,
        category=rule.category,
        description=description,
        recommendation=rule.recommendation,
        location=location,
        related=list(related),
        confidence=confidence,
        owasp_agentic=list(rule.owasp_agentic),
    )