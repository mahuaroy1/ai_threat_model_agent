"""Project-level reasoning across all files.

Per-file analyzers find local facts; this module combines them into:

* trust boundaries (user -> app, app -> model provider, content -> context
  window, model -> tools, app -> observability vendor),
* coarse data flows between components for the architecture diagram, and
* risks that only appear when components are combined, such as indirect
  prompt injection (untrusted content + privileged tools), and
* the agent controls checklist: which defenses for the OWASP Top 10 for
  Agentic Applications were (or were not) observed in the code.
"""

from __future__ import annotations

from . import catalog
from .catalog import SIDE_EFFECT_SINKS, SinkKind
from .models import (
    Component,
    ComponentKind,
    ControlCheck,
    ControlStatus,
    DataFlow,
    Finding,
    Location,
    Severity,
    ThreatModel,
    TrustBoundary,
)
from .rules import make_finding

Signals = dict[str, list[Location]]

_SIDE_EFFECT_CAPABILITIES = frozenset(kind.value for kind in SIDE_EFFECT_SINKS)
_MAX_RELATED = 10
Outcome = tuple[ControlStatus, str, list[Location]]
_CODE_RUNNING_LOAD_TOOLS = frozenset({"terminal", "shell", "python_repl"})
# Matches data-flow capabilities and the reasons in catalog.DANGEROUS_TOOLS.
_CODE_EXECUTION_MARKERS = (SinkKind.COMMAND.value, SinkKind.CODE.value, "executes generated")


def is_side_effecting(tool: Component) -> bool:
    """True if a tool can change state or reach external systems."""
    if tool.attributes.get("dangerous") == "yes":
        return True
    capabilities = set(filter(None, tool.attributes.get("capabilities", "").split(", ")))
    return bool(capabilities & _SIDE_EFFECT_CAPABILITIES)


def correlate(model: ThreatModel, signals: Signals) -> None:
    """Add trust boundaries, data flows, cross-component findings, and the controls checklist.

    Args:
        model: The threat model with per-file components and findings.
        signals: Evidence of agent controls keyed by ``catalog.SIGNAL_*``.
    """
    model.findings.extend(_cross_component_findings(model, signals))
    model.trust_boundaries = _trust_boundaries(model)
    model.data_flows = _data_flows(model)
    model.controls = _controls(model, signals)


def is_multi_agent(signals: Signals) -> bool:
    """True if agents delegate to other agents (supervisor, swarm, hand-offs, remote agents)."""
    return bool(signals.get(catalog.SIGNAL_MULTI_AGENT))


# --------------------------------------------------------------------------- findings


def _cross_component_findings(model: ThreatModel, signals: Signals) -> list[Finding]:
    human_approval = signals.get(catalog.SIGNAL_HUMAN_APPROVAL, [])
    findings: list[Finding] = []
    agents = model.components_of(ComponentKind.AGENT)
    tools = model.components_of(ComponentKind.TOOL)
    models = model.components_of(ComponentKind.MODEL)
    risky_tools = [tool for tool in tools if is_side_effecting(tool)]
    external_sources = [
        component for component in model.components_of(ComponentKind.RETRIEVAL)
        if component.attributes.get("trust") == "untrusted external content"
    ]

    if external_sources and agents and risky_tools:
        anchor = agents[0]
        findings.append(make_finding(
            "AITM-PI-003", anchor.location,
            f"Untrusted external content ({_names(external_sources)}) can reach agent context while the agent "
            f"can call side-effecting tools ({_names(risky_tools)}). Instructions hidden in fetched content "
            "can trigger those tools.",
            related=[c.location for c in (*external_sources, *risky_tools)][:_MAX_RELATED],
        ))
    elif external_sources and (agents or models):
        anchor = (agents or models)[0]
        findings.append(make_finding(
            "AITM-PI-003", anchor.location,
            f"Untrusted external content ({_names(external_sources)}) is placed in model context. "
            "Injected instructions can manipulate responses even without privileged tools.",
            severity=Severity.MEDIUM,
            related=[c.location for c in external_sources][:_MAX_RELATED],
        ))

    if risky_tools and not human_approval:
        anchor = agents[0].location if agents else risky_tools[0].location
        findings.append(make_finding(
            "AITM-TOOL-005", anchor,
            f"Side-effecting tools ({_names(risky_tools)}) run without any detected human approval step "
            "(no LangGraph interrupt, interrupt_before/after, or human-in-the-loop middleware).",
            related=[tool.location for tool in risky_tools][:_MAX_RELATED],
        ))

    if agents or models:
        for entry in model.components_of(ComponentKind.ENTRY_POINT):
            if entry.attributes.get("interface", "").startswith("HTTP") and entry.attributes.get("auth") == "not detected":
                findings.append(make_finding(
                    "AITM-AUTH-001", entry.location,
                    f"`{entry.name}` exposes LLM functionality without detected authentication; anyone who can "
                    "reach it can spend model quota and drive connected tools.",
                    confidence="low",
                ))

    if risky_tools and is_multi_agent(signals):
        anchor = (signals.get(catalog.SIGNAL_MULTI_AGENT) or [a.location for a in agents] or [risky_tools[0].location])[0]
        findings.append(make_finding(
            "AITM-MA-002", anchor,
            f"Agents delegate work to each other while side-effecting tools ({_names(risky_tools)}) are reachable. "
            "Output of one agent becomes instructions for the next, so a single hijacked agent can drive "
            "privileged tools elsewhere in the system.",
            severity=Severity.MEDIUM if human_approval else Severity.HIGH,
            related=[c.location for c in (*agents, *risky_tools)][:_MAX_RELATED],
            confidence="low",
        ))
    return findings


def _names(components: list[Component], limit: int = 5) -> str:
    names = sorted({component.name for component in components})
    shown = ", ".join(f"`{name}`" for name in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


# --------------------------------------------------------------------------- boundaries


def _trust_boundaries(model: ThreatModel) -> list[TrustBoundary]:
    boundaries: list[TrustBoundary] = []

    def add(name: str, source: str, target: str, description: str, components: list[Component]) -> None:
        if components:
            boundaries.append(TrustBoundary(
                id=f"TB-{len(boundaries) + 1}", name=name, source_zone=source, target_zone=target,
                description=description, component_ids=[c.id for c in components],
            ))

    entry_points = model.components_of(ComponentKind.ENTRY_POINT)
    add("Users to application", "External users", "Application",
        "Requests, chat messages, and uploads enter the application. All content is attacker-controllable.",
        entry_points)

    models = model.components_of(ComponentKind.MODEL)
    remote_models = [m for m in models if m.attributes.get("local") != "yes"]
    local_models = [m for m in models if m.attributes.get("local") == "yes"]
    providers = sorted({m.attributes.get("provider", "unknown") for m in remote_models})
    add("Application to hosted model provider", "Application", f"Model provider ({', '.join(providers)})",
        "Prompts, retrieved context, and tool results leave the organization; responses return as untrusted text.",
        remote_models)
    add("Application to local model runtime", "Application", "Local model runtime",
        "Prompts stay on local infrastructure, but model responses are still untrusted output.",
        local_models)

    add("External content to model context", "Documents, web, and data stores", "Model context window",
        "Retrieved or fetched content is concatenated into prompts and can carry indirect prompt injection.",
        model.components_of(ComponentKind.RETRIEVAL))

    add("Model decisions to tool execution", "Model output", "Tools and downstream systems",
        "The model chooses which tools run and with which arguments; tool arguments are attacker-influenced.",
        model.components_of(ComponentKind.TOOL))

    add("Application to observability vendor", "Application", "Tracing / logging vendor",
        "Traces include full prompts, tool arguments, and outputs.",
        model.components_of(ComponentKind.OBSERVABILITY))

    add("Agent to persistent memory", "Agent session", "Shared memory and state",
        "Content written in one session is read back as trusted context in later sessions (memory poisoning, "
        "cross-user leakage).",
        model.components_of(ComponentKind.MEMORY))

    add("Agent to remote agents and MCP servers", "Application", "Third-party agents and tool servers",
        "Tool descriptions, results, and agent messages from remote parties are untrusted and can carry "
        "instructions.",
        [c for c in (*model.components_of(ComponentKind.TOOL), *model.components_of(ComponentKind.AGENT)) if _is_remote(c)])
    return boundaries


def _is_remote(component: Component) -> bool:
    return (
        component.attributes.get("source") == "MCP"
        or component.attributes.get("remote") == "yes"
        or component.attributes.get("factory") == "RemoteGraph"
    )


def _boundary_for(model: ThreatModel, component: Component) -> str:
    return next((b.id for b in model.trust_boundaries if component.id in b.component_ids), "")


# --------------------------------------------------------------------------- flows


def _data_flows(model: ThreatModel) -> list[DataFlow]:
    """Coarse component-level flows used for the architecture diagram."""
    entry_points = model.components_of(ComponentKind.ENTRY_POINT)
    agents = model.components_of(ComponentKind.AGENT)
    models = model.components_of(ComponentKind.MODEL)
    tools = model.components_of(ComponentKind.TOOL)
    sources = model.components_of(ComponentKind.RETRIEVAL)
    observability = model.components_of(ComponentKind.OBSERVABILITY)
    orchestrators = agents or models

    flows: list[DataFlow] = []

    def link(source: Component, target: Component, label: str, boundary_component: Component) -> None:
        flows.append(DataFlow(source.id, target.id, label, _boundary_for(model, boundary_component)))

    for entry in entry_points:
        for target in orchestrators:
            link(entry, target, "user input", entry)
    for agent in agents:
        for llm in models:
            link(agent, llm, "prompts and context", llm)
        for tool in tools:
            link(agent, tool, "tool calls (model-chosen arguments)", tool)
    if not agents:
        for llm in models:
            for tool in tools:
                link(llm, tool, "tool calls (model-chosen arguments)", tool)
    for source in sources:
        for target in orchestrators:
            link(source, target, "retrieved content", source)
    for sink in observability:
        for source in orchestrators:
            link(source, sink, "traces", sink)
    for memory in model.components_of(ComponentKind.MEMORY):
        for source in orchestrators:
            link(source, memory, "memory read/write", memory)
    return flows


# --------------------------------------------------------------------------- controls checklist


def _controls(model: ThreatModel, signals: Signals) -> list[ControlCheck]:
    """Checklist of agent defenses (OWASP Agentic Top 10), based only on statically observed evidence.

    "present" means code evidence was found, not that the control is effective;
    "partial" means no violation was found but the control cannot be confirmed statically.
    """
    agents = model.components_of(ComponentKind.AGENT)
    tools = model.components_of(ComponentKind.TOOL)
    models = model.components_of(ComponentKind.MODEL)
    memory = model.components_of(ComponentKind.MEMORY)
    entry_points = model.components_of(ComponentKind.ENTRY_POINT)
    http_entries = [e for e in entry_points if e.attributes.get("interface", "").startswith("HTTP")]
    risky_tools = [tool for tool in tools if is_side_effecting(tool)]
    code_tools = [tool for tool in tools if _runs_code(tool)]
    remote = [c for c in (*tools, *agents) if _is_remote(c)]
    by_rule: dict[str, list[Finding]] = {}
    for finding in model.findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    def violations(*rule_ids: str) -> list[Location]:
        return [f.location for rule_id in rule_ids for f in by_rule.get(rule_id, [])][:_MAX_RELATED]

    def evidence(name: str) -> list[Location]:
        return signals.get(name, [])[:_MAX_RELATED]

    def control(
        control_id: str, name: str, asi: tuple[str, ...], applicable: bool, outcome: Outcome,
    ) -> ControlCheck:
        status, note, proof = outcome
        if not applicable:
            return ControlCheck(control_id, name, ControlStatus.NOT_APPLICABLE, list(asi),
                                "No matching components were detected.", [])
        return ControlCheck(control_id, name, status, list(asi), note, proof)

    def presence(signal: str, missing_note: str, present_note: str) -> Outcome:
        found = evidence(signal)
        return (ControlStatus.PRESENT, present_note, found) if found else (ControlStatus.MISSING, missing_note, [])

    checks: list[ControlCheck] = []

    checks.append(control(
        "CTRL-01", "Human approval before side-effecting actions", ("ASI02", "ASI09"), bool(risky_tools),
        presence(catalog.SIGNAL_HUMAN_APPROVAL,
                  f"Side-effecting tools ({_names(risky_tools)}) run without an interrupt or approval step.",
                  "Interrupts or human-in-the-loop middleware were found; confirm they cover every risky tool."),
    ))

    unbounded = violations("AITM-TOOL-006")
    limits = evidence(catalog.SIGNAL_ITERATION_LIMIT)
    if unbounded:
        limit_status = (ControlStatus.MISSING, "At least one agent loop is unbounded or has an excessive limit.", unbounded)
    elif limits:
        limit_status = (ControlStatus.PRESENT, "Explicit iteration/recursion limits were found.", limits)
    else:
        limit_status = (ControlStatus.PARTIAL, "No explicit limits; relying on framework defaults "
                        "(LangGraph recursion_limit=25, AgentExecutor max_iterations=15).", [])
    checks.append(control("CTRL-02", "Bounded agent execution (iteration / recursion limits)",
                          ("ASI08", "ASI10"), bool(agents), limit_status))

    unauthenticated = [e.location for e in http_entries if e.attributes.get("auth") == "not detected"]
    uncertain = [e.location for e in http_entries if e.attributes.get("auth") in {"unknown", "platform default"}]
    if unauthenticated:
        auth_status = (ControlStatus.MISSING, "Some HTTP entry points have no detected authentication.", unauthenticated)
    elif uncertain:
        auth_status = (ControlStatus.PARTIAL, "Authentication could not be confirmed for some entry points.", uncertain)
    else:
        auth_status = (ControlStatus.PRESENT, "Authentication was detected on every HTTP entry point.",
                       [e.location for e in http_entries][:_MAX_RELATED])
    checks.append(control("CTRL-03", "Authenticated entry points", ("ASI03",), bool(http_entries), auth_status))

    confused = violations("AITM-ID-001")
    checks.append(control(
        "CTRL-04", "Caller identity enforced inside tools", ("ASI03", "ASI02"), bool(tools),
        (ControlStatus.MISSING, "Tools accept model-chosen user/object identifiers without caller context.", confused)
        if confused else
        (ControlStatus.PARTIAL, "Every tool that takes an identifier also receives caller context; confirm it "
         "authorizes each object access.", []),
    ))

    checks.append(control(
        "CTRL-05", "Rate limiting and usage quotas", ("ASI08",), bool(http_entries and (models or agents)),
        presence(catalog.SIGNAL_RATE_LIMIT, "Network entry points have no rate limiter or quota enforcement.",
                  "A rate limiter was found."),
    ))

    audit = evidence(catalog.SIGNAL_AUDIT) + [c.location for c in model.components_of(ComponentKind.OBSERVABILITY)]
    checks.append(control(
        "CTRL-06", "Audit trail of agent decisions and tool calls", ("ASI09", "ASI10"), bool(agents or tools),
        (ControlStatus.PRESENT, "Tracing or callback handlers were found; make sure they record tool calls "
         "and are tamper-resistant.", audit[:_MAX_RELATED]) if audit else
        (ControlStatus.MISSING, "No tracing, callbacks, or audit logging of agent actions was found.", []),
    ))

    checks.append(control(
        "CTRL-07", "Prompt-injection and content guardrails", ("ASI01",), bool(models or agents),
        presence(catalog.SIGNAL_GUARDRAIL, "No input/output guardrail or moderation layer was found.",
                  "A guardrail or moderation component was found."),
    ))

    checks.append(control(
        "CTRL-08", "Structured, validated model output", ("ASI05", "ASI02"), bool(models or agents),
        presence(catalog.SIGNAL_STRUCTURED_OUTPUT, "Model output is consumed as free text; no schema validation "
                  "(with_structured_output / output parsers) was found.", "Schema-validated output parsing was found."),
    ))

    checks.append(control(
        "CTRL-09", "Sandboxed code execution", ("ASI05",), bool(code_tools),
        presence(catalog.SIGNAL_SANDBOX, f"Tools that execute code or commands ({_names(code_tools)}) run in the "
                  "application process.", "A sandbox library was found; confirm the code-running tools use it."),
    ))

    supply = violations("AITM-SUP-001", "AITM-SUP-002")
    checks.append(control(
        "CTRL-10", "Pinned agent supply chain (packages, prompts, MCP servers)", ("ASI04",), bool(model.components),
        (ControlStatus.MISSING, "Unpinned dependencies, prompts, or MCP servers were found.", supply) if supply else
        (ControlStatus.PRESENT, "No unpinned AI dependencies, hub prompts, or MCP launchers were found.", []),
    ))

    insecure = violations("AITM-MA-001", "AITM-MA-002")
    checks.append(control(
        "CTRL-11", "Secured inter-agent and MCP channels", ("ASI07",), bool(remote or is_multi_agent(signals)),
        (ControlStatus.MISSING, "Insecure, unauthenticated, or over-privileged agent-to-agent channels were found.",
         insecure) if insecure else
        (ControlStatus.PARTIAL, "No insecure channel found; confirm remote agents and MCP servers are authenticated "
         "and their messages validated.", [c.location for c in remote][:_MAX_RELATED]),
    ))

    poisoned = violations("AITM-MEM-001", "AITM-MEM-002")
    checks.append(control(
        "CTRL-12", "Memory isolation and write validation", ("ASI06",), bool(memory or poisoned),
        (ControlStatus.MISSING, "Untrusted data is written to memory, or memory scope is caller-controlled.", poisoned)
        if poisoned else
        (ControlStatus.PARTIAL, "No unsafe memory writes found; confirm memory is namespaced per user and expires.",
         [c.location for c in memory][:_MAX_RELATED]),
    ))
    return checks


def _runs_code(tool: Component) -> bool:
    """True for tools that execute code or shell commands (built-in or detected via data flow)."""
    capabilities = tool.attributes.get("capabilities", "")
    return (
        any(marker in capabilities for marker in _CODE_EXECUTION_MARKERS)
        or tool.name in _CODE_RUNNING_LOAD_TOOLS
    )
