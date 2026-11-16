"""AST analysis of a single Python file in a LangChain / LangGraph application.

The analyzer parses source code with :mod:`ast`; it never imports or executes
the target application. It produces two kinds of results:

* **Components** – entry points, models, tools, retrieval sources, agents, and
  graph nodes, each tied to a file and line.
* **Findings** – risks such as prompt injection, unsafe tool use, improper
  output handling, and sensitive-data exposure.

Data flow
---------
Within each function (and at module level) variables are labelled with the
kinds of untrusted or sensitive data they may hold, and labels propagate
through assignments until a fixed point is reached.

Every place where labelled data can cause harm is described as a
:class:`_Flow` (a shell call, a prompt, a log statement, ...). The same flow
detection is used twice:

* while building :mod:`interprocedural <ai_threat_model.interprocedural>`
  summaries, parameters carry symbolic labels so the analyzer learns which
  parameters reach which sinks; and
* while reporting, concrete labels (user input, model output, tool arguments,
  secrets, personal data) are turned into findings. Calls into other project
  functions produce flows from those functions' summaries, so data that
  crosses helper functions and files is still traced to its sink.

Typical project-level usage (see :mod:`ai_threat_model.engine`)::

    registry = SummaryRegistry()
    analyzers = [PythonFileAnalyzer(path, source, registry) for ...]
    for analyzer in analyzers: analyzer.prepare()
    while any(analyzer.update_summaries() for analyzer in analyzers): pass
    results = [analyzer.analyze() for analyzer in analyzers]
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable, Iterator
from urllib.parse import urlparse

from . import agentic, catalog
from .catalog import SinkKind
from .interprocedural import (
    FunctionSummary,
    SinkRef,
    SummaryRegistry,
    module_names,
    parameter_label,
    split_labels,
    summary_keys,
)
from .models import Component, ComponentKind, Finding, Location, Severity
from .rules import make_finding
from .sensitive import find_token, is_pii_name, is_secret_name, looks_like_secret_value, mask, redact

LOGGER = logging.getLogger(__name__)

# Data labels used by the taint tracker.
USER_INPUT = "user input"
MODEL_OUTPUT = "model output"
TOOL_ARGUMENT = "model-controlled tool argument"
SECRET = "secret"
PII = "personal data"
EXTERNAL_CONTENT = "external web content"
UNTRUSTED_LABELS = frozenset({USER_INPUT, MODEL_OUTPUT, TOOL_ARGUMENT, EXTERNAL_CONTENT})
# Labels that let a caller or the model pick *whose* memory is used.
_SCOPE_CONTROL_LABELS = frozenset({USER_INPUT, MODEL_OUTPUT, TOOL_ARGUMENT})
_MODEL_DRIVEN_LABELS = frozenset({MODEL_OUTPUT, TOOL_ARGUMENT, EXTERNAL_CONTENT})

# Flow kinds in addition to the dangerous-sink kinds in ``catalog.SinkKind``.
PROMPT_FORMAT = "prompt formatting"
SYSTEM_PROMPT = "system prompt"
PROMPT_TEMPLATE = "prompt template"
JINJA_TEMPLATE = "jinja2 prompt template"
MODEL_INPUT = "model input"
LOG_OUTPUT = "log output"
MARKUP_RENDER = "markup rendering"
MEMORY_WRITE = "memory write"
MEMORY_SCOPE = "memory scope"
_DANGEROUS_SINK_KINDS = frozenset(kind.value for kind in SinkKind)

_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)
_SCOPE_BOUNDARIES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
_MAX_TAINT_PASSES = 6
_SNIPPET_LENGTH = 200

_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "log"})
# ``.run()``/``.invoke()``-style calls on these are not model invocations. Modules are
# matched after import resolution; variables only when they are local (not imported),
# so ``from app.agent import llm; llm.invoke()`` is still treated as a model call.
_NON_MODEL_MODULES = frozenset({"subprocess", "asyncio", "os", "sys", "threading", "multiprocessing", "uvicorn"})
_NON_MODEL_VARIABLES = frozenset({"app"})
_TOOL_FRAMEWORK_PARAMETERS = frozenset({"self", "cls", "run_manager", "config", "callbacks", "runtime", "state", "store"})
_LOOPBACK_HOSTS = agentic.LOOPBACK_HOSTS
_REMOTE_AUTH_KWARGS = ("api_key", "headers", "auth", "client", "sync_client", "credentials")
_HTML_SINKS = frozenset({"Markup", "mark_safe", "HTMLResponse", "render_template_string", "Template"})
_HTML_SINK_MODULES = ("markupsafe", "flask", "django", "fastapi", "starlette", "jinja2")
_CREDENTIAL_IN_TEXT = re.compile(
    r"(?i)\b(password|passwd|api[_ -]?key|secret|token|credential)s?\b\s*(?:is|:|=)\s*\S{4,}"
)

Taint = dict[str, set[str]]


# --------------------------------------------------------------------------- helpers


def _walk_scope(node: ast.AST) -> Iterator[ast.AST]:
    """Yield descendants of ``node`` without entering nested functions or classes."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        yield child
        if not isinstance(child, _SCOPE_BOUNDARIES):
            stack.extend(ast.iter_child_nodes(child))


def _dotted(node: ast.AST) -> str | None:
    """Return ``a.b.c`` for Name/Attribute chains, otherwise ``None``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _constant_str(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _is_true(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and node.value is True


def _keyword(call: ast.Call, *names: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg in names:
            return keyword.value
    return None


def _argument(call: ast.Call, position: int, *names: str) -> ast.expr | None:
    """Return a call argument by position or keyword name."""
    if len(call.args) > position and not isinstance(call.args[position], ast.Starred):
        return call.args[position]
    return _keyword(call, *names)


def _all_arguments(call: ast.Call) -> list[ast.expr]:
    return [*call.args, *(keyword.value for keyword in call.keywords)]


def _target_names(target: ast.AST) -> Iterator[str]:
    """Yield variable names bound by an assignment target."""
    if isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            yield from _target_names(element)
    elif isinstance(target, ast.Starred):
        yield from _target_names(target.value)
    else:
        dotted = _dotted(target)
        if dotted:
            yield dotted


def _is_dynamic_string(node: ast.AST) -> bool:
    """True for f-strings, ``+``/``%`` string building, and ``"...".format()``."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(
            _constant_str(side) is not None or isinstance(side, ast.JoinedStr)
            for side in (node.left, node.right)
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return _constant_str(node.func.value) is not None
    return False


def _literal_text(node: ast.AST | None) -> str:
    """Concatenate the constant parts of a string or f-string."""
    if node is None:
        return ""
    if isinstance(node, ast.JoinedStr):
        return "".join(_constant_str(value) or "" for value in node.values)
    return _constant_str(node) or ""


def _short_source(node: ast.AST, limit: int = 120) -> str:
    try:
        text = ast.unparse(node)
    except (ValueError, TypeError, AttributeError, RecursionError):
        return "<expression>"
    return redact(text if len(text) <= limit else text[: limit - 1] + "…")


def _describe_labels(labels: Iterable[str]) -> str:
    return ", ".join(sorted(labels))


def _is_injected(arg: ast.arg) -> bool:
    """True if the parameter is hidden from the model and injected by the framework."""
    if arg.annotation is None:
        return False
    text = _short_source(arg.annotation, 400)
    return any(hint in text for hint in catalog.INJECTED_ANNOTATION_HINTS)


def _looks_authenticated(node: ast.AST | None) -> bool:
    """True if an expression appears to come from an authenticated identity (heuristic)."""
    if node is None:
        return False
    text = _short_source(node, 400).lower()
    return any(hint in text for hint in catalog.AUTHENTICATED_IDENTITY_HINTS)


# --------------------------------------------------------------------------- results


@dataclass
class FileAnalysis:
    """Everything learned from one Python file."""

    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    # Evidence of agent controls, keyed by ``catalog.SIGNAL_*`` (human approval, limits, ...).
    signals: dict[str, list[Location]] = field(default_factory=dict)


@dataclass
class _ScopeContext:
    """Information about the function (or module) currently being analyzed."""

    name: str
    tool: Component | None = None
    capabilities: set[str] = field(default_factory=set)


@dataclass(frozen=True)
class _Flow:
    """Labelled data reaching a sensitive operation.

    ``via`` is empty for direct flows and names the project function (and
    parameter) for interprocedural flows; ``sink`` is where the operation is.
    """

    kind: str
    callee: str
    labels: frozenset[str]
    sink: Location
    via: str = ""


# --------------------------------------------------------------------------- analyzer


class PythonFileAnalyzer:
    """Analyze one Python source file. Create a new instance per file.

    Pass a shared :class:`SummaryRegistry` to enable interprocedural analysis
    across files; without one, flows are still followed through functions
    defined in the same file.
    """

    def __init__(self, relative_path: str, source: str, registry: SummaryRegistry | None = None) -> None:
        self._path = relative_path
        self._source = source
        self._lines = source.splitlines()
        self._imports: dict[str, str] = {}
        self._result = FileAnalysis()
        self._has_global_auth = False
        self._registry = registry if registry is not None else SummaryRegistry()
        self._module_names = module_names(relative_path) or ["__main__"]
        self._is_package = PurePosixPath(relative_path).stem == "__init__"
        self._tree: ast.Module | None = None
        self._functions: list[tuple[ast.FunctionDef | ast.AsyncFunctionDef, str | None]] = []
        self._summaries: dict[int, FunctionSummary] = {}
        self._class_of: dict[int, str | None] = {}
        self._active_class: str | None = None
        self._analyzed = False
        self._dependencies: set[str] = set()

    @property
    def path(self) -> str:
        """Scan-root-relative path of the analyzed file."""
        return self._path

    @property
    def dependencies(self) -> frozenset[str]:
        """Other project files whose function summaries this file's analysis used."""
        return frozenset(self._dependencies)

    @property
    def summaries(self) -> list[FunctionSummary]:
        """Summaries of the functions defined in this file, in definition order."""
        return [self._summaries[id(func)] for func, _ in self._functions]

    def prepare(self) -> None:
        """Parse the file, resolve imports, and register function summaries.

        Raises:
            SyntaxError, ValueError, RecursionError: If the file cannot be parsed.
                The caller records these as non-fatal scan errors.
        """
        if self._tree is not None:
            return
        tree = ast.parse(self._source, filename=self._path)
        self._collect_imports(tree)
        self._has_global_auth = self._detect_global_auth(tree)
        self._register_functions(tree)
        self._tree = tree

    def update_summaries(self) -> bool:
        """Recompute this file's function summaries; return True if any changed."""
        self.prepare()
        changed = False
        for func, class_name in self._functions:
            self._active_class = class_name
            try:
                changed |= self._summarize(func, self._summaries[id(func)])
            finally:
                self._active_class = None
        return changed

    def analyze(self) -> FileAnalysis:
        """Build the inventory and findings for this file (idempotent)."""
        if self._analyzed:
            return self._result
        self.prepare()
        tree = self._tree
        assert tree is not None  # guaranteed by prepare()
        tool_methods = self._collect_tool_classes(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._inspect_call(node)
            elif isinstance(node, ast.Dict):
                self._inspect_config_dict(node)
        self._scan_hardcoded_secrets(tree)

        self._analyze_scope(tree, _ScopeContext(name="<module>"), {})
        for node in ast.walk(tree):
            if isinstance(node, _FUNCTION_NODES):
                self._active_class = self._class_of.get(id(node))
                try:
                    self._analyze_function(node, tool_methods.get(id(node)))
                finally:
                    self._active_class = None

        self._detect_main_guard(tree)
        self._analyzed = True
        return self._result

    # ------------------------------------------------------------------ function registry

    def _register_functions(self, tree: ast.Module) -> None:
        """Register top-level functions and methods for interprocedural lookup."""

        def visit(body: list[ast.stmt], prefix: str, class_name: str | None) -> None:
            for statement in body:
                if isinstance(statement, _FUNCTION_NODES):
                    name = f"{prefix}{statement.name}"
                    parameters, positional_count = self._parameters(statement)
                    summary = FunctionSummary(
                        key=f"{self._module_names[0]}.{name}",
                        name=name,
                        location=self._location(statement),
                        parameters=parameters,
                        positional_count=positional_count,
                    )
                    self._functions.append((statement, class_name))
                    self._summaries[id(statement)] = summary
                    self._class_of[id(statement)] = class_name
                    self._registry.register(summary_keys(self._path, name), summary)
                elif isinstance(statement, ast.ClassDef):
                    visit(statement.body, f"{prefix}{statement.name}.", statement.name)

        visit(tree.body, "", None)

    @staticmethod
    def _parameters(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[tuple[str, ...], int]:
        """Return parameter names (without self/cls) and how many are positional."""
        positional = [arg.arg for arg in (*func.args.posonlyargs, *func.args.args) if arg.arg not in {"self", "cls"}]
        keyword_only = [arg.arg for arg in func.args.kwonlyargs]
        return tuple(positional + keyword_only), len(positional)

    def _resolve_relative(self, qualified: str) -> str:
        """Turn ``..pkg.func`` (relative import) into an absolute dotted path."""
        if not qualified.startswith("."):
            return qualified
        level = len(qualified) - len(qualified.lstrip("."))
        package = self._module_names[0].split(".")
        if not self._is_package:
            package = package[:-1]
        package = package[: len(package) - (level - 1)] if level > 1 else package
        return ".".join([*package, qualified.lstrip(".")])

    def _resolve_summary(self, call: ast.Call) -> FunctionSummary | None:
        """Find the summary of the project function a call targets, if any."""
        func = call.func
        candidates: list[str] = []
        if isinstance(func, ast.Name):
            candidates.append(f"{self._module_names[0]}.{func.id}")
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in {"self", "cls"}
            and self._active_class
        ):
            candidates.append(f"{self._module_names[0]}.{self._active_class}.{func.attr}")
        qualified = self._qualified(func)
        if qualified:
            candidates.append(self._resolve_relative(qualified))
        for key in candidates:
            summary = self._registry.get(key)
            if summary is not None:
                if summary.location.file != self._path:
                    self._dependencies.add(summary.location.file)
                return summary
        return None

    @staticmethod
    def _map_arguments(call: ast.Call, summary: FunctionSummary) -> Iterator[tuple[str, ast.expr]]:
        """Pair call arguments with the callee's parameter names."""
        for index, argument in enumerate(call.args):
            if isinstance(argument, ast.Starred) or index >= summary.positional_count:
                break
            yield summary.parameters[index], argument
        for keyword in call.keywords:
            if keyword.arg in summary.parameters:
                yield keyword.arg, keyword.value

    def _summarize(self, func: ast.FunctionDef | ast.AsyncFunctionDef, summary: FunctionSummary) -> bool:
        """Analyze ``func`` with symbolic parameter labels and merge into ``summary``."""
        taint: Taint = {name: {parameter_label(name)} for name in summary.parameters}
        nodes = list(_walk_scope(func))
        self._propagate_taint(nodes, taint)

        return_labels: set[str] = set()
        returns_parameters: set[str] = set()
        parameter_sinks: dict[str, set[SinkRef]] = {}
        reachable: set[SinkRef] = set()
        for node in nodes:
            if isinstance(node, ast.Return) and node.value is not None:
                concrete, parameters = split_labels(self._labels(node.value, taint))
                return_labels |= concrete
                returns_parameters |= parameters
            for flow in self._flows_at(node, taint):
                ref = SinkRef(flow.kind, flow.callee, flow.sink)
                if flow.kind in _DANGEROUS_SINK_KINDS:
                    reachable.add(ref)
                for parameter in split_labels(flow.labels)[1]:
                    parameter_sinks.setdefault(parameter, set()).add(ref)
        return summary.update(return_labels, returns_parameters, parameter_sinks, reachable)

    # ------------------------------------------------------------------ utilities

    def _location(self, node: ast.AST) -> Location:
        line = getattr(node, "lineno", 1) or 1
        snippet = self._lines[line - 1].strip() if 0 < line <= len(self._lines) else ""
        return Location(file=self._path, line=line, snippet=redact(snippet)[:_SNIPPET_LENGTH])

    def _qualified(self, node: ast.AST) -> str:
        """Resolve a Name/Attribute chain through the file's imports."""
        dotted = _dotted(node)
        if not dotted:
            return ""
        head, _, rest = dotted.partition(".")
        resolved = self._imports.get(head, head)
        return f"{resolved}.{rest}" if rest else resolved

    def _callee(self, call: ast.Call) -> tuple[str, str, str | None]:
        """Return ``(qualified_name, simple_name, method_name)`` for a call."""
        qualified = self._qualified(call.func)
        method = call.func.attr if isinstance(call.func, ast.Attribute) else None
        simple = qualified.rsplit(".", 1)[-1] if qualified else (method or "")
        return qualified, simple, method

    def _add_component(
        self, kind: ComponentKind, name: str, node: ast.AST, qualified: str = "", **attributes: str
    ) -> Component:
        component = Component(
            kind=kind,
            name=redact(name)[:120],
            location=self._location(node),
            qualified_name=qualified,
            attributes={key: redact(str(value)) for key, value in attributes.items()},
        )
        self._result.components.append(component)
        return component

    def _add_finding(self, rule_id: str, node: ast.AST, description: str, **kwargs: object) -> None:
        self._result.findings.append(make_finding(rule_id, self._location(node), description, **kwargs))

    def _add_signal(self, name: str, node: ast.AST) -> None:
        """Record evidence that an agent control (``catalog.SIGNAL_*``) is present."""
        self._result.signals.setdefault(name, []).append(self._location(node))

    # ------------------------------------------------------------------ imports

    def _collect_imports(self, tree: ast.Module) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.asname:
                        self._imports[alias.asname] = alias.name
                    else:
                        head = alias.name.split(".")[0]
                        self._imports[head] = head
                    self._note_framework(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                self._note_framework(module)
                for alias in node.names:
                    if alias.name != "*":
                        self._imports[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name

    def _note_framework(self, module: str) -> None:
        framework = catalog.framework_of(module)
        if framework:
            self._result.frameworks.add(framework)

    # ------------------------------------------------------------------ inventory: calls

    def _inspect_call(self, call: ast.Call) -> None:
        qualified, simple, method = self._callee(call)
        self._check_dangerous_flags(call, qualified or simple)
        if catalog.is_ai_framework(qualified):
            self._inspect_framework_call(call, qualified, simple)
        if method and "LangGraph" in self._result.frameworks:
            self._inspect_graph_method(call, method)
        if method == "as_retriever":
            store = _dotted(call.func.value) or "vector store"  # type: ignore[union-attr]
            self._add_component(ComponentKind.RETRIEVAL, f"{store}.as_retriever()", call, trust="vector store")
        self._inspect_entry_point_call(call, qualified, simple)
        self._inspect_remote_channel_call(call, qualified, simple)
        self._record_control_signals(call, qualified, simple, method)
        if method == "pull_prompt":
            self._check_hub_pull(call)

    def _check_dangerous_flags(self, call: ast.Call, callee: str) -> None:
        for keyword in call.keywords:
            if keyword.arg in catalog.HUMAN_APPROVAL_KWARGS:
                self._add_signal(catalog.SIGNAL_HUMAN_APPROVAL, call)
            elif keyword.arg in catalog.ITERATION_LIMIT_KWARGS:
                self._check_iteration_limit(call, keyword.arg, keyword.value)
            elif keyword.arg == "callbacks":
                self._add_signal(catalog.SIGNAL_AUDIT, call)
            elif keyword.arg == "rate_limiter":
                self._add_signal(catalog.SIGNAL_RATE_LIMIT, call)
            elif keyword.arg == "response_format":
                self._add_signal(catalog.SIGNAL_STRUCTURED_OUTPUT, call)
            if keyword.arg in catalog.DANGEROUS_FLAGS and _is_true(keyword.value):
                self._add_finding(
                    "AITM-TOOL-004",
                    call,
                    f"`{keyword.arg}=True` disables a built-in safety guard in `{callee}`.",
                    severity=catalog.DANGEROUS_FLAGS[keyword.arg],
                    confidence="high",
                )

    def _check_iteration_limit(self, node: ast.AST, name: str, value: ast.AST | None) -> None:
        """Record an iteration/recursion limit and flag limits too large to stop a runaway agent."""
        if isinstance(value, ast.Constant) and value.value is None:
            return  # ``max_iterations=None`` is reported by the AgentExecutor check
        self._add_signal(catalog.SIGNAL_ITERATION_LIMIT, node)
        limit = value.value if isinstance(value, ast.Constant) else None
        if name == "recursion_limit" and isinstance(limit, int) and limit >= catalog.UNBOUNDED_RECURSION_LIMIT:
            self._add_finding(
                "AITM-TOOL-006", node,
                f"`recursion_limit={limit}` effectively removes the LangGraph step limit, so a hijacked or looping "
                "agent can run (and spend) for a very long time.",
                confidence="high",
            )

    def _inspect_config_dict(self, node: ast.Dict) -> None:
        """Signals from RunnableConfig-style dicts: ``{"recursion_limit": 10, "callbacks": [...]}``."""
        for key, value in zip(node.keys, node.values):
            name = _constant_str(key)
            if name in catalog.ITERATION_LIMIT_KWARGS:
                self._check_iteration_limit(node, name, value)
            elif name == "callbacks":
                self._add_signal(catalog.SIGNAL_AUDIT, node)

    def _record_control_signals(self, call: ast.Call, qualified: str, simple: str, method: str | None) -> None:
        """Note guardrails, rate limits, audit hooks, sandboxes, and output validation."""
        lowered = qualified.lower()
        receiver = (_dotted(call.func.value) or "").lower() if isinstance(call.func, ast.Attribute) else ""
        if simple in catalog.RATE_LIMIT_NAMES or qualified.startswith(catalog.RATE_LIMIT_MODULES) or (
            method == "limit" and "limit" in receiver
        ):
            self._add_signal(catalog.SIGNAL_RATE_LIMIT, call)
        if simple in catalog.AUDIT_NAMES or qualified.startswith(catalog.AUDIT_MODULES):
            self._add_signal(catalog.SIGNAL_AUDIT, call)
        if qualified.startswith(catalog.GUARDRAIL_MODULES) or any(
            hint in simple.lower() for hint in catalog.GUARDRAIL_NAME_HINTS
        ):
            self._add_signal(catalog.SIGNAL_GUARDRAIL, call)
        if simple in catalog.STRUCTURED_OUTPUT_NAMES or method in catalog.STRUCTURED_OUTPUT_NAMES:
            self._add_signal(catalog.SIGNAL_STRUCTURED_OUTPUT, call)
        if qualified.startswith(catalog.SANDBOX_MODULES) or "sandbox" in lowered:
            self._add_signal(catalog.SIGNAL_SANDBOX, call)

    def _inspect_remote_channel_call(self, call: ast.Call, qualified: str, simple: str) -> None:
        """MCP transports and A2A clients from non-LangChain packages."""
        if qualified.startswith("mcp") and simple in catalog.MCP_TRANSPORT_FUNCTIONS:
            url = _constant_str(_argument(call, 0, "url"))
            self._add_component(ComponentKind.TOOL, f"MCP server ({simple})", call, qualified,
                                source="MCP", transport=simple, endpoint=url or "dynamic")
            self._report_channel(call, f"MCP client `{simple}`", url, _keyword(call, "headers", "auth") is not None)
        elif qualified.startswith("mcp") and simple == "StdioServerParameters":
            command = _constant_str(_keyword(call, "command"))
            args_node = _keyword(call, "args")
            args = [value for element in getattr(args_node, "elts", []) if (value := _constant_str(element))]
            self._add_component(ComponentKind.TOOL, f"MCP server ({command or 'stdio'})", call, qualified,
                                source="MCP", transport="stdio", endpoint=" ".join([command or "", *args])[:120])
            self._report_unpinned_package(call, "MCP server", command, args)
        elif qualified.startswith("a2a") and simple in catalog.A2A_CLIENT_CLASSES:
            url = _constant_str(_keyword(call, "url", "base_url"))
            self._add_component(ComponentKind.AGENT, f"A2A remote agent ({url or 'dynamic'})", call, qualified,
                                factory=simple, remote="yes")
            self._add_signal(catalog.SIGNAL_MULTI_AGENT, call)
            self._report_channel(call, f"A2A client `{simple}`", url, _keyword(call, "httpx_client", "auth") is not None)

    def _report_channel(self, node: ast.AST, what: str, url: str | None, has_auth: bool) -> None:
        issue = agentic.channel_issue(what, url, has_auth=has_auth)
        if issue is not None:
            self._add_finding("AITM-MA-001", node, issue.description,
                              severity=issue.severity, confidence=issue.confidence)

    def _report_unpinned_package(self, node: ast.AST, what: str, command: str | None, args: list[str]) -> None:
        package = agentic.unpinned_package(command, args)
        if package:
            self._add_finding(
                "AITM-SUP-002", node,
                f"{what} is launched with `{command} {package}` without a version pin, so the agent runs whatever "
                "code and tool descriptions the registry serves at start-up.",
                confidence="high",
            )

    def _inspect_framework_call(self, call: ast.Call, qualified: str, simple: str) -> None:
        parts = qualified.split(".")

        if catalog.is_model_class(simple):
            self._record_model(call, qualified, simple)

        if simple in catalog.DANGEROUS_TOOLS:
            severity, reason = catalog.DANGEROUS_TOOLS[simple]
            self._add_component(ComponentKind.TOOL, simple, call, qualified, capabilities=reason, dangerous="yes")
            self._add_finding(
                "AITM-TOOL-001", call, f"`{simple}` gives the model {reason}.", severity=severity, confidence="high"
            )
        elif simple == "load_tools":
            self._record_load_tools(call)
        elif simple in {"Tool", "StructuredTool", "from_function"} and {"Tool", "StructuredTool"} & set(parts + [simple]):
            name = _constant_str(_argument(call, 0, "name")) or _short_source(_keyword(call, "func") or call.func, 60)
            self._add_component(ComponentKind.TOOL, name, call, qualified, source=simple)

        self._record_retrieval(call, qualified, simple, parts)

        if simple in catalog.AGENT_FACTORIES:
            tools = _argument(call, 1, "tools") if simple in {"create_react_agent", "create_agent"} else _keyword(call, "tools")
            self._add_component(
                ComponentKind.AGENT, simple, call, qualified,
                factory=simple, tools=_short_source(tools) if tools is not None else "",
            )
            max_iterations = _keyword(call, "max_iterations")
            if simple == "AgentExecutor" and isinstance(max_iterations, ast.Constant) and max_iterations.value is None:
                self._add_finding("AITM-TOOL-006", call, "`AgentExecutor(max_iterations=None)` allows an unbounded tool loop.")

        if simple in catalog.HUMAN_APPROVAL_CALLS:
            self._add_signal(catalog.SIGNAL_HUMAN_APPROVAL, call)
        if simple in catalog.MULTI_AGENT_FACTORIES:
            self._add_signal(catalog.SIGNAL_MULTI_AGENT, call)
        if simple in catalog.MEMORY_CLASSES:
            self._add_component(ComponentKind.MEMORY, simple, call, qualified, scope=catalog.MEMORY_CLASSES[simple])
        self._inspect_agentic_framework_call(call, qualified, simple)

        if simple in {"set_debug", "set_verbose"} and call.args and _is_true(call.args[0]):
            self._add_finding(
                "AITM-DATA-003", call,
                f"`{simple}(True)` prints full prompts, tool arguments, and responses to stdout/logs.",
                confidence="high",
            )
        elif _is_true(_keyword(call, "verbose")):
            self._add_finding(
                "AITM-DATA-003", call,
                f"`{simple}(verbose=True)` logs prompts and intermediate steps.", severity=Severity.INFO,
            )

        if _constant_str(_keyword(call, "template_format")) == "jinja2":
            self._add_finding("AITM-PI-004", call, f"`{simple}` uses `template_format=\"jinja2\"`.", confidence="high")

        if simple == "add_routes" and qualified.startswith("langserve"):
            path = _constant_str(_argument(call, 2, "path")) or "/"
            self._add_component(
                ComponentKind.ENTRY_POINT, f"LangServe {path}", call, qualified,
                interface="HTTP (LangServe)", auth="detected" if self._has_global_auth else "unknown",
            )

    def _inspect_agentic_framework_call(self, call: ast.Call, qualified: str, simple: str) -> None:
        """Remote agents, MCP clients, and Prompt Hub pulls (ASI04 / ASI07)."""
        if simple == "RemoteGraph" or (qualified.startswith("langgraph_sdk") and simple in {"get_client", "get_sync_client"}):
            url = _constant_str(_keyword(call, "url"))
            has_auth = _keyword(call, *_REMOTE_AUTH_KWARGS) is not None
            if simple != "RemoteGraph":
                self._add_signal(catalog.SIGNAL_MULTI_AGENT, call)
            self._report_channel(call, f"Remote LangGraph agent (`{simple}`)", url, has_auth)
        elif simple in catalog.MCP_CLIENT_CLASSES:
            self._record_mcp_client(call, qualified)
        elif simple == "pull" and qualified.endswith("hub.pull"):
            self._check_hub_pull(call)

    def _check_hub_pull(self, call: ast.Call) -> None:
        """``hub.pull("owner/prompt")`` / ``client.pull_prompt(...)`` without a commit pin."""
        reference = _constant_str(_argument(call, 0, "owner_repo_commit", "prompt_identifier"))
        if reference and not agentic.is_pinned_hub_reference(reference):
            self._add_finding(
                "AITM-SUP-002", call,
                f"Prompt `{reference}` is pulled from a hub at runtime without a commit pin; whoever can "
                "update it can rewrite the agent's instructions.",
                confidence="high",
            )

    def _record_mcp_client(self, call: ast.Call, qualified: str) -> None:
        """Inventory each server in ``MultiServerMCPClient({...})`` and check its transport."""
        connections = _argument(call, 0, "connections")
        if not isinstance(connections, ast.Dict):
            self._add_component(ComponentKind.TOOL, "MCP servers (dynamic config)", call, qualified, source="MCP")
            return
        for key, value in zip(connections.keys, connections.values):
            name = _constant_str(key) or "server"
            settings = {
                setting: item for k, item in zip(getattr(value, "keys", []), getattr(value, "values", []))
                if (setting := _constant_str(k)) is not None
            }
            url = _constant_str(settings.get("url"))
            command = _constant_str(settings.get("command"))
            args = [text for element in getattr(settings.get("args"), "elts", []) if (text := _constant_str(element))]
            transport = _constant_str(settings.get("transport")) or ("stdio" if command else "http")
            endpoint = url or " ".join([command or "", *args]).strip() or "dynamic"
            self._add_component(ComponentKind.TOOL, f"MCP server '{name}'", value, qualified,
                                source="MCP", transport=transport, endpoint=endpoint[:120])
            has_auth = any(k in settings for k in ("headers", "auth"))
            self._report_channel(value, f"MCP server `{name}`", url, has_auth)
            self._report_unpinned_package(value, f"MCP server `{name}`", command, args)

    def _record_model(self, call: ast.Call, qualified: str, simple: str) -> None:
        model_name = _constant_str(
            _keyword(call, "model", "model_name", "model_id", "deployment_name", "azure_deployment", "repo_id")
        ) or _constant_str(_argument(call, 0))
        hint = qualified
        if simple == "init_chat_model":
            hint = _constant_str(_keyword(call, "model_provider")) or (model_name or "").split(":")[0]
        provider, local = catalog.provider_for(hint)
        base_url = _constant_str(_keyword(call, "base_url", "openai_api_base", "endpoint", "azure_endpoint")) or ""
        if base_url:
            try:
                local = (urlparse(base_url).hostname or "") in _LOOPBACK_HOSTS
            except ValueError:
                LOGGER.debug("Unparseable base_url in %s", self._path)
        self._add_component(
            ComponentKind.MODEL, model_name or simple, call, qualified,
            provider=provider, local="yes" if local else "no", base_url=base_url,
        )

    def _record_load_tools(self, call: ast.Call) -> None:
        names_node = _argument(call, 0, "tool_names")
        names = [
            value for element in getattr(names_node, "elts", [])
            if (value := _constant_str(element)) is not None
        ]
        for name in names:
            self._add_component(ComponentKind.TOOL, name, call, "load_tools", source="load_tools")
        dangerous = sorted(set(names) & catalog.DANGEROUS_LOAD_TOOLS)
        if dangerous:
            self._add_finding(
                "AITM-TOOL-001", call,
                f"`load_tools` enables high-risk tools: {', '.join(dangerous)}.", confidence="high",
            )

    def _record_retrieval(self, call: ast.Call, qualified: str, simple: str, parts: list[str]) -> None:
        web_source = next((part for part in parts if part in catalog.WEB_CONTENT_SOURCES), None)
        vector_store = next((part for part in parts if part in catalog.VECTOR_STORES), None)
        database = next((part for part in parts if part in catalog.DATABASE_SOURCES), None)
        if web_source:
            self._add_component(ComponentKind.RETRIEVAL, web_source, call, qualified, trust="untrusted external content")
        elif vector_store:
            self._add_component(ComponentKind.RETRIEVAL, vector_store, call, qualified, trust="vector store")
        elif database:
            self._add_component(ComponentKind.RETRIEVAL, database, call, qualified, trust="database")
        elif simple.endswith(("Loader", "Retriever")):
            self._add_component(ComponentKind.RETRIEVAL, simple, call, qualified, trust="documents")

    def _inspect_graph_method(self, call: ast.Call, method: str) -> None:
        if method == "add_node" and call.args:
            name = _constant_str(call.args[0]) or _short_source(call.args[0], 60)
            target = _short_source(call.args[1], 60) if len(call.args) > 1 else name
            self._add_component(ComponentKind.GRAPH_NODE, name, call, target=target)

    def _inspect_entry_point_call(self, call: ast.Call, qualified: str, simple: str) -> None:
        if qualified.startswith("streamlit.") and simple in catalog.STREAMLIT_INPUTS:
            self._add_component(ComponentKind.ENTRY_POINT, f"st.{simple}", call, qualified, interface="Streamlit UI", auth="unknown")
        elif qualified.startswith("gradio.") and simple in catalog.GRADIO_INTERFACES:
            self._add_component(ComponentKind.ENTRY_POINT, f"gradio.{simple}", call, qualified, interface="Gradio UI", auth="unknown")
        elif qualified in {"input", "builtins.input"} and self._result.frameworks:
            self._add_component(ComponentKind.ENTRY_POINT, "input()", call, qualified, interface="console", auth="local user")

    # ------------------------------------------------------------------ inventory: definitions

    def _collect_tool_classes(self, tree: ast.Module) -> dict[int, Component]:
        """Register ``BaseTool`` subclasses; map their ``_run`` methods to the tool."""
        methods: dict[int, Component] = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(self._qualified(base).rsplit(".", 1)[-1] == "BaseTool" for base in node.bases):
                continue
            name = node.name
            for statement in node.body:
                target = statement.targets[0] if isinstance(statement, ast.Assign) else getattr(statement, "target", None)
                if isinstance(target, ast.Name) and target.id == "name":
                    name = _constant_str(getattr(statement, "value", None)) or name
            component = self._add_component(ComponentKind.TOOL, name, node, node.name, source="BaseTool subclass")
            for statement in node.body:
                if isinstance(statement, _FUNCTION_NODES) and statement.name in {"_run", "_arun"}:
                    methods[id(statement)] = component
        return methods

    def _tool_from_decorators(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> Component | None:
        for decorator in func.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            qualified = self._qualified(target)
            if qualified.rsplit(".", 1)[-1] == "tool" and catalog.is_ai_framework(qualified):
                name = func.name
                if isinstance(decorator, ast.Call):
                    name = _constant_str(_argument(decorator, 0, "name_or_callable")) or name
                return self._add_component(ComponentKind.TOOL, name, func, qualified, source="@tool", function=func.name)
        return None

    def _entry_point_from_decorators(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> Component | None:
        for decorator in func.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if not isinstance(target, ast.Attribute):
                continue
            method = target.attr
            if method in catalog.HTTP_ROUTE_DECORATORS and isinstance(decorator, ast.Call):
                route = _constant_str(_argument(decorator, 0, "path", "rule")) or "?"
                methods = _keyword(decorator, "methods")
                verb = method.upper() if method not in {"route", "api_route"} else (
                    _short_source(methods, 40) if methods is not None else "GET"
                )
                return self._add_component(
                    ComponentKind.ENTRY_POINT, f"{verb} {route}", func, func.name,
                    interface="HTTP", auth=self._detect_route_auth(func, decorator), handler=func.name,
                )
            if method in catalog.CHAT_UI_HANDLERS:
                return self._add_component(
                    ComponentKind.ENTRY_POINT, f"chainlit.{method}", func, func.name,
                    interface="Chat UI", auth="unknown", handler=func.name,
                )
            if method == "command" and self._qualified(target).startswith(("click", "typer")):
                return self._add_component(
                    ComponentKind.ENTRY_POINT, f"cli {func.name}", func, func.name,
                    interface="CLI", auth="local user", handler=func.name,
                )
        return None

    def _detect_route_auth(self, func: ast.FunctionDef | ast.AsyncFunctionDef, route: ast.Call) -> str:
        """Best-effort detection of authentication on an HTTP route."""

        def has_hint(node: ast.AST) -> bool:
            text = _short_source(node, 400).lower()
            return any(word in text for word in catalog.AUTH_HINT_WORDS)

        if self._has_global_auth:
            return "detected (app/router level)"
        dependencies = _keyword(route, "dependencies")
        if dependencies is not None and has_hint(dependencies):
            return "detected"
        if any(decorator is not route and has_hint(decorator) for decorator in func.decorator_list):
            return "detected"
        arguments = [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]
        defaults = [*func.args.defaults, *(d for d in func.args.kw_defaults if d is not None)]
        for node in [*defaults, *(a.annotation for a in arguments if a.annotation is not None)]:
            if "Depends(" in _short_source(node, 400) or "Security(" in _short_source(node, 400):
                if has_hint(node):
                    return "detected"
        return "not detected"

    def _detect_global_auth(self, tree: ast.Module) -> bool:
        """Detect auth applied to a whole FastAPI app/router or Flask app."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                dependencies = _keyword(node, "dependencies")
                method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
                texts = [_short_source(dependencies, 400)] if dependencies is not None else []
                if method == "add_middleware":
                    texts.append(_short_source(node, 400))
                if any(word in text.lower() for text in texts for word in ("auth", "token", "jwt", "user", "verify", "api_key")):
                    return True
            if isinstance(node, _FUNCTION_NODES):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Attribute) and decorator.attr == "before_request":
                        return True
        return False

    def _detect_main_guard(self, tree: ast.Module) -> None:
        if not self._result.frameworks:
            return
        for statement in tree.body:
            test = getattr(statement, "test", None)
            if (
                isinstance(statement, ast.If)
                and isinstance(test, ast.Compare)
                and isinstance(test.left, ast.Name)
                and test.left.id == "__name__"
                and any(_constant_str(c) == "__main__" for c in test.comparators)
            ):
                self._add_component(ComponentKind.ENTRY_POINT, "__main__", statement, interface="script", auth="local user")

    # ------------------------------------------------------------------ secrets

    def _scan_hardcoded_secrets(self, tree: ast.Module) -> None:
        reported_lines: set[int] = set()

        def report(node: ast.AST, description: str) -> None:
            line = getattr(node, "lineno", 0)
            if line not in reported_lines:
                reported_lines.add(line)
                self._add_finding("AITM-DATA-001", node, description, confidence="high")

        def check_pair(node: ast.AST, name: str | None, value_node: ast.AST | None) -> None:
            value = _constant_str(value_node)
            if name and value and is_secret_name(name) and looks_like_secret_value(value):
                report(node, f"`{name}` is set to a literal credential ({mask(value)}).")

        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Subscript):
                        check_pair(node, _constant_str(target.slice), node.value)
                    else:
                        for name in _target_names(target):
                            check_pair(node, name.rsplit(".", 1)[-1], node.value)
            elif isinstance(node, ast.Call):
                for keyword in node.keywords:
                    check_pair(node, keyword.arg, keyword.value)
            elif isinstance(node, ast.Dict):
                for key, value in zip(node.keys, node.values):
                    check_pair(node, _constant_str(key), value)
            elif (text := _constant_str(node)) is not None and (token := find_token(text)):
                report(node, f"String literal matches a known credential format ({mask(token)}).")

    # ------------------------------------------------------------------ data flow

    def _analyze_function(self, func: ast.FunctionDef | ast.AsyncFunctionDef, tool: Component | None) -> None:
        tool = tool or self._tool_from_decorators(func)
        entry_point = None if tool else self._entry_point_from_decorators(func)
        arguments = [*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs]
        arguments += [arg for arg in (func.args.vararg, func.args.kwarg) if arg is not None]

        taint: Taint = {}
        if tool is not None:
            for arg in arguments:
                if arg.arg not in _TOOL_FRAMEWORK_PARAMETERS and not _is_injected(arg):
                    taint[arg.arg] = {TOOL_ARGUMENT}
        elif entry_point is not None:
            for arg in arguments:
                if arg.arg not in {"self", "cls"}:
                    taint[arg.arg] = {USER_INPUT}

        context = _ScopeContext(name=func.name, tool=tool)
        self._analyze_scope(func, context, taint)
        if tool is not None and context.capabilities:
            existing = tool.attributes.get("capabilities", "")
            merged = sorted(set(filter(None, existing.split(", "))) | context.capabilities)
            tool.attributes["capabilities"] = ", ".join(merged)
        if tool is not None:
            self._check_tool_identity(func, tool, arguments, context)

    def _check_tool_identity(
        self,
        func: ast.FunctionDef | ast.AsyncFunctionDef,
        tool: Component,
        arguments: list[ast.arg],
        context: _ScopeContext,
    ) -> None:
        """ASI03: a tool that lets the model choose which user/object to act on (confused deputy / IDOR)."""
        exposed = [arg for arg in arguments if arg.arg not in _TOOL_FRAMEWORK_PARAMETERS and not _is_injected(arg)]
        identifiers = [arg.arg for arg in exposed if catalog.is_identifier_parameter(arg.arg)]
        if not identifiers:
            return
        has_caller_context = any(
            arg.arg in {"config", "runtime", "state"} or _is_injected(arg) for arg in arguments
        )
        if has_caller_context:
            return  # the tool can see who is calling; authorization may happen inside
        names = ", ".join(f"`{name}`" for name in identifiers)
        self._add_finding(
            "AITM-ID-001", func,
            f"Tool `{tool.name}` lets the model choose {names} and receives no caller identity "
            "(no InjectedToolArg/InjectedState/config). A prompt-injected model can act on other users' "
            "records with the agent's privileges (IDOR / confused deputy).",
            confidence="medium" if context.capabilities else "low",
        )

    def _analyze_scope(self, scope: ast.AST, context: _ScopeContext, taint: Taint) -> None:
        nodes = list(_walk_scope(scope))
        self._propagate_taint(nodes, taint)
        for node in nodes:
            for flow in self._flows_at(node, taint):
                self._report_flow(node, flow, context)
            self._check_system_prompt_literal(node)

    def _propagate_taint(self, nodes: list[ast.AST], taint: Taint) -> None:
        """Propagate labels through assignments until nothing changes (flow-insensitive)."""
        assignments: list[tuple[ast.AST, ast.AST]] = []
        for node in nodes:
            if isinstance(node, ast.Assign):
                assignments.extend((target, node.value) for target in node.targets)
            elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)) and node.value is not None:
                assignments.append((node.target, node.value))
            elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
                assignments.append((node.target, node.iter))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                assignments.append((node.optional_vars, node.context_expr))

        for _ in range(_MAX_TAINT_PASSES):
            changed = False
            for target, value in assignments:
                labels = self._labels(value, taint)
                if not labels:
                    continue
                for name in _target_names(target):
                    current = taint.setdefault(name, set())
                    if not labels <= current:
                        current |= labels
                        changed = True
            if not changed:
                break

    def _labels(self, expression: ast.AST | None, taint: Taint) -> set[str]:
        """Return the data labels an expression may carry.

        Calls to project functions with a summary are evaluated precisely: only
        arguments that the callee returns contribute labels, plus any labels the
        callee's return value always carries. Other calls conservatively carry
        the labels of their receiver and arguments.
        """
        if expression is None:
            return set()
        if isinstance(expression, ast.Call):
            return self._call_labels(expression, taint)
        if isinstance(expression, (ast.Name, ast.Attribute)):
            return self._reference_labels(expression, taint)
        labels: set[str] = set()
        if isinstance(expression, ast.Subscript) and self._qualified(expression.value) == "os.environ":
            key = _constant_str(expression.slice)
            if key and is_secret_name(key):
                labels.add(SECRET)
        for child in ast.iter_child_nodes(expression):
            labels |= self._labels(child, taint)
        return labels

    def _reference_labels(self, node: ast.Name | ast.Attribute, taint: Taint, *, as_callee: bool = False) -> set[str]:
        """Labels for a variable or attribute reference such as ``user.email``."""
        dotted = _dotted(node)
        labels = set(taint.get(dotted, set())) if dotted else set()
        if isinstance(node, ast.Attribute):
            labels |= self._labels(node.value, taint)
            if dotted and self._qualified(node) == "sys.argv":
                labels.add(USER_INPUT)
            if dotted and dotted.split(".")[0] == "request" and node.attr in catalog.REQUEST_ATTRIBUTES:
                labels.add(USER_INPUT)
        if not as_callee:
            leaf = node.id if isinstance(node, ast.Name) else node.attr
            if is_pii_name(leaf):
                labels.add(PII)
        return labels

    def _call_labels(self, call: ast.Call, taint: Taint) -> set[str]:
        summary = self._resolve_summary(call)
        if summary is not None:
            labels = set(summary.return_labels)
            for parameter, argument in self._map_arguments(call, summary):
                if parameter in summary.returns_parameters:
                    labels |= self._labels(argument, taint)
            return labels

        labels = self._call_source_labels(call)
        if isinstance(call.func, (ast.Name, ast.Attribute)):
            labels |= self._reference_labels(call.func, taint, as_callee=True)
        for argument in _all_arguments(call):
            labels |= self._labels(argument, taint)
        return labels

    def _is_model_invocation(self, call: ast.Call, qualified: str, method: str | None) -> bool:
        """True for ``.invoke()``-style calls on runnables that are not project functions."""
        if method not in catalog.INVOKE_METHODS:
            return False
        receiver_head = (_dotted(call.func) or "").split(".")[0]
        if receiver_head in self._imports:
            if qualified.split(".")[0] in _NON_MODEL_MODULES:
                return False
        elif receiver_head in _NON_MODEL_VARIABLES or receiver_head in _NON_MODEL_MODULES:
            return False
        return self._resolve_summary(call) is None

    def _call_source_labels(self, call: ast.Call) -> set[str]:
        """Labels introduced by the call itself (user input, secrets, model output)."""
        qualified, simple, method = self._callee(call)
        dotted = _dotted(call.func) or ""
        if qualified in {"input", "builtins.input"} or dotted.split(".")[0] == "request":
            return {USER_INPUT}
        if qualified.startswith("streamlit.") and simple in catalog.STREAMLIT_INPUTS:
            return {USER_INPUT}
        if qualified in {"os.getenv", "os.environ.get"}:
            key = _constant_str(_argument(call, 0, "key"))
            return {SECRET} if key and is_secret_name(key) else set()
        if method == "get_secret_value":
            return {SECRET}
        if catalog.is_ai_framework(qualified) and simple in catalog.WEB_CONTENT_SOURCES:
            return {EXTERNAL_CONTENT}  # loaders/search tools: everything they return is attacker-reachable
        if self._is_model_invocation(call, qualified, method):
            return {MODEL_OUTPUT}
        return set()

    # ------------------------------------------------------------------ flow detection

    def _flows_at(self, node: ast.AST, taint: Taint) -> list[_Flow]:
        """All flows of labelled data into sensitive operations at ``node``."""
        if isinstance(node, ast.Tuple):
            return self._role_tuple_flows(node, taint)
        if isinstance(node, ast.Dict):
            return self._memory_scope_dict_flows(node, taint)
        if not isinstance(node, ast.Call):
            return []
        return [
            *self._sink_flows(node, taint),
            *self._prompt_flows(node, taint),
            *self._log_flows(node, taint),
            *self._markup_flows(node, taint),
            *self._memory_flows(node, taint),
            *self._summary_flows(node, taint),
        ]

    def _union_labels(self, expressions: Iterable[ast.AST | None], taint: Taint) -> frozenset[str]:
        labels: set[str] = set()
        for expression in expressions:
            labels |= self._labels(expression, taint)
        return frozenset(labels)

    def _sink_arguments(self, call: ast.Call, sink: SinkKind) -> list[ast.expr]:
        """The arguments of a sink that are dangerous if attacker-controlled."""
        if sink is SinkKind.SQL:
            query = _argument(call, 0, "sql", "statement", "query")
            return [query] if query is not None and not isinstance(query, ast.Constant) else []
        if sink is SinkKind.NETWORK:
            qualified = self._qualified(call.func)
            url = _argument(call, 1, "url") if qualified.endswith(".request") else _argument(call, 0, "url")
            return [url] if url is not None else []
        return _all_arguments(call)

    def _sink_flows(self, call: ast.Call, taint: Taint) -> list[_Flow]:
        qualified, _, method = self._callee(call)
        open_mode = None
        if qualified in {"open", "builtins.open", "io.open"}:
            open_mode = _constant_str(_argument(call, 1, "mode"))
        sink = catalog.classify_sink(qualified, method, open_mode)
        if sink is None or self._resolve_summary(call) is not None:
            return []
        labels = self._union_labels(self._sink_arguments(call, sink), taint)
        return [_Flow(sink.value, qualified or f".{method}", labels, self._location(call))]

    def _summary_flows(self, call: ast.Call, taint: Taint) -> list[_Flow]:
        """Flows into sinks inside a called project function (interprocedural)."""
        summary = self._resolve_summary(call)
        if summary is None:
            return []
        flows: list[_Flow] = []
        covered: set[SinkRef] = set()
        for parameter, argument in self._map_arguments(call, summary):
            refs = summary.parameter_sinks.get(parameter)
            if not refs:
                continue
            labels = frozenset(self._labels(argument, taint))
            via = f"`{summary.name}()` parameter `{parameter}`"
            for ref in refs:
                flows.append(_Flow(ref.kind, ref.callee, labels, ref.location, via))
                covered.add(ref)
        for ref in summary.reachable_sinks - covered:
            flows.append(_Flow(ref.kind, ref.callee, frozenset(), ref.location, f"`{summary.name}()`"))
        return flows

    def _prompt_flows(self, call: ast.Call, taint: Taint) -> list[_Flow]:
        qualified, simple, method = self._callee(call)
        location = self._location(call)
        flows: list[_Flow] = []
        if self._is_model_invocation(call, qualified, method):
            arguments = _all_arguments(call)
            formatted = self._union_labels(
                (node for argument in arguments for node in ast.walk(argument) if _is_dynamic_string(node)), taint
            )
            if formatted:
                flows.append(_Flow(PROMPT_FORMAT, f".{method}()", formatted, location))
            model_input = self._union_labels(arguments, taint)
            if model_input:
                flows.append(_Flow(MODEL_INPUT, f".{method}()", model_input, location))

        if not catalog.is_ai_framework(qualified):
            return flows
        if simple == "SystemMessage":
            labels = self._union_labels([_argument(call, 0, "content")], taint)
            if labels:
                flows.append(_Flow(SYSTEM_PROMPT, simple, labels, location))
        elif simple in {"from_template", "PromptTemplate"}:
            labels = self._union_labels([_argument(call, 0, "template")], taint)
            if labels:
                jinja = _constant_str(_keyword(call, "template_format")) == "jinja2"
                flows.append(_Flow(JINJA_TEMPLATE if jinja else PROMPT_TEMPLATE, simple, labels, location))
        return flows

    def _role_tuple_flows(self, node: ast.Tuple, taint: Taint) -> list[_Flow]:
        """Flows into ``("system", ...)`` / ``("human", f"...")`` prompt messages."""
        if len(node.elts) != 2:
            return []
        role = _constant_str(node.elts[0])
        content = node.elts[1]
        if role in {"system", "developer"}:
            labels = self._union_labels([content], taint)
            return [_Flow(SYSTEM_PROMPT, f"({role!r}, ...) message", labels, self._location(node))] if labels else []
        if role in {"human", "user"} and _is_dynamic_string(content):
            labels = self._union_labels([content], taint)
            return [_Flow(PROMPT_FORMAT, "a prompt template string", labels, self._location(node))] if labels else []
        return []

    def _log_flows(self, call: ast.Call, taint: Taint) -> list[_Flow]:
        qualified, _, method = self._callee(call)
        receiver = (_dotted(call.func.value) or "") if isinstance(call.func, ast.Attribute) else ""
        is_log = qualified in {"print", "builtins.print"} or (method in _LOG_METHODS and "log" in receiver.lower())
        if not is_log:
            return []
        labels = self._union_labels(_all_arguments(call), taint)
        return [_Flow(LOG_OUTPUT, qualified or f".{method}", labels, self._location(call))] if labels else []

    def _markup_flows(self, call: ast.Call, taint: Taint) -> list[_Flow]:
        qualified, simple, _ = self._callee(call)
        is_markup_sink = (
            (qualified.startswith("streamlit.") and (simple == "html" or (
                simple in {"markdown", "write"} and _is_true(_keyword(call, "unsafe_allow_html"))
            )))
            or (qualified.startswith("gradio.") and simple == "HTML")
            or (simple in _HTML_SINKS and qualified.startswith(_HTML_SINK_MODULES))
        )
        if not is_markup_sink:
            return []
        labels = self._union_labels(_all_arguments(call), taint)
        return [_Flow(MARKUP_RENDER, qualified, labels, self._location(call))] if labels else []

    def _memory_flows(self, call: ast.Call, taint: Taint) -> list[_Flow]:
        """Writes into long-term memory, and memory namespaces chosen by labelled data (ASI06)."""
        _, _, method = self._callee(call)
        if method is None or not isinstance(call.func, ast.Attribute) or self._resolve_summary(call) is not None:
            return []
        receiver = (_dotted(call.func.value) or "").rsplit(".", 1)[-1].lower()
        location = self._location(call)
        flows: list[_Flow] = []
        if method in catalog.MEMORY_WRITE_METHODS:
            labels = self._union_labels(_all_arguments(call), taint)
            if labels:
                flows.append(_Flow(MEMORY_WRITE, f"{receiver or '?'}.{method}()", labels, location))
            return flows
        if method not in catalog.STORE_SCOPED_METHODS or not any(h in receiver for h in catalog.STORE_RECEIVER_HINTS):
            return flows
        namespace = _argument(call, 0, "namespace", "namespace_prefix")
        is_store_namespace = isinstance(namespace, ast.Tuple) or method in {"put", "aput", "search", "asearch"}
        if is_store_namespace and not _looks_authenticated(namespace):
            labels = self._union_labels([namespace], taint)
            if labels:
                flows.append(_Flow(MEMORY_SCOPE, f"the namespace of `{receiver}.{method}()`", labels, location))
        if method in catalog.STORE_WRITE_METHODS:
            values = [*call.args[1:], *(k.value for k in call.keywords if k.arg not in {"namespace", "key"})]
            labels = self._union_labels(values, taint)
            if labels:
                flows.append(_Flow(MEMORY_WRITE, f"{receiver}.{method}()", labels, location))
        return flows

    def _memory_scope_dict_flows(self, node: ast.Dict, taint: Taint) -> list[_Flow]:
        """``{"configurable": {"thread_id": <labelled>}}`` selects whose conversation/memory is loaded."""
        flows: list[_Flow] = []
        for key, value in zip(node.keys, node.values):
            if _constant_str(key) != "configurable" or not isinstance(value, ast.Dict):
                continue
            for inner_key, inner_value in zip(value.keys, value.values):
                name = _constant_str(inner_key)
                if name not in catalog.MEMORY_SCOPE_KEYS or _looks_authenticated(inner_value):
                    continue
                labels = self._union_labels([inner_value], taint)
                if labels:
                    flows.append(_Flow(MEMORY_SCOPE, f"`configurable.{name}`", labels, self._location(inner_value)))
        return flows

    # ------------------------------------------------------------------ reporting

    def _report_flow(self, anchor: ast.AST, flow: _Flow, context: _ScopeContext) -> None:
        """Translate a flow with concrete labels into findings."""
        labels = flow.labels
        related = [flow.sink] if flow.via else []
        trace = f" The data passes through {flow.via} and reaches the sink at {flow.sink}." if flow.via else ""
        tool = context.tool

        def report(rule_id: str, description: str, *, extra_related: Iterable[Location] = (), **kwargs: object) -> None:
            self._add_finding(rule_id, anchor, description + trace, related=[*related, *extra_related], **kwargs)

        if flow.kind in _DANGEROUS_SINK_KINDS:
            sink = SinkKind(flow.kind)
            severity = catalog.SINK_SEVERITY[sink]
            if tool is not None:
                context.capabilities.add(flow.kind)
            if TOOL_ARGUMENT in labels and tool is not None:
                report(
                    "AITM-TOOL-003",
                    f"Tool `{tool.name}` passes a model-controlled argument to `{flow.callee}` ({flow.kind}). "
                    "A prompt-injected model chooses this value.",
                    severity=severity, extra_related=[tool.location], confidence="high",
                )
            elif MODEL_OUTPUT in labels:
                report("AITM-OUT-001", f"Model output flows into `{flow.callee}` ({flow.kind}) in `{context.name}`.",
                       severity=severity)
            elif USER_INPUT in labels:
                report("AITM-INJ-001", f"User input flows into `{flow.callee}` ({flow.kind}) in `{context.name}`.",
                       severity=Severity.MEDIUM if sink is SinkKind.NETWORK else severity)
            elif tool is not None:
                report("AITM-TOOL-002", f"Tool `{tool.name}` can perform {flow.kind} via `{flow.callee}`.",
                       extra_related=[tool.location])
        elif flow.kind == PROMPT_FORMAT and USER_INPUT in labels:
            report(
                "AITM-PI-001",
                f"User input is formatted directly into {flow.callee}; it is not delimited from "
                "instructions and braces in the input can inject template variables.",
            )
        elif flow.kind == SYSTEM_PROMPT and labels & UNTRUSTED_LABELS:
            report(
                "AITM-PI-002",
                f"The system prompt ({flow.callee}) includes {_describe_labels(labels & UNTRUSTED_LABELS)}, "
                "letting that data rewrite instructions.",
            )
        elif flow.kind in {PROMPT_TEMPLATE, JINJA_TEMPLATE} and labels & UNTRUSTED_LABELS:
            jinja = flow.kind == JINJA_TEMPLATE
            report(
                "AITM-PI-002",
                f"The prompt template passed to `{flow.callee}` is built from "
                f"{_describe_labels(labels & UNTRUSTED_LABELS)}"
                + (" and rendered with Jinja2 (server-side template injection)." if jinja else "."),
                severity=Severity.CRITICAL if jinja else None,
            )
        elif flow.kind == MODEL_INPUT and SECRET in labels:
            report("AITM-DATA-002", f"A credential-derived value is sent to the model via {flow.callee}.",
                   severity=Severity.HIGH)
        elif flow.kind == MODEL_INPUT and PII in labels:
            report("AITM-DATA-002", f"Personal data is sent to the model via {flow.callee}.")
        elif flow.kind == LOG_OUTPUT and SECRET in labels:
            report("AITM-DATA-003", f"A credential-derived value is written to logs via `{flow.callee}`.",
                   severity=Severity.HIGH)
        elif flow.kind == LOG_OUTPUT and PII in labels:
            report("AITM-DATA-003", f"Personal data is written to logs via `{flow.callee}`.", severity=Severity.MEDIUM)
        elif flow.kind == MARKUP_RENDER and MODEL_OUTPUT in labels:
            report("AITM-OUT-002", f"Model output is rendered as trusted markup via `{flow.callee}` (XSS / template injection).")
        elif flow.kind == MARKUP_RENDER and USER_INPUT in labels:
            report("AITM-INJ-001", f"User input is rendered as trusted markup via `{flow.callee}`.")
        elif flow.kind == MEMORY_WRITE and labels & UNTRUSTED_LABELS:
            untrusted = labels & UNTRUSTED_LABELS
            if tool is not None:
                context.capabilities.add(MEMORY_WRITE)
            report(
                "AITM-MEM-001",
                f"{_describe_labels(untrusted).capitalize()} is persisted via `{flow.callee}` in `{context.name}`. "
                "Later sessions retrieve it as trusted context, so injected instructions survive and can "
                "spread to other conversations.",
                severity=Severity.HIGH if untrusted & _MODEL_DRIVEN_LABELS else Severity.MEDIUM,
            )
        elif flow.kind == MEMORY_SCOPE and labels & _SCOPE_CONTROL_LABELS:
            report(
                "AITM-MEM-002",
                f"{flow.callee} in `{context.name}` is derived from "
                f"{_describe_labels(labels & _SCOPE_CONTROL_LABELS)}, so a caller (or a hijacked model) can "
                "read or poison another user's conversation and memory.",
            )

    def _check_system_prompt_literal(self, node: ast.AST) -> None:
        """Flag credentials written directly into system prompt text."""
        content: ast.AST | None = None
        if isinstance(node, ast.Tuple) and len(node.elts) == 2 and _constant_str(node.elts[0]) in {"system", "developer"}:
            content = node.elts[1]
        elif isinstance(node, ast.Call):
            qualified, simple, _ = self._callee(node)
            if simple == "SystemMessage" and catalog.is_ai_framework(qualified):
                content = _argument(node, 0, "content")
        text = _literal_text(content)
        if text and (_CREDENTIAL_IN_TEXT.search(text) or find_token(text)):
            self._add_finding("AITM-DATA-005", node, "The system prompt text appears to contain a credential.")


MAX_SUMMARY_ROUNDS = 20


def solve_summaries(analyzers: Iterable[PythonFileAnalyzer], max_rounds: int = MAX_SUMMARY_ROUNDS) -> int:
    """Recompute summaries for all prepared analyzers until they stop changing.

    Returns the number of rounds performed. Facts only grow and are capped, so
    the loop terminates; ``max_rounds`` is an additional safety bound.
    """
    analyzers = list(analyzers)
    for round_number in range(1, max_rounds + 1):
        changed = False
        for analyzer in list(analyzers):
            try:
                changed |= analyzer.update_summaries()
            except RecursionError:
                LOGGER.warning("Expression nesting too deep in %s; excluding it from interprocedural analysis",
                               analyzer.path)
                analyzers.remove(analyzer)
        if not changed:
            return round_number
    LOGGER.warning("Interprocedural summaries did not converge after %d rounds; results may be incomplete", max_rounds)
    return max_rounds


def analyze_python_source(relative_path: str, source: str) -> FileAnalysis:
    """Convenience wrapper: analyze one file (interprocedural within the file)."""
    analyzer = PythonFileAnalyzer(relative_path, source)
    analyzer.prepare()
    solve_summaries([analyzer])
    return analyzer.analyze()
