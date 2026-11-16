"""Analysis of configuration files: secrets, tracing, LangGraph deployments, MCP servers, dependencies."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from . import agentic, catalog
from .models import Component, ComponentKind, Finding, Location, Severity
from .rules import make_finding
from .sensitive import find_token, is_secret_name, looks_like_secret_value, mask, redact

LOGGER = logging.getLogger(__name__)

_KEY_VALUE_RE = re.compile(
    r"""^\s*(?:export\s+)?["']?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?(?P<value>[^"'#\s,}]*)"""
)
_TRACING_KEYS = frozenset({"LANGCHAIN_TRACING_V2", "LANGSMITH_TRACING", "LANGCHAIN_TRACING", "LANGSMITH_TRACING_V2"})
_TRUTHY = frozenset({"true", "1", "yes", "on"})
_AI_PACKAGE_RE = re.compile(r"^(langchain[\w\-]*|langgraph[\w\-]*|langserve|langsmith|openai|anthropic)$", re.IGNORECASE)
_REQUIREMENT_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(.*)$")
_QUOTED_REQUIREMENT_RE = re.compile(r"""["']([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*([^"']*)["']""")
_POETRY_REQUIREMENT_RE = re.compile(r"""^\s*([A-Za-z0-9_.\-]+)\s*=\s*["']([^"']*)["']""")
_EXAMPLE_FILE_RE = re.compile(r"(example|sample|template|dist)", re.IGNORECASE)


@dataclass
class ConfigAnalysis:
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


def analyze_config(relative_path: str, text: str, *, env_ignored_by_git: bool) -> ConfigAnalysis:
    """Analyze a single configuration file's text."""
    result = ConfigAnalysis()
    name = PurePosixPath(relative_path).name.lower()
    lines = text.splitlines()

    _scan_lines(relative_path, name, lines, result, env_ignored_by_git)
    if name == "langgraph.json":
        _scan_langgraph_config(relative_path, text, lines, result)
    elif name in catalog.MCP_CONFIG_FILES:
        _scan_mcp_config(relative_path, text, lines, result)
    if name.startswith("requirements") and name.endswith(".txt"):
        _scan_requirements(relative_path, lines, result)
    elif name == "pyproject.toml":
        _scan_pyproject(relative_path, lines, result)
    return result


def _location(path: str, line_number: int, lines: list[str]) -> Location:
    snippet = lines[line_number - 1].strip() if 0 < line_number <= len(lines) else ""
    return Location(path, line_number, redact(snippet)[:200])


def _scan_lines(path: str, name: str, lines: list[str], result: ConfigAnalysis, env_ignored: bool) -> None:
    is_env_file = name.startswith(".env")
    is_example = bool(_EXAMPLE_FILE_RE.search(name))
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith(("#", "//", ";")):
            continue
        location = _location(path, number, lines)
        token = find_token(line)
        match = _KEY_VALUE_RE.match(line)
        key, value = (match.group("key"), match.group("value")) if match else ("", "")

        if token:
            result.findings.append(make_finding(
                "AITM-DATA-001", location,
                f"A value matching a known credential format is committed in `{path}` ({mask(token)}).",
                confidence="high",
            ))
        elif key and not is_example and is_secret_name(key.rsplit(".", 1)[-1]) and looks_like_secret_value(value):
            detail = ""
            if is_env_file and not env_ignored:
                detail = " `.env` files are not listed in `.gitignore`, so this file may be committed."
            result.findings.append(make_finding(
                "AITM-DATA-001", location,
                f"`{key}` holds a literal credential ({mask(value)}).{detail}",
                severity=Severity.HIGH if (not is_env_file or not env_ignored) else Severity.LOW,
            ))

        if key.upper() in _TRACING_KEYS and value.lower() in _TRUTHY:
            result.components.append(Component(
                ComponentKind.OBSERVABILITY, "LangSmith tracing", location, key, {"vendor": "LangSmith"},
            ))
            result.findings.append(make_finding(
                "AITM-DATA-004", location,
                f"`{key}={value}` sends prompts, tool arguments, and model outputs to LangSmith.",
                confidence="high",
            ))


def _scan_langgraph_config(path: str, text: str, lines: list[str], result: ConfigAnalysis) -> None:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        LOGGER.warning("Cannot parse %s: %s", path, error.msg)
        return
    graphs = data.get("graphs") if isinstance(data, dict) else None
    if not isinstance(graphs, dict):
        return
    auth = "configured" if data.get("auth") else "platform default"
    for graph_name, target in graphs.items():
        line = next((i for i, text_line in enumerate(lines, 1) if f'"{graph_name}"' in text_line), 1)
        result.components.append(Component(
            ComponentKind.ENTRY_POINT, f"LangGraph API graph '{graph_name}'", _location(path, line, lines),
            str(target), {"interface": "HTTP (LangGraph Platform)", "auth": auth, "target": redact(str(target))},
        ))


def _scan_mcp_config(path: str, text: str, lines: list[str], result: ConfigAnalysis) -> None:
    """Inventory MCP servers (``mcpServers`` / ``servers``) and check pinning and transport (ASI04, ASI07)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as error:
        LOGGER.warning("Cannot parse %s: %s", path, error.msg)
        return
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers", data.get("servers"))
    if not isinstance(servers, dict):
        return
    for server_name, settings in servers.items():
        if not isinstance(settings, dict):
            continue
        line = next((i for i, text_line in enumerate(lines, 1) if f'"{server_name}"' in text_line), 1)
        location = _location(path, line, lines)
        command = settings.get("command") if isinstance(settings.get("command"), str) else None
        args = [arg for arg in settings.get("args", []) if isinstance(arg, str)] if isinstance(settings.get("args"), list) else []
        url = settings.get("url") if isinstance(settings.get("url"), str) else None
        transport = str(settings.get("type") or settings.get("transport") or ("stdio" if command else "http"))
        endpoint = url or " ".join([command or "", *args]).strip()
        result.components.append(Component(
            ComponentKind.TOOL, f"MCP server '{server_name}'", location, path,
            {"source": "MCP", "transport": redact(transport), "endpoint": redact(endpoint)[:120]},
        ))
        issue = agentic.channel_issue(f"MCP server `{server_name}`", url, has_auth=bool(settings.get("headers")))
        if issue is not None:
            result.findings.append(make_finding(
                "AITM-MA-001", location, issue.description, severity=issue.severity, confidence=issue.confidence,
            ))
        package = agentic.unpinned_package(command, args)
        if package:
            result.findings.append(make_finding(
                "AITM-SUP-002", location,
                f"MCP server `{server_name}` is launched with `{command} {package}` without a version pin, so the "
                "agent runs whatever code and tool descriptions the registry serves at start-up.",
                confidence="high",
            ))


def _report_unpinned(path: str, lines: list[str], unpinned: list[tuple[str, int]], result: ConfigAnalysis) -> None:
    if not unpinned:
        return
    names = ", ".join(sorted({package for package, _ in unpinned}))
    result.findings.append(make_finding(
        "AITM-SUP-001", _location(path, unpinned[0][1], lines),
        f"Unpinned AI dependencies: {names}.",
        related=[_location(path, line, lines) for _, line in unpinned[1:]],
    ))


def _scan_requirements(path: str, lines: list[str], result: ConfigAnalysis) -> None:
    unpinned: list[tuple[str, int]] = []
    for number, line in enumerate(lines, start=1):
        stripped = line.split("#", 1)[0].strip()
        if not stripped or stripped.startswith("-"):
            continue
        match = _REQUIREMENT_RE.match(stripped)
        if match and _AI_PACKAGE_RE.match(match.group(1)) and "==" not in match.group(3):
            unpinned.append((match.group(1), number))
    _report_unpinned(path, lines, unpinned, result)


def _scan_pyproject(path: str, lines: list[str], result: ConfigAnalysis) -> None:
    unpinned: list[tuple[str, int]] = []
    for number, line in enumerate(lines, start=1):
        poetry = _POETRY_REQUIREMENT_RE.match(line)
        if poetry and _AI_PACKAGE_RE.match(poetry.group(1)):
            if not re.fullmatch(r"=?=?\s*\d[\w.]*", poetry.group(2).strip()):
                unpinned.append((poetry.group(1), number))
            continue
        for match in _QUOTED_REQUIREMENT_RE.finditer(line):
            if _AI_PACKAGE_RE.match(match.group(1)) and "==" not in match.group(3):
                unpinned.append((match.group(1), number))
    _report_unpinned(path, lines, unpinned, result)
