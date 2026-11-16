"""Pure helper checks for agentic supply-chain and inter-agent channel risks.

These functions only inspect strings taken from source code or configuration;
they never resolve hosts, download packages, or contact servers. They are
shared by :mod:`python_analyzer` (``MultiServerMCPClient(...)``, ``RemoteGraph``,
``hub.pull``) and :mod:`config_analyzer` (``mcp.json`` and similar files).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse

from . import catalog
from .models import Severity
from .sensitive import redact

LOGGER = logging.getLogger(__name__)

LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0"})
_COMMIT_REF = re.compile(r":[0-9a-f]{8,40}$")
_NPM_PINNED = re.compile(r"^(@[^/@\s]+/)?[^@\s]+@\d[\w.\-+]*$")
_PY_PINNED = re.compile(r"^[A-Za-z0-9_.\-\[\]]+(==|@)\d[\w.\-+]*$")


@dataclass(frozen=True)
class ChannelIssue:
    """A problem with how an agent connects to a remote agent or MCP server."""

    severity: Severity
    confidence: str
    description: str


def is_loopback(url: str) -> bool:
    """True if ``url`` points at the local machine (or cannot be parsed)."""
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        LOGGER.debug("Unparseable URL %r", redact(url))
        return True
    return host in LOOPBACK_HOSTS


def channel_issue(what: str, url: str | None, *, has_auth: bool) -> ChannelIssue | None:
    """Check a remote agent/MCP endpoint for plaintext transport or missing credentials.

    Args:
        what: Human-readable name of the connection, e.g. ``MCP server `crm```.
        url: Constant URL from code or config; ``None`` if it is computed at runtime.
        has_auth: Whether headers, an API key, or an auth object are configured.
    """
    if not url or not url.lower().startswith(("http://", "https://", "ws://", "wss://")) or is_loopback(url):
        return None
    shown = redact(url)[:120]
    if url.lower().startswith(("http://", "ws://")):
        return ChannelIssue(
            Severity.HIGH, "high",
            f"{what} connects to `{shown}` over an unencrypted channel; another party on the network can "
            "read or rewrite tool descriptions, tool results, and agent messages.",
        )
    if not has_auth:
        return ChannelIssue(
            Severity.MEDIUM, "low",
            f"{what} connects to `{shown}` with no credentials or auth headers configured in code; "
            "verify the remote side authenticates this agent and that the agent authenticates the server.",
        )
    return None


def unpinned_package(command: str | None, args: Iterable[str]) -> str | None:
    """Return the package an MCP launcher downloads without a version pin, if any.

    ``npx -y @org/server`` and ``uvx mcp-server-x`` fetch the latest release every
    time the agent starts; ``npx -y @org/server@1.2.3`` and ``uvx pkg==1.2.3`` do not.
    """
    if not command:
        return None
    runner = command.replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".cmd").removesuffix(".exe")
    if runner not in catalog.PACKAGE_RUNNERS:
        return None
    for arg in args:
        if arg.startswith("-") or arg in {"run", "dlx", "exec"}:
            continue
        pinned = _NPM_PINNED.match(arg) if runner in {"npx", "bunx", "pnpx"} else _PY_PINNED.match(arg)
        return None if pinned else arg
    return None


def is_pinned_hub_reference(name: str) -> bool:
    """True for ``owner/prompt:<commit-hash>`` references."""
    return bool(_COMMIT_REF.search(name))
