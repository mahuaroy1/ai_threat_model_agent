"""Persistent cache of per-file analysis results for incremental scans.

What is stored (one JSON file per scanned project)
-----------------------------------------------------
For every analyzed file:

* ``sha256`` of its content, used to detect changes,
* its converged interprocedural :class:`FunctionSummary` objects (the
  intermediate representation other files consume),
* ``dependencies``: the project files whose summaries it used, i.e. the
  cross-file call graph, used to invalidate dependents,
* its components, findings, frameworks, and control signals (where human
  approval, iteration limits, guardrails, and similar controls were seen).

Plus an ``export_signature``: every function's file, name, and parameters.
If that changes, import resolution may change, so all summaries are rebuilt.

Security
--------
* JSON only, never ``pickle``: loading a cache cannot execute code.
* Every value is type-checked on load. A corrupt, oversized, or
  version-mismatched cache is ignored with a warning and a full scan runs.
* The file extension ``.aitmcache`` is not a scanned config type, so a cache
  stored inside the scanned tree is never analyzed as project configuration.
* Anyone who can write the cache can hide findings. Do not restore caches from
  untrusted sources, such as CI caches populated by forked pull requests.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .interprocedural import FunctionSummary, SinkRef
from .models import Component, ComponentKind, Finding, Location, Severity

LOGGER = logging.getLogger(__name__)

CACHE_SCHEMA = 2
CACHE_SUFFIX = ".aitmcache"
MAX_CACHE_BYTES = 200_000_000


class CacheFormatError(ValueError):
    """The cache content does not match the expected structure."""


def content_hash(text: str) -> str:
    """SHA-256 of a file's decoded text."""
    return hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def cache_path(cache_dir: Path, project_root: Path) -> Path:
    """Cache file for ``project_root``; different projects never share a file."""
    digest = hashlib.sha256(str(project_root).encode("utf-8", errors="surrogatepass")).hexdigest()[:24]
    return cache_dir / f"{digest}{CACHE_SUFFIX}"


# --------------------------------------------------------------------------- cache content


@dataclass
class FileEntry:
    """Cached analysis of one file."""

    sha256: str
    kind: str  # "python" or "config"
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    frameworks: set[str] = field(default_factory=set)
    signals: dict[str, list[Location]] = field(default_factory=dict)
    summaries: list[FunctionSummary] = field(default_factory=list)
    dependencies: set[str] = field(default_factory=set)
    env_ignored: bool = False  # config files only: the .gitignore state the result depends on


@dataclass
class CacheState:
    """Everything persisted between scans of one project."""

    project_root: str
    export_signature: str = ""
    files: dict[str, FileEntry] = field(default_factory=dict)


def export_signature(exports: dict[str, list[FunctionSummary]]) -> str:
    """Fingerprint of every function's identity and parameters across the project."""
    items = sorted(
        (path, summary.name, list(summary.parameters), summary.positional_count)
        for path, summaries in exports.items()
        for summary in summaries
    )
    return hashlib.sha256(json.dumps(items, separators=(",", ":")).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- load / save


def load_cache(path: Path, project_root: Path) -> CacheState | None:
    """Load a cache, or return ``None`` if it is missing, stale, or invalid.

    Never raises for bad cache content; problems are logged and a full scan runs.
    """
    try:
        size = path.stat().st_size
    except FileNotFoundError:
        LOGGER.info("No analysis cache at %s; running a full scan", path)
        return None
    except OSError as error:
        LOGGER.warning("Cannot access analysis cache %s (%s); running a full scan", path, error)
        return None
    if size > MAX_CACHE_BYTES:
        LOGGER.warning("Analysis cache %s is larger than %d bytes; ignoring it", path, MAX_CACHE_BYTES)
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        state = _state_from_json(data, project_root)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        LOGGER.warning("Cannot read analysis cache %s (%s); running a full scan", path, error)
        return None
    except (CacheFormatError, KeyError, TypeError, ValueError) as error:
        LOGGER.warning("Ignoring invalid analysis cache %s (%s); running a full scan", path, error)
        return None
    if state is not None:
        LOGGER.info("Loaded analysis cache %s (%d files)", path, len(state.files))
    return state


def save_cache(path: Path, state: CacheState) -> bool:
    """Atomically write the cache. Returns False (and logs) on failure; never raises."""
    temp_name = ""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(_state_to_json(state), separators=(",", ":"), sort_keys=True)
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.", delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(content)
        os.replace(temp_name, path)
        LOGGER.info("Saved analysis cache %s (%d files)", path, len(state.files))
        return True
    except (OSError, TypeError, ValueError) as error:
        LOGGER.warning("Could not save analysis cache %s: %s", path, error)
        if temp_name:
            try:
                os.unlink(temp_name)
            except OSError:
                LOGGER.debug("Could not remove temporary file %s", temp_name)
        return False


# --------------------------------------------------------------------------- serialization


def _state_to_json(state: CacheState) -> dict[str, Any]:
    return {
        "schema": CACHE_SCHEMA,
        "tool_version": __version__,
        "project_root": state.project_root,
        "export_signature": state.export_signature,
        "files": {path: _entry_to_json(entry) for path, entry in sorted(state.files.items())},
    }


def _state_from_json(data: Any, project_root: Path) -> CacheState | None:
    obj = _dict(data, "cache")
    if obj.get("schema") != CACHE_SCHEMA or obj.get("tool_version") != __version__:
        LOGGER.info("Analysis cache was written by another version; running a full scan")
        return None
    if obj.get("project_root") != str(project_root):
        LOGGER.info("Analysis cache belongs to another project root; running a full scan")
        return None
    files = {
        _str(path, "file path"): _entry_from_json(entry)
        for path, entry in _dict(obj["files"], "files").items()
    }
    return CacheState(project_root=str(project_root), export_signature=_str(obj["export_signature"], "signature"),
                      files=files)


def _entry_to_json(entry: FileEntry) -> dict[str, Any]:
    return {
        "sha256": entry.sha256,
        "kind": entry.kind,
        "env_ignored": entry.env_ignored,
        "components": [_component_to_json(c) for c in entry.components],
        "findings": [_finding_to_json(f) for f in entry.findings],
        "frameworks": sorted(entry.frameworks),
        "signals": {name: [_location_to_json(loc) for loc in locations]
                    for name, locations in sorted(entry.signals.items())},
        "summaries": [_summary_to_json(s) for s in entry.summaries],
        "dependencies": sorted(entry.dependencies),
    }


def _entry_from_json(data: Any) -> FileEntry:
    obj = _dict(data, "file entry")
    kind = _str(obj["kind"], "kind")
    if kind not in {"python", "config"}:
        raise CacheFormatError(f"unknown file kind {kind!r}")
    return FileEntry(
        sha256=_str(obj["sha256"], "sha256"),
        kind=kind,
        env_ignored=_bool(obj["env_ignored"], "env_ignored"),
        components=[_component_from_json(c) for c in _list(obj["components"], "components")],
        findings=[_finding_from_json(f) for f in _list(obj["findings"], "findings")],
        frameworks={_str(name, "framework") for name in _list(obj["frameworks"], "frameworks")},
        signals={
            _str(name, "signal"): [_location_from_json(loc) for loc in _list(locations, "signal locations")]
            for name, locations in _dict(obj["signals"], "signals").items()
        },
        summaries=[_summary_from_json(s) for s in _list(obj["summaries"], "summaries")],
        dependencies={_str(path, "dependency") for path in _list(obj["dependencies"], "dependencies")},
    )


def _location_to_json(location: Location) -> dict[str, Any]:
    return {"file": location.file, "line": location.line, "snippet": location.snippet}


def _location_from_json(data: Any) -> Location:
    obj = _dict(data, "location")
    return Location(file=_str(obj["file"], "file"), line=_int(obj["line"], "line"),
                    snippet=_str(obj["snippet"], "snippet"))


def _component_to_json(component: Component) -> dict[str, Any]:
    return {
        "kind": component.kind.value,
        "name": component.name,
        "location": _location_to_json(component.location),
        "qualified_name": component.qualified_name,
        "attributes": dict(component.attributes),
    }


def _component_from_json(data: Any) -> Component:
    obj = _dict(data, "component")
    attributes = _dict(obj["attributes"], "attributes")
    return Component(
        kind=ComponentKind(_str(obj["kind"], "component kind")),
        name=_str(obj["name"], "name"),
        location=_location_from_json(obj["location"]),
        qualified_name=_str(obj["qualified_name"], "qualified_name"),
        attributes={_str(k, "attribute"): _str(v, "attribute value") for k, v in attributes.items()},
    )


def _finding_to_json(finding: Finding) -> dict[str, Any]:
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.value,
        "category": finding.category,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "location": _location_to_json(finding.location),
        "related": [_location_to_json(loc) for loc in finding.related],
        "confidence": finding.confidence,
        "owasp_agentic": list(finding.owasp_agentic),
    }


def _finding_from_json(data: Any) -> Finding:
    obj = _dict(data, "finding")
    return Finding(
        rule_id=_str(obj["rule_id"], "rule_id"),
        title=_str(obj["title"], "title"),
        severity=Severity(_str(obj["severity"], "severity")),
        category=_str(obj["category"], "category"),
        description=_str(obj["description"], "description"),
        recommendation=_str(obj["recommendation"], "recommendation"),
        location=_location_from_json(obj["location"]),
        related=[_location_from_json(loc) for loc in _list(obj["related"], "related")],
        confidence=_str(obj["confidence"], "confidence"),
        owasp_agentic=[_str(code, "owasp_agentic") for code in _list(obj["owasp_agentic"], "owasp_agentic")],
    )


def _sink_to_json(ref: SinkRef) -> dict[str, Any]:
    return {"kind": ref.kind, "callee": ref.callee, "location": _location_to_json(ref.location)}


def _sink_from_json(data: Any) -> SinkRef:
    obj = _dict(data, "sink")
    return SinkRef(kind=_str(obj["kind"], "sink kind"), callee=_str(obj["callee"], "callee"),
                   location=_location_from_json(obj["location"]))


def _sink_order(ref: SinkRef) -> tuple[str, int, str, str]:
    return (ref.location.file, ref.location.line, ref.kind, ref.callee)


def _summary_to_json(summary: FunctionSummary) -> dict[str, Any]:
    return {
        "key": summary.key,
        "name": summary.name,
        "location": _location_to_json(summary.location),
        "parameters": list(summary.parameters),
        "positional_count": summary.positional_count,
        "return_labels": sorted(summary.return_labels),
        "returns_parameters": sorted(summary.returns_parameters),
        "parameter_sinks": {
            name: [_sink_to_json(ref) for ref in sorted(refs, key=_sink_order)]
            for name, refs in sorted(summary.parameter_sinks.items())
        },
        "reachable_sinks": [_sink_to_json(ref) for ref in sorted(summary.reachable_sinks, key=_sink_order)],
    }


def _summary_from_json(data: Any) -> FunctionSummary:
    obj = _dict(data, "summary")
    parameters = tuple(_str(name, "parameter") for name in _list(obj["parameters"], "parameters"))
    positional_count = _int(obj["positional_count"], "positional_count")
    if not 0 <= positional_count <= len(parameters):
        raise CacheFormatError("positional_count out of range")
    return FunctionSummary(
        key=_str(obj["key"], "key"),
        name=_str(obj["name"], "name"),
        location=_location_from_json(obj["location"]),
        parameters=parameters,
        positional_count=positional_count,
        return_labels={_str(label, "label") for label in _list(obj["return_labels"], "return_labels")},
        returns_parameters={_str(p, "parameter") for p in _list(obj["returns_parameters"], "returns_parameters")},
        parameter_sinks={
            _str(name, "parameter"): {_sink_from_json(ref) for ref in _list(refs, "sinks")}
            for name, refs in _dict(obj["parameter_sinks"], "parameter_sinks").items()
        },
        reachable_sinks={_sink_from_json(ref) for ref in _list(obj["reachable_sinks"], "reachable_sinks")},
    )


# --------------------------------------------------------------------------- type checks


def _dict(value: Any, what: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CacheFormatError(f"{what} must be an object")
    return value


def _list(value: Any, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise CacheFormatError(f"{what} must be a list")
    return value


def _str(value: Any, what: str) -> str:
    if not isinstance(value, str):
        raise CacheFormatError(f"{what} must be a string")
    return value


def _int(value: Any, what: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise CacheFormatError(f"{what} must be an integer")
    return value


def _bool(value: Any, what: str) -> bool:
    if not isinstance(value, bool):
        raise CacheFormatError(f"{what} must be a boolean")
    return value
