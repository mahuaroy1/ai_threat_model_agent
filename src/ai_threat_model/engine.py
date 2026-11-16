"""Orchestrates a scan: discovery -> parsing -> summaries -> analysis -> correlation.

Incremental scans
-----------------
With ``ScanOptions.cache_dir`` set, per-file results and interprocedural
function summaries are saved after each scan (see :mod:`ai_threat_model.cache`).
On the next scan, a Python file is reused from the cache when:

1. its content hash is unchanged,
2. none of the files it depends on (directly or transitively) changed, and
3. the project-wide set of function names and parameters is unchanged,
   so every call resolves exactly as before.

Everything else is parsed and analyzed again, seeded with the cached
summaries of the reused files. Correlation (trust boundaries, data flows,
cross-component risks) always runs on the full set of results because it is cheap.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .cache import (
    CacheState,
    FileEntry,
    cache_path,
    content_hash,
    export_signature,
    load_cache,
    save_cache,
)
from .config_analyzer import analyze_config
from .correlation import correlate
from .discovery import SourceFile, discover_files
from .interprocedural import FunctionSummary, SummaryRegistry, summary_keys
from .models import Component, Finding, Location, ThreatModel
from .python_analyzer import PythonFileAnalyzer, solve_summaries

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanOptions:
    max_file_bytes: int = 2_000_000
    max_files: int = 20_000
    cache_dir: Path | None = None  # enables incremental scans when set
    rebuild_cache: bool = False  # ignore any existing cache, then write a fresh one


@dataclass
class ScanStats:
    """How much work an (incremental) scan reused versus recomputed."""

    files: int = 0
    reused: int = 0
    analyzed: int = 0
    cache_file: Path | None = None
    cache_loaded: bool = False
    cache_saved: bool = False


@dataclass
class ScanResult:
    model: ThreatModel
    stats: ScanStats = field(default_factory=ScanStats)


def build_threat_model(root: Path, options: ScanOptions | None = None) -> ThreatModel:
    """Scan ``root`` and return a complete :class:`ThreatModel`.

    Individual files that cannot be read or parsed are recorded in
    ``ThreatModel.errors`` and skipped; only an invalid root raises.

    Raises:
        ScanError: If ``root`` is not a readable directory.
    """
    return scan(root, options).model


def scan(root: Path, options: ScanOptions | None = None) -> ScanResult:
    """Like :func:`build_threat_model`, but also returns cache statistics."""
    options = options or ScanOptions()
    root = root.resolve()
    files, warnings = discover_files(root, max_file_bytes=options.max_file_bytes, max_files=options.max_files)
    model = ThreatModel(
        project_root=str(root),
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        errors=list(warnings),
    )
    stats = ScanStats()
    previous: CacheState | None = None
    if options.cache_dir is not None:
        stats.cache_file = cache_path(options.cache_dir, root)
        if options.rebuild_cache:
            LOGGER.info("Ignoring any existing analysis cache (--rebuild-cache)")
        else:
            previous = load_cache(stats.cache_file, root)
        stats.cache_loaded = previous is not None

    texts = _read_sources(files, model)
    hashes = {path: content_hash(text) for path, text in texts.items()}
    readable = [source for source in files if source.relative_path in texts]
    env_ignored = _env_ignored_by_git(root)

    python_paths = [s.relative_path for s in readable if s.kind == "python"]
    reusable = _reusable_python_files(python_paths, hashes, previous)
    registry = SummaryRegistry()
    analyzers = _prepare_python_analyzers(
        [s for s in readable if s.kind == "python" and s.relative_path not in reusable], texts, registry, model,
    )

    exports: dict[str, list[FunctionSummary]] = {path: a.summaries for path, a in analyzers.items()}
    if previous is not None and reusable:
        exports.update({path: previous.files[path].summaries for path in reusable})
        signature = export_signature(exports)
        if signature != previous.export_signature:
            LOGGER.info("Function names or parameters changed; rebuilding all interprocedural summaries")
            analyzers.update(_prepare_python_analyzers(
                [s for s in readable if s.relative_path in reusable], texts, registry, model,
            ))
            reusable = set()
        else:
            for path in reusable:
                for summary in previous.files[path].summaries:
                    registry.register(summary_keys(path, summary.name), summary)

    rounds = solve_summaries(analyzers.values())
    LOGGER.info("Interprocedural summaries converged in %d round(s) over %d file(s)", rounds, len(analyzers))

    entries: dict[str, FileEntry] = {}
    signals: dict[str, list[Location]] = {}
    frameworks: set[str] = set()
    for source in readable:
        path = source.relative_path
        try:
            entry = _cached_entry(source, hashes[path], previous, reusable, env_ignored)
            if entry is not None:
                stats.reused += 1
            elif source.kind == "python":
                analyzer = analyzers.get(path)
                if analyzer is None:
                    continue  # parse failure already recorded
                result = analyzer.analyze()
                entry = FileEntry(
                    sha256=hashes[path], kind="python", components=result.components, findings=result.findings,
                    frameworks=result.frameworks, signals=result.signals,
                    summaries=analyzer.summaries, dependencies=set(analyzer.dependencies),
                )
                stats.analyzed += 1
            else:
                config = analyze_config(path, texts[path], env_ignored_by_git=env_ignored)
                entry = FileEntry(sha256=hashes[path], kind="config", components=config.components,
                                  findings=config.findings, env_ignored=env_ignored)
                stats.analyzed += 1
            entries[path] = entry
            model.components.extend(entry.components)
            model.findings.extend(entry.findings)
            for name, locations in entry.signals.items():
                signals.setdefault(name, []).extend(locations)
            frameworks |= entry.frameworks
            model.scanned_files.append(path)
        except (OSError, RecursionError, ValueError) as error:
            _record_error(model, source, error)
        except Exception:  # noqa: BLE001 - one bad file must not abort the whole scan
            LOGGER.exception("Unexpected error while analyzing %s", path)
            model.errors.append(f"{path}: unexpected analyzer error (see log)")
    stats.files = len(model.scanned_files)

    model.frameworks = sorted(frameworks)
    if not frameworks:
        model.errors.append("No LangChain or LangGraph imports were found; results may be incomplete.")
    model.components = _dedupe_components(model.components)
    correlate(model, signals)
    model.findings = _dedupe_findings(model.findings)

    if stats.cache_file is not None:
        python_exports = {path: e.summaries for path, e in entries.items() if e.kind == "python"}
        state = CacheState(project_root=str(root), export_signature=export_signature(python_exports), files=entries)
        stats.cache_saved = save_cache(stats.cache_file, state)

    LOGGER.info("Scan complete: %d components, %d findings (%d file(s) reused from cache, %d analyzed)",
                len(model.components), len(model.findings), stats.reused, stats.analyzed)
    return ScanResult(model=model, stats=stats)


def _read_sources(files: list[SourceFile], model: ThreatModel) -> dict[str, str]:
    """Read every discovered file once; unreadable files are recorded and skipped."""
    texts: dict[str, str] = {}
    for source in files:
        try:
            texts[source.relative_path] = source.read_text()
        except OSError as error:
            _record_error(model, source, error)
    return texts


def _reusable_python_files(paths: list[str], hashes: dict[str, str], previous: CacheState | None) -> set[str]:
    """Python files whose cached results remain valid, ignoring signature changes.

    A file is dirty if it is new or changed, or if it (transitively) depends on
    a dirty or deleted file. Dependencies come from the previous scan, which is
    accurate for any file whose content did not change.
    """
    if previous is None:
        return set()
    cached = {path: entry for path, entry in previous.files.items() if entry.kind == "python"}
    current = set(paths)
    dirty = {path for path in current if path not in cached or cached[path].sha256 != hashes[path]}
    dirty |= set(cached) - current
    candidates = current - dirty
    changed = True
    while changed:
        changed = False
        for path in list(candidates):
            if cached[path].dependencies & dirty:
                dirty.add(path)
                candidates.discard(path)
                changed = True
    return candidates


def _cached_entry(
    source: SourceFile, sha256: str, previous: CacheState | None, reusable: set[str], env_ignored: bool,
) -> FileEntry | None:
    if previous is None:
        return None
    entry = previous.files.get(source.relative_path)
    if entry is None or entry.sha256 != sha256 or entry.kind != source.kind:
        return None
    if source.kind == "python":
        return entry if source.relative_path in reusable else None
    return entry if entry.env_ignored == env_ignored else None


def _prepare_python_analyzers(
    files: list[SourceFile], texts: dict[str, str], registry: SummaryRegistry, model: ThreatModel,
) -> dict[str, PythonFileAnalyzer]:
    """Parse Python files and register their functions in the shared registry."""
    analyzers: dict[str, PythonFileAnalyzer] = {}
    for source in files:
        try:
            analyzer = PythonFileAnalyzer(source.relative_path, texts[source.relative_path], registry)
            analyzer.prepare()
            analyzers[source.relative_path] = analyzer
        except (SyntaxError, ValueError, RecursionError) as error:
            _record_error(model, source, error)
    return analyzers


def _record_error(model: ThreatModel, source: SourceFile, error: BaseException) -> None:
    detail = getattr(error, "msg", None) or getattr(error, "strerror", None) or type(error).__name__
    message = f"{source.relative_path}: skipped ({type(error).__name__}: {detail})"
    LOGGER.warning(message)
    model.errors.append(message)


def _env_ignored_by_git(root: Path) -> bool:
    try:
        content = (root / ".gitignore").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return any(line.strip().lstrip("/").startswith(".env") for line in content.splitlines())


def _dedupe_components(components: list[Component]) -> list[Component]:
    unique: dict[str, Component] = {}
    for component in components:
        unique.setdefault(component.id, component)
    return sorted(unique.values(), key=lambda c: (c.kind.value, c.location.file, c.location.line, c.name))


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Keep the most severe finding per rule and location."""
    ordered = sorted(findings, key=lambda f: (-f.severity.rank, f.location.file, f.location.line, f.rule_id))
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in ordered:
        unique.setdefault((finding.rule_id, finding.location.file, finding.location.line), finding)
    return list(unique.values())
