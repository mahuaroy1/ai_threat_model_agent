"""Function summaries for interprocedural (cross-function and cross-file) data flow.

How it works
------------
1. Every top-level function and method in the project is registered in a
   :class:`SummaryRegistry` under each plausible import path
   (``pkg.mod.func``, ``mod.func``, ...).
2. Each function is analyzed with *symbolic* labels on its parameters
   (``param:<name>``). The analysis records:

   * which parameters flow to the return value,
   * which concrete labels the return value always carries
     (for example ``model output`` when it returns ``llm.invoke(...)``),
   * which parameters reach which sinks (shell, SQL, prompt, logs, ...),
   * which sinks the function can reach at all (its capabilities).

3. Summaries are recomputed for all files until nothing changes, so flows
   through chains of helpers and recursive calls converge.
4. In the reporting pass, a call site that passes untrusted data into a
   parameter with a recorded sink produces a finding at the call site, with
   the ultimate sink attached as related evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Iterable

from .models import Location

PARAMETER_PREFIX = "param:"
MAX_SINKS_PER_PARAMETER = 8
MAX_REACHABLE_SINKS = 16


def parameter_label(name: str) -> str:
    """Symbolic label standing for "whatever the caller passes as ``name``"."""
    return f"{PARAMETER_PREFIX}{name}"


def split_labels(labels: Iterable[str]) -> tuple[set[str], set[str]]:
    """Split labels into ``(concrete_labels, parameter_names)``."""
    concrete: set[str] = set()
    parameters: set[str] = set()
    for label in labels:
        if label.startswith(PARAMETER_PREFIX):
            parameters.add(label[len(PARAMETER_PREFIX):])
        else:
            concrete.add(label)
    return concrete, parameters


@dataclass(frozen=True)
class SinkRef:
    """A sink reached inside a function (possibly through further calls)."""

    kind: str
    callee: str
    location: Location


@dataclass
class FunctionSummary:
    """Data-flow behaviour of one function, independent of its callers."""

    key: str
    name: str
    location: Location
    parameters: tuple[str, ...]
    positional_count: int
    return_labels: set[str] = field(default_factory=set)
    returns_parameters: set[str] = field(default_factory=set)
    parameter_sinks: dict[str, set[SinkRef]] = field(default_factory=dict)
    reachable_sinks: set[SinkRef] = field(default_factory=set)

    def update(
        self,
        return_labels: set[str],
        returns_parameters: set[str],
        parameter_sinks: dict[str, set[SinkRef]],
        reachable_sinks: set[SinkRef],
    ) -> bool:
        """Merge newly computed facts; return True if anything changed.

        Facts only grow, which guarantees the project-wide fixed point terminates.
        Sink sets are capped to keep reports and memory bounded.
        """
        before = (
            len(self.return_labels),
            len(self.returns_parameters),
            sum(len(refs) for refs in self.parameter_sinks.values()),
            len(self.reachable_sinks),
        )
        self.return_labels |= return_labels
        self.returns_parameters |= returns_parameters & set(self.parameters)
        for parameter, refs in parameter_sinks.items():
            if parameter not in self.parameters:
                continue
            current = self.parameter_sinks.setdefault(parameter, set())
            for ref in sorted(refs, key=_sink_sort_key):
                if len(current) >= MAX_SINKS_PER_PARAMETER:
                    break
                current.add(ref)
        for ref in sorted(reachable_sinks, key=_sink_sort_key):
            if len(self.reachable_sinks) >= MAX_REACHABLE_SINKS:
                break
            self.reachable_sinks.add(ref)
        after = (
            len(self.return_labels),
            len(self.returns_parameters),
            sum(len(refs) for refs in self.parameter_sinks.values()),
            len(self.reachable_sinks),
        )
        return after != before


def _sink_sort_key(ref: SinkRef) -> tuple[str, int, str, str]:
    return (ref.location.file, ref.location.line, ref.kind, ref.callee)


class SummaryRegistry:
    """Project-wide lookup from import path to :class:`FunctionSummary`.

    A key registered by two different functions (e.g. ``utils.helper`` in two
    packages) is marked ambiguous and never resolved, avoiding false flows.
    """

    def __init__(self) -> None:
        self._by_key: dict[str, FunctionSummary | None] = {}

    def register(self, keys: Iterable[str], summary: FunctionSummary) -> None:
        for key in keys:
            existing = self._by_key.get(key, summary)
            self._by_key[key] = summary if existing is summary else None

    def get(self, key: str) -> FunctionSummary | None:
        return self._by_key.get(key)

    def summaries(self) -> list[FunctionSummary]:
        unique = {id(summary): summary for summary in self._by_key.values() if summary is not None}
        return list(unique.values())


def summary_keys(relative_path: str, name: str) -> list[str]:
    """Every registry key under which function ``name`` in ``relative_path`` is registered."""
    return [f"{module}.{name}" for module in module_names(relative_path) or ["__main__"]]


def module_names(relative_path: str) -> list[str]:
    """All dotted module names a file may be imported as, longest first.

    ``src/app/tools.py`` -> ``["src.app.tools", "app.tools", "tools"]``
    """
    parts = PurePosixPath(relative_path).with_suffix("").parts
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return [".".join(parts[index:]) for index in range(len(parts))]
