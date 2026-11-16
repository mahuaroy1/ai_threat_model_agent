"""Data model for the generated threat model.

All objects are plain dataclasses so they can be serialized to JSON with
``dataclasses.asdict`` and rendered by the reporting module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Finding severity, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank used for sorting and threshold comparisons."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ComponentKind(str, Enum):
    """Architectural element discovered in the target application."""

    ENTRY_POINT = "entry_point"
    MODEL = "model"
    TOOL = "tool"
    RETRIEVAL = "retrieval"
    AGENT = "agent"
    GRAPH_NODE = "graph_node"
    OBSERVABILITY = "observability"
    MEMORY = "memory"


@dataclass(frozen=True)
class Location:
    """A concrete place in the scanned project (path is relative, POSIX style)."""

    file: str
    line: int
    snippet: str = ""

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class Component:
    """An entry point, model, tool, retrieval source, agent, or similar element."""

    kind: ComponentKind
    name: str
    location: Location
    qualified_name: str = ""
    attributes: dict[str, str] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return f"{self.kind.value}:{self.name}@{self.location}"


@dataclass
class Finding:
    """A risk tied to a concrete file and line."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    location: Location
    related: list[Location] = field(default_factory=list)
    confidence: str = "medium"
    owasp_agentic: list[str] = field(default_factory=list)  # e.g. ["ASI01", "ASI06"]


class ControlStatus(str, Enum):
    """Whether a security control for agents was observed in the code."""

    PRESENT = "present"
    PARTIAL = "partial"
    MISSING = "missing"
    NOT_APPLICABLE = "not applicable"


@dataclass
class ControlCheck:
    """One row of the agent controls checklist (statically observed evidence only)."""

    id: str
    name: str
    status: ControlStatus
    owasp_agentic: list[str]
    note: str
    evidence: list[Location] = field(default_factory=list)


@dataclass
class TrustBoundary:
    """A point where data or control crosses between trust zones."""

    id: str
    name: str
    source_zone: str
    target_zone: str
    description: str
    component_ids: list[str] = field(default_factory=list)


@dataclass
class DataFlow:
    """A directed flow of data between two components."""

    source_id: str
    target_id: str
    label: str
    boundary_id: str = ""


@dataclass
class ThreatModel:
    """Complete result of a scan."""

    project_root: str
    generated_at: str
    scanned_files: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    controls: list[ControlCheck] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    llm_narrative: str | None = None
    llm_model: str | None = None

    def components_of(self, kind: ComponentKind) -> list[Component]:
        return [component for component in self.components if component.kind is kind]

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts
