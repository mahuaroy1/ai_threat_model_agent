"""Exception types raised by the threat model agent."""


class ThreatModelError(Exception):
    """Base class for expected, user-facing errors."""


class ScanError(ThreatModelError):
    """The target project cannot be scanned."""


class LLMError(ThreatModelError):
    """The optional local LLM could not produce a narrative."""


class ReportError(ThreatModelError):
    """A report could not be written."""
