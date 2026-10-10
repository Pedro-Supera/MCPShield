"""Data models used by MCPShield's scanner."""

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]


@dataclass(frozen=True, slots=True)
class Finding:
    """A single static-analysis finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    path: str
    line: int
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-serializable representation."""
        return asdict(self)
