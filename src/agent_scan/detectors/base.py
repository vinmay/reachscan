"""Detector base types and data model for agent-scan detectors.

- CapabilityFinding: canonical data returned by detectors
- Detector: protocol for class-based detectors (optional)
- DetectorFunc: type alias for function-style detectors (the pattern used by the registry)
"""

from dataclasses import dataclass, asdict
from typing import Optional, Protocol, List, Dict, Any, Callable

@dataclass
class CapabilityFinding:
    """
    A single finding returned by a detector.

    Attributes:
        capability: canonical capability key, e.g. "EXECUTE", "READ", "SEND"
        evidence: short evidence string, e.g. "subprocess.run()"
        file: path of the scanned file
        lineno: optional 1-based line number for the evidence
        confidence: float between 0.0 and 1.0 (higher is more confident)
    """
    capability: str
    evidence: str
    file: str
    lineno: Optional[int] = None
    confidence: float = 0.9

    def as_dict(self) -> Dict[str, Any]:
        """Return a serializable dict representation (helpful for JSON reporter)."""
        return asdict(self)

# Protocol for class-style detectors (optional)
class Detector(Protocol):
    """
    Optional protocol for detector objects.

    Implement either:
      - a function detector: Callable[[str, str], List[CapabilityFinding]]
      - a class detector: class with method `scan_file(path: str, content: str) -> List[CapabilityFinding]`
    """
    name: str

    def scan_file(self, path: str, content: str) -> List[CapabilityFinding]:
        ...

DetectorFunc = Callable[[str, str], List[CapabilityFinding]]

# Exported symbols
__all__ = [
    "CapabilityFinding",
    "Detector",
    "DetectorFunc",
]