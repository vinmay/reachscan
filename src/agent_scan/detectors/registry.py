"""
Detector registry for agent-scan.

Usage patterns supported:

1) Function detector (recommended)
    @register_detector("shell_exec")
    def scan_file(path: str, content: str) -> List[CapabilityFinding]:
        ...

2) Class-based detector (optional)
    class MyDetector:
        name = "mydet"
        def scan_file(self, path: str, content: str) -> List[CapabilityFinding]:
            ...

    register_detector(MyDetector())    # registers instance

Helpers:
- get_detectors() -> dict of registered detectors
- get_detector(name) -> a single detector (function or object)
- call_detector(detector, path, content) -> canonical call wrapper
- clear_registry() -> remove all entries (useful in tests)
"""
from typing import Callable, Dict, List, Optional, Any, Union
from .base import DetectorFunc, CapabilityFinding, Detector

# Internal registry map: name -> detector (callable or object with scan_file)
_REGISTRY: Dict[str, Union[DetectorFunc, Detector]] = {}

def register_detector(name_or_obj: Optional[Union[str, DetectorFunc, Detector]] = None):
    """
    Decorator / helper to register a detector.

    Can be used in three ways:

    1) As a decorator with a name:
        @register_detector("shell_exec")
        def scan_file(path, content): ...

    2) As a decorator without args (uses function.__name__):
        @register_detector
        def shell_exec(path, content): ...

    3) Register an already-instantiated object or function:
        register_detector(some_detector_obj_or_fn)

    Returns the original function/object for convenience (so you can import it
    from the module that defines it).
    """
    # Case A: used as @register_detector (no args)
    if callable(name_or_obj) and not isinstance(name_or_obj, str):
        fn_or_obj = name_or_obj
        key = getattr(fn_or_obj, "name", None) or getattr(fn_or_obj, "__name__", None)
        if not key:
            raise ValueError("Detector must have a name (either attribute 'name' or function __name__).")
        if key in _REGISTRY:
            raise ValueError(f"Detector with name '{key}' already registered.")
        _REGISTRY[key] = fn_or_obj
        return fn_or_obj

    # Otherwise return a decorator that accepts the function/object
    def _decorator(fn_or_obj: Union[DetectorFunc, Detector]):
        key = name_or_obj or getattr(fn_or_obj, "name", None) or getattr(fn_or_obj, "__name__", None)
        if not key:
            raise ValueError("Detector must have a name (provide it to register_detector or use function/class name).")
        if key in _REGISTRY:
            raise ValueError(f"Detector with name '{key}' already registered.")
        _REGISTRY[key] = fn_or_obj
        return fn_or_obj

    return _decorator

def get_detectors() -> Dict[str, Union[DetectorFunc, Detector]]:
    """Return a copy of the registry mapping (name -> detector)."""
    return dict(_REGISTRY)

def get_detector(name: str) -> Optional[Union[DetectorFunc, Detector]]:
    """Return a single registered detector by name or None if not found."""
    return _REGISTRY.get(name)

def clear_registry() -> None:
    """Clear the registry. Useful in tests to reset state."""
    _REGISTRY.clear()

def call_detector(detector: Union[DetectorFunc, Detector], path: str, content: str) -> List[CapabilityFinding]:
    """
    Canonical way to call a registered detector.

    Accepts either:
      - a function: fn(path, content) -> List[CapabilityFinding]
      - an object with method scan_file(path, content) -> List[CapabilityFinding]

    Returns an empty list on unexpected errors (registry should be resilient).
    """
    try:
        if callable(detector):
            # function-style detector
            result = detector(path, content)
        else:
            # object-style detector
            result = detector.scan_file(path, content)
        # Basic type hint contract: expecting list of CapabilityFinding
        if result is None:
            return []
        return list(result)
    except Exception:
        # Don't let a single detector crash the scanner; return empty and allow
        # the scanner to continue collecting other detectors' findings.
        return []