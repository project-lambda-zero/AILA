"""Shared miasm compatibility shim for the re_analytics tool groups.

miasm (through 0.1.x) references ``pyparsing.operatorPrecedence`` at
module load; pyparsing 3 removed that alias. Restore it from the modern
spelling (``infix_notation``) BEFORE ``miasm.*`` is imported anywhere,
or the first ``Machine()`` construction raises ``AttributeError`` from
inside miasm's arch import. Same shim the archived ida-headless
``_miasm_compat`` module carried.

Import this module before any direct miasm import::

    from aila.platform.re_analytics import _miasm_compat
    if _miasm_compat.HAS_MIASM:
        machine = _miasm_compat.Machine("x86_64")
"""
from __future__ import annotations

__all__ = [
    "HAS_MIASM",
    "Machine",
    "LocationDB",
    "bin_stream_str",
    "SymbolicExecutionEngine",
]

try:
    import pyparsing as _pyparsing

    if not hasattr(_pyparsing, "operatorPrecedence"):
        _infix = getattr(_pyparsing, "infix_notation", None) or getattr(
            _pyparsing, "infixNotation", None,
        )
        if _infix is not None:
            _pyparsing.operatorPrecedence = _infix  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - pyparsing missing
    pass  # miasm then fails to import on its own; handled by HAS_MIASM

try:
    from miasm.analysis.machine import Machine
    from miasm.core.bin_stream import bin_stream_str
    from miasm.core.locationdb import LocationDB
    from miasm.ir.symbexec import SymbolicExecutionEngine

    HAS_MIASM = True
except ImportError:  # pragma: no cover - environment without extra
    Machine = None  # type: ignore[assignment]
    bin_stream_str = None  # type: ignore[assignment]
    LocationDB = None  # type: ignore[assignment]
    SymbolicExecutionEngine = None  # type: ignore[assignment]
    HAS_MIASM = False
