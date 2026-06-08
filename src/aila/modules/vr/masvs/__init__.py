"""MASVS catalog package — controls plus level/group enums.

The catalog itself lives in ``catalog.py`` (populated incrementally
per the project IMPLEMENTATION_PLAN, group by group). Public surface
is re-exported here so downstream callers can write
``from aila.modules.vr.masvs import MasvsControl`` without coupling
to the internal layout.

:mod:`aila.modules.vr.masvs.verdict_mapper` is intentionally not
re-exported from this package because it imports from
:mod:`aila.modules.vr.contracts.masvs`, which transitively re-enters
this package's ``__init__`` and would form an import cycle. The
aggregator at :mod:`aila.modules.vr.reporting.masvs_report` reaches
:func:`child_outcome_to_verdict` via its full submodule path.
"""
from __future__ import annotations

from aila.modules.vr.masvs.catalog import CATALOG_VERSION, MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsControl, MasvsGroup, MasvsLevel
from aila.modules.vr.masvs.seed import MasvsSeedBuilder

__all__ = [
    "CATALOG_VERSION",
    "MASVS_CONTROLS",
    "MasvsControl",
    "MasvsGroup",
    "MasvsLevel",
    "MasvsSeedBuilder",
]
