"""APK static-analysis check catalog package.

The catalog (in ``catalog.py``) holds a flat tuple of
:class:`ApkStaticCheck` instances -- one per concrete, statically-
answerable investigation against a decompiled Android APK. Public surface
is re-exported here so downstream callers can write
``from aila.modules.vr.apk_static import ApkStaticCheck`` without coupling
to the internal layout.

A companion to :mod:`aila.modules.vr.masvs`: MASVS models broad
compliance controls (some unanswerable from an APK); this package models
sharp, evidence-backed checks. Both dispatch children as ``kind=audit``
running the unchanged vuln_researcher chain, reconciled by the same
``sweep_masvs_audit_parents`` cron.
"""
from __future__ import annotations

# Deliberately no eager re-export of ``aggregate.collect_apk_static_findings``
# or ``verdict_mapper.apk_static_child_outcome_to_verdict`` here. Both sit
# downstream of :mod:`aila.modules.vr.contracts.apk_static`, which in turn
# imports :class:`ApkStaticGroup` from this package. Re-exporting them at
# package init time creates a partially-initialized cycle
# (vr.contracts.__init__ -> .apk_static contracts -> apk_static package
# init -> aggregate/verdict_mapper -> vr.contracts). The API router
# imports the aggregate lazily inside its handler; any other caller must
# reach past this barrel and import from the submodule directly
# (``aila.modules.vr.apk_static.aggregate`` for the collector,
# ``aila.modules.vr.apk_static.verdict_mapper`` for the mapper).
from aila.modules.vr.apk_static.catalog import (
    APK_STATIC_CATALOG_VERSION,
    APK_STATIC_CHECKS,
)
from aila.modules.vr.apk_static.models import (
    ApkStaticCheck,
    ApkStaticGroup,
    ApkStaticMode,
)
from aila.modules.vr.apk_static.seed import ApkStaticSeedBuilder

__all__ = [
    "APK_STATIC_CATALOG_VERSION",
    "APK_STATIC_CHECKS",
    "ApkStaticCheck",
    "ApkStaticGroup",
    "ApkStaticMode",
    "ApkStaticSeedBuilder",
]
