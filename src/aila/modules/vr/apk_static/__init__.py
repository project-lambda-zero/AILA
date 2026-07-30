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
