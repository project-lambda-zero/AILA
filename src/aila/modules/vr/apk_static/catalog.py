"""APK static-analysis check catalog -- flat tuple of every catalogued check.

Assembled from the per-cluster check modules (``_checks_*.py``). The
iteration order is group-major, matching the catalog author order, so the
dispatcher fans children out deterministically and the frontend renders a
stable per-check progress table without re-sorting.

Only :attr:`ApkStaticMode.STATIC` checks are dispatched. EXTRACTOR checks
are catalogued for the roadmap (they need a pipeline stage not yet built)
and skipped by the dispatcher, exactly as the MASVS catalog carries L2/R
controls that the L1 audit does not dispatch.
"""
from __future__ import annotations

from aila.modules.vr.apk_static._checks_chains_auth_sbom_flutter import (
    CHECKS as _CHAINS_CHECKS,
)
from aila.modules.vr.apk_static._checks_deser_code_resil_priv import (
    CHECKS as _DESER_CHECKS,
)
from aila.modules.vr.apk_static._checks_extractor import (
    CHECKS as _EXTRACTOR_CHECKS,
)
from aila.modules.vr.apk_static._checks_manifest import (
    CHECKS as _MANIFEST_CHECKS,
)
from aila.modules.vr.apk_static._checks_secrets_crypto_net import (
    CHECKS as _SECRETS_CHECKS,
)
from aila.modules.vr.apk_static._checks_webview_storage_ipc import (
    CHECKS as _WEBVIEW_CHECKS,
)
from aila.modules.vr.apk_static.models import ApkStaticCheck

__all__ = [
    "APK_STATIC_CATALOG_VERSION",
    "APK_STATIC_CHECKS",
]

# Catalog spec version pinned on every APK static audit parent
# investigation. Bumped together with any catalog-content change (new
# check, edited evidence_hints, retired check). Historical audits keep
# their original version on the parent's secondary_target_refs_json so a
# later edit never silently invalidates a shipped audit's provenance.
# ``1.0.0`` is the first shipped catalog; the ``-aila`` suffix marks it as
# AILA's compiled set rather than a verbatim upstream release.
APK_STATIC_CATALOG_VERSION: str = "1.0.0-aila"


APK_STATIC_CHECKS: tuple[ApkStaticCheck, ...] = (
    *_MANIFEST_CHECKS,
    *_SECRETS_CHECKS,
    *_WEBVIEW_CHECKS,
    *_DESER_CHECKS,
    *_CHAINS_CHECKS,
    *_EXTRACTOR_CHECKS,
)
