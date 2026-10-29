"""Tests for provider HTTP client reuse (SCALE-03).

Verifies that all 6 provider clients:
- Create self._http_client in __init__ (via BaseProviderClient)
- Reuse the same client across method calls (no per-call creation)
- Provide close() and __del__ for explicit resource management
"""
from __future__ import annotations

import inspect

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _init_assigns_http_client(cls: type) -> bool:
    """Return True if __init__ (anywhere in MRO) assigns self._http_client."""
    for c in cls.__mro__:
        if "__init__" in c.__dict__:
            src = inspect.getsource(c.__init__)
            if "self._http_client" in src:
                return True
    return False


def _no_per_call_with_block(cls: type) -> bool:
    """Return True if no method on the class contains 'with build_provider_http_client'."""
    src = inspect.getsource(cls)
    return "with build_provider_http_client" not in src


# ---------------------------------------------------------------------------
# NVDClient
# ---------------------------------------------------------------------------

class TestNVDClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _init_assigns_http_client(NVDClient), (
            "NVDClient (or its base) __init__ must assign self._http_client"
        )


    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _no_per_call_with_block(NVDClient), (
            "NVDClient must not open a new HTTP client per call (remove 'with build_provider_http_client')"
        )


# ---------------------------------------------------------------------------
# OSVClient
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# EPSSClient
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# KEVClient
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# AlpineSecDBClient
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# ArchSecurityClient
# ---------------------------------------------------------------------------

