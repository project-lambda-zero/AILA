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

def _has_close(cls: type) -> bool:
    return callable(getattr(cls, "close", None))


def _has_del(cls: type) -> bool:
    """Check __del__ exists anywhere in the MRO (base class counts)."""
    return any("__del__" in c.__dict__ for c in cls.__mro__)


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


def _init_calls_build_provider_http_client(cls: type) -> bool:
    """Return True if __init__ (anywhere in MRO) calls build_provider_http_client."""
    for c in cls.__mro__:
        if "__init__" in c.__dict__:
            src = inspect.getsource(c.__init__)
            if "build_provider_http_client" in src:
                return True
    return False


# ---------------------------------------------------------------------------
# NVDClient
# ---------------------------------------------------------------------------

class TestNVDClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _init_assigns_http_client(NVDClient), (
            "NVDClient (or its base) __init__ must assign self._http_client"
        )

    def test_init_calls_build_provider_http_client(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _init_calls_build_provider_http_client(NVDClient), (
            "NVDClient (or its base) __init__ must call build_provider_http_client()"
        )

    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _no_per_call_with_block(NVDClient), (
            "NVDClient must not open a new HTTP client per call (remove 'with build_provider_http_client')"
        )

    def test_has_close_method(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _has_close(NVDClient), "NVDClient must have a close() method"

    def test_has_del_method(self):
        from aila.modules.vulnerability.providers.nvd import NVDClient
        assert _has_del(NVDClient), "NVDClient must have a __del__ method"


# ---------------------------------------------------------------------------
# OSVClient
# ---------------------------------------------------------------------------

class TestOSVClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.osv import OSVClient
        assert _init_assigns_http_client(OSVClient)

    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.osv import OSVClient
        assert _no_per_call_with_block(OSVClient)

    def test_has_close_method(self):
        from aila.modules.vulnerability.providers.osv import OSVClient
        assert _has_close(OSVClient)

    def test_has_del_method(self):
        from aila.modules.vulnerability.providers.osv import OSVClient
        assert _has_del(OSVClient)


# ---------------------------------------------------------------------------
# EPSSClient
# ---------------------------------------------------------------------------

class TestEPSSClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.epss import EPSSClient
        assert _init_assigns_http_client(EPSSClient)

    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.epss import EPSSClient
        assert _no_per_call_with_block(EPSSClient)

    def test_has_close_method(self):
        from aila.modules.vulnerability.providers.epss import EPSSClient
        assert _has_close(EPSSClient)

    def test_has_del_method(self):
        from aila.modules.vulnerability.providers.epss import EPSSClient
        assert _has_del(EPSSClient)


# ---------------------------------------------------------------------------
# KEVClient
# ---------------------------------------------------------------------------

class TestKEVClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.kev import KEVClient
        assert _init_assigns_http_client(KEVClient)

    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.kev import KEVClient
        assert _no_per_call_with_block(KEVClient)

    def test_has_close_method(self):
        from aila.modules.vulnerability.providers.kev import KEVClient
        assert _has_close(KEVClient)

    def test_has_del_method(self):
        from aila.modules.vulnerability.providers.kev import KEVClient
        assert _has_del(KEVClient)


# ---------------------------------------------------------------------------
# AlpineSecDBClient
# ---------------------------------------------------------------------------

class TestAlpineSecDBClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.alpine_secdb import AlpineSecDBClient
        assert _init_assigns_http_client(AlpineSecDBClient)

    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.alpine_secdb import AlpineSecDBClient
        assert _no_per_call_with_block(AlpineSecDBClient)

    def test_has_close_method(self):
        from aila.modules.vulnerability.providers.alpine_secdb import AlpineSecDBClient
        assert _has_close(AlpineSecDBClient)

    def test_has_del_method(self):
        from aila.modules.vulnerability.providers.alpine_secdb import AlpineSecDBClient
        assert _has_del(AlpineSecDBClient)


# ---------------------------------------------------------------------------
# ArchSecurityClient
# ---------------------------------------------------------------------------

class TestArchSecurityClientHttpClientReuse:
    def test_init_creates_http_client(self):
        from aila.modules.vulnerability.providers.arch_security import ArchSecurityClient
        assert _init_assigns_http_client(ArchSecurityClient)

    def test_no_per_call_with_block(self):
        from aila.modules.vulnerability.providers.arch_security import ArchSecurityClient
        assert _no_per_call_with_block(ArchSecurityClient)

    def test_has_close_method(self):
        from aila.modules.vulnerability.providers.arch_security import ArchSecurityClient
        assert _has_close(ArchSecurityClient)

    def test_has_del_method(self):
        from aila.modules.vulnerability.providers.arch_security import ArchSecurityClient
        assert _has_del(ArchSecurityClient)
