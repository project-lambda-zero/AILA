"""GET /dashboard warns when a module's ``report_count`` is excluded from totals.

A module whose ``report_count`` raises is left out of the finding totals.
That omission is logged at WARNING so the lower totals are not silent; a
module that simply has no findings is not an omission and logs nothing.
"""
from __future__ import annotations

import logging
import types
from typing import Any

import pytest

from aila.api.auth import AuthContext
from aila.api.routers.dashboard import get_dashboard

_LOGGER = "aila.api.routers.dashboard"


class _Module:
    def __init__(self, module_id: str, counts: dict[str, int] | None = None, error: Exception | None = None) -> None:
        self.module_id = module_id
        self._counts = counts or {}
        self._error = error

    async def report_count(self, run_id: str, session: Any, *, team_id: str | None = None) -> dict[str, int]:
        if self._error is not None:
            raise self._error
        return self._counts


class _Registry:
    def __init__(self, modules: list[_Module]) -> None:
        self.modules = modules

    def all_with(self, capability: str) -> list[_Module]:
        return [m for m in self.modules if callable(getattr(m, capability, None))]


def _request(modules: list[_Module]) -> object:
    platform = types.SimpleNamespace(runtime=types.SimpleNamespace(module_registry=_Registry(modules)))
    return types.SimpleNamespace(app=types.SimpleNamespace(state=types.SimpleNamespace(platform=platform)))


def _auth() -> AuthContext:
    return AuthContext(user_id="u-ops", role="operator", auth_type="user", team_id="team-dash-461")


def _excluded_warnings(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r for r in caplog.records
        if r.name == _LOGGER and r.levelno == logging.WARNING and "excluded from totals" in r.getMessage()
    ]


@pytest.mark.usefixtures("test_db")
async def test_raising_report_count_is_excluded_with_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    healthy = _Module("healthy", {"total_findings": 3, "high": 2, "low": 1})
    broken = _Module("broken", error=RuntimeError("report store offline"))

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        envelope = await get_dashboard(request=_request([healthy, broken]), auth=_auth())

    fleet = envelope.data.fleet_stats
    assert (fleet.total_findings, fleet.high_findings, fleet.low_findings) == (3, 2, 1)
    warnings = _excluded_warnings(caplog)
    assert len(warnings) == 1
    assert "broken" in warnings[0].getMessage()


@pytest.mark.usefixtures("test_db")
async def test_module_without_findings_logs_no_warning(caplog: pytest.LogCaptureFixture) -> None:
    healthy = _Module("healthy", {"total_findings": 1, "high": 1})
    empty = _Module("empty", {})

    with caplog.at_level(logging.WARNING, logger=_LOGGER):
        envelope = await get_dashboard(request=_request([healthy, empty]), auth=_auth())

    assert envelope.data.fleet_stats.total_findings == 1
    assert _excluded_warnings(caplog) == []
