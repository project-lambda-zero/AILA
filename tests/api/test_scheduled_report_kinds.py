"""req 39 -- report-kind catalog + fleet-health payload.

The kinds route enumerates the report kinds the worker dispatch
understands; the fleet-health generator produces a deliverable text+CSV
payload with stdlib only. Tests invoke the route handler directly (the
slowapi limiter is disabled by the autouse fixture in tests/api/conftest.py)
and exercise the pure payload builder plus the extended SMTP send path with
a mocked smtplib -- no live infra.
"""
from __future__ import annotations

import smtplib
import types
from email import message_from_string

import pytest

from aila.api.auth import AuthContext
from aila.api.routers.scheduled_reports import router as sr_router
from aila.platform.tasks.report_tasks import (
    REPORT_KINDS,
    _build_fleet_health_payload,
    _send_report_email,
)


def _req() -> object:
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


def _auth(team_id: str | None = None) -> AuthContext:
    return AuthContext(
        user_id="u-" + (team_id or "god"),
        role="admin",
        auth_type="user",
        team_id=team_id,
    )


def _endpoint(path: str, method: str):
    for route in sr_router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _host(
    name: str, host: str, role: str, distro: str, port: int = 22
) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        name=name, host=host, username="root", port=port, role=role, distro=distro
    )


# ---------------------------------------------------------------------------
# GET /scheduled-reports/kinds
# ---------------------------------------------------------------------------


async def test_kinds_route_returns_catalog() -> None:
    kinds_route = _endpoint("/scheduled-reports/kinds", "GET")
    env = await kinds_route(request=_req(), auth=_auth())
    kinds = {k.report_type: k for k in env.data}
    assert "fleet_health" in kinds

    fleet = kinds["fleet_health"]
    assert fleet.name
    assert fleet.description
    options = {o.key: o for o in fleet.config_schema}
    group_by = options["group_by"]
    assert group_by.type == "select"
    assert group_by.default == "role"
    assert group_by.options == ["role", "distro"]


def test_kinds_catalog_matches_worker_dispatch() -> None:
    """Every catalog kind carries a generator, so the dispatch is non-empty."""
    assert REPORT_KINDS
    for kind in REPORT_KINDS:
        assert callable(kind.generator)


# ---------------------------------------------------------------------------
# fleet-health payload builder (pure, no DB)
# ---------------------------------------------------------------------------


def test_fleet_health_payload_builds_csv_grouped_by_role() -> None:
    rows = [
        _host("alpha", "10.0.0.1", "vuln-scan", "ubuntu"),
        _host("beta", "10.0.0.2", "vuln-scan", "debian"),
        _host("gamma", "10.0.0.3", "", "ubuntu"),
    ]
    body, csv_bytes = _build_fleet_health_payload("role", rows)
    assert "Managed systems: 3" in body
    assert "vuln-scan: 2" in body
    assert "unassigned: 1" in body

    csv_rows = csv_bytes.decode("utf-8").splitlines()
    assert csv_rows[0] == "name,host,username,port,role,distro"
    assert csv_rows[1] == "alpha,10.0.0.1,root,22,vuln-scan,ubuntu"
    assert csv_rows[3] == "gamma,10.0.0.3,root,22,,ubuntu"


def test_fleet_health_payload_group_by_distro_and_unknown_fallback() -> None:
    rows = [
        _host("alpha", "10.0.0.1", "vuln-scan", "ubuntu"),
        _host("beta", "10.0.0.2", "poc", "ubuntu"),
        _host("gamma", "10.0.0.3", "fuzz", ""),
    ]
    body, _ = _build_fleet_health_payload("distro", rows)
    assert "ubuntu: 2" in body
    assert "unknown: 1" in body

    body_role, _ = _build_fleet_health_payload("bogus", rows)
    assert "Count by role:" in body_role
    assert "vuln-scan: 1" in body_role


def test_fleet_health_payload_empty_fleet() -> None:
    body, csv_bytes = _build_fleet_health_payload("role", [])
    assert "Managed systems: 0" in body
    assert csv_bytes.decode("utf-8").splitlines() == ["name,host,username,port,role,distro"]


# ---------------------------------------------------------------------------
# SMTP send path with a non-PDF payload
# ---------------------------------------------------------------------------


class _FakeSMTP:
    """Records the last message instead of talking to a server."""

    sent: list[tuple[str, list[str], str]] = []

    def __init__(self, host: str, port: int, timeout: int = 30) -> None:
        self._host = host
        self._port = port

    def __enter__(self) -> _FakeSMTP:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def ehlo(self) -> None:
        return None

    def starttls(self, context: object = None) -> None:
        return None

    def login(self, username: str, password: str) -> None:
        return None

    def sendmail(self, from_addr: str, to_addrs: list[str], msg: str) -> None:
        _FakeSMTP.sent.append((from_addr, to_addrs, msg))


def test_send_report_email_carries_csv_without_pdf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    _FakeSMTP.sent = []

    _send_report_email(
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_from="aila@example.test",
        smtp_username=None,
        smtp_password=None,
        recipient="ops@example.test",
        report_name="Fleet Health",
        date_str="2026-08-26",
        pdf_bytes=None,
        csv_bytes=b"name,role\nalpha,vuln-scan\n",
        body_text="Managed systems: 1\n",
        ca_bundle_path=None,
        use_implicit_tls=False,
    )

    assert len(_FakeSMTP.sent) == 1
    from_addr, to_addrs, raw = _FakeSMTP.sent[0]
    assert from_addr == "aila@example.test"
    assert to_addrs == ["ops@example.test"]

    msg = message_from_string(raw)
    assert msg["Subject"] == "AILA Security Report: Fleet Health -- 2026-08-26"
    assert msg.is_multipart()

    parts = list(msg.walk())
    ctypes = [p.get_content_type() for p in parts]
    assert "text/plain" in ctypes
    assert "application/csv" in ctypes
    assert "application/pdf" not in ctypes

    csv_part = next(p for p in parts if p.get_content_type() == "application/csv")
    assert csv_part.get_filename() == "aila-report-2026-08-26.csv"
    assert "name,role" in csv_part.get_payload(decode=True).decode("utf-8")
    text_part = next(p for p in parts if p.get_content_type() == "text/plain")
    assert "Managed systems: 1" in text_part.get_payload()


def test_send_report_email_still_attaches_pdf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    _FakeSMTP.sent = []

    _send_report_email(
        smtp_host="smtp.example.test",
        smtp_port=587,
        smtp_from="aila@example.test",
        smtp_username=None,
        smtp_password=None,
        recipient="ops@example.test",
        report_name="Risk Digest",
        date_str="2026-08-26",
        pdf_bytes=b"%PDF-1.4 fake",
        csv_bytes=None,
        body_text=None,
        ca_bundle_path=None,
        use_implicit_tls=False,
    )

    parts = list(message_from_string(_FakeSMTP.sent[0][2]).walk())
    ctypes = [p.get_content_type() for p in parts]
    assert "application/pdf" in ctypes
    assert "application/csv" not in ctypes
