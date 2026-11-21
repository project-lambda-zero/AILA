from __future__ import annotations

from email.message import EmailMessage

import pytest

from aila.platform.services import smtp as smtp_module


def _install_fake_smtp(monkeypatch: pytest.MonkeyPatch) -> list[tuple]:
    events: list[tuple] = []

    class _FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
            events.append(("connect", host, port))

        def __enter__(self) -> _FakeSMTP:
            return self

        def __exit__(self, *exc: object) -> bool:
            return False

        def ehlo(self) -> None:
            events.append(("ehlo",))

        def starttls(self, context: object = None) -> None:
            events.append(("starttls",))

        def login(self, username: str, password: str) -> None:
            events.append(("login", username, password))

        def sendmail(self, sender: str, recipients: list[str], message: str) -> dict:
            events.append(("sendmail", sender, tuple(recipients)))
            return {}

    monkeypatch.setattr(smtp_module.smtplib, "SMTP", _FakeSMTP)
    return events


def _message() -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = "report"
    message.set_content("body")
    return message


def test_starttls_with_credentials_runs_ehlo_starttls_login_then_sendmail(monkeypatch) -> None:
    events = _install_fake_smtp(monkeypatch)
    refused = smtp_module.send_smtp_email(
        _message(), host="mail.test", port=587, sender="aila@test", recipients=["ops@test"],
        timeout=5, tls_mode="starttls", username="aila", password="pw",
    )
    assert refused == {}
    assert events == [
        ("connect", "mail.test", 587),
        ("ehlo",),
        ("starttls",),
        ("login", "aila", "pw"),
        ("sendmail", "aila@test", ("ops@test",)),
    ]


def test_no_tls_without_credentials_skips_starttls_and_login(monkeypatch) -> None:
    events = _install_fake_smtp(monkeypatch)
    smtp_module.send_smtp_email(
        _message(), host="mail.test", port=25, sender="aila@test", recipients=["ops@test"],
        timeout=5, tls_mode="none",
    )
    assert events == [
        ("connect", "mail.test", 25),
        ("ehlo",),
        ("sendmail", "aila@test", ("ops@test",)),
    ]


def test_credentials_without_tls_are_rejected_before_connecting(monkeypatch) -> None:
    events = _install_fake_smtp(monkeypatch)
    with pytest.raises(ValueError, match="credentials require"):
        smtp_module.send_smtp_email(
            _message(), host="mail.test", port=25, sender="aila@test", recipients=["ops@test"],
            timeout=5, tls_mode="none", username="aila", password="pw",
        )
    assert events == []


@pytest.mark.parametrize("tls_mode", ["starttls", "none"])
@pytest.mark.parametrize(("username", "password"), [("aila", None), (None, "pw")])
def test_partial_credentials_are_rejected_before_connecting(
    monkeypatch, tls_mode, username, password,
) -> None:
    events = _install_fake_smtp(monkeypatch)
    with pytest.raises(ValueError, match="username and password must be provided together"):
        smtp_module.send_smtp_email(
            _message(), host="mail.test", port=587, sender="aila@test", recipients=["ops@test"],
            timeout=5, tls_mode=tls_mode, username=username, password=password,
        )
    assert events == []
